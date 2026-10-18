#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;

const GW_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const HOST_MAC: Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const GW_IP: Ipv4 = [10, 0, 2, 15];
const HOST_IP: Ipv4 = [10, 0, 2, 2];

fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let f = Frame {
        eth: EthAddrs { src: HOST_MAC, dst: GW_MAC },
        body: Body::Udp4(Udp4 { src: HOST_IP, dst: GW_IP, sport: 40000, dport: 7, payload }),
    };
    let mut out = [0u8; MAX_FRAME];
    let n = emit(&f, &mut out).unwrap();
    out[..n].to_vec()
}

fn arp_request() -> Vec<u8> {
    let f = Frame {
        eth: EthAddrs { src: HOST_MAC, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket {
            op: ArpOp::Request,
            sha: HOST_MAC,
            spa: HOST_IP,
            tha: [0; 6],
            tpa: GW_IP,
        }),
    };
    let mut out = [0u8; MAX_FRAME];
    let n = emit(&f, &mut out).unwrap();
    out[..n].to_vec()
}

/// Recomputes the IPv4 header checksum after a deliberate mutation, so the
/// test reaches the check it targets instead of failing on the checksum.
fn fix_ip_csum(b: &mut [u8]) {
    b[ETH_HDR + 10] = 0;
    b[ETH_HDR + 11] = 0;
    let c = csum_fold(csum_add(0, &b[ETH_HDR..ETH_HDR + IPV4_HDR]));
    b[ETH_HDR + 10..ETH_HDR + 12].copy_from_slice(&c.to_be_bytes());
}

fn reason(b: &[u8]) -> DropReason {
    parse_frame(b).unwrap_err()
}

#[test]
fn valid_udp_frame_parses_to_its_fields() {
    let b = udp_frame(b"nonce-123");
    let f = parse_frame(&b).unwrap();
    assert_eq!(f.eth, EthAddrs { src: HOST_MAC, dst: GW_MAC });
    let Body::Udp4(u) = f.body else { panic!("not udp") };
    assert_eq!((u.src, u.dst, u.sport, u.dport, u.payload), (HOST_IP, GW_IP, 40000, 7, &b"nonce-123"[..]));
}

#[test]
fn valid_arp_request_parses() {
    let b = arp_request();
    let f = parse_frame(&b).unwrap();
    assert!(matches!(f.body, Body::Arp(ArpPacket { op: ArpOp::Request, tpa: GW_IP, .. })));
}

#[test]
fn ethernet_padding_after_ipv4_total_length_is_ignored() {
    let mut b = udp_frame(b"x");
    assert_eq!(b.len(), 43);
    b.resize(60, 0);
    let Body::Udp4(u) = parse_frame(&b).unwrap().body else { panic!("not udp") };
    assert_eq!(u.payload, b"x");
}

#[test]
fn zero_udp_checksum_means_not_computed() {
    let mut b = udp_frame(b"abc");
    b[ETH_HDR + IPV4_HDR + 6] = 0;
    b[ETH_HDR + IPV4_HDR + 7] = 0;
    assert!(parse_frame(&b).is_ok());
}

#[test]
fn too_short() {
    assert_eq!(reason(&udp_frame(b"")[..13]), DropReason::TooShort);
    assert_eq!(reason(&arp_request()[..ETH_HDR + ARP_LEN - 1]), DropReason::TooShort);
    assert_eq!(reason(&udp_frame(b"")[..ETH_HDR + IPV4_HDR - 1]), DropReason::TooShort);
}

#[test]
fn too_long() {
    let mut b = udp_frame(b"");
    b.resize(MAX_FRAME + 1, 0);
    assert_eq!(reason(&b), DropReason::TooLong);
}

#[test]
fn eth_bad_src_multicast_and_zero() {
    let mut b = udp_frame(b"");
    b[6] |= 1;
    assert_eq!(reason(&b), DropReason::EthBadSrc);
    let mut b = udp_frame(b"");
    b[6..12].fill(0);
    assert_eq!(reason(&b), DropReason::EthBadSrc);
}

#[test]
fn unknown_ethertype_incl_vlan() {
    let mut b = udp_frame(b"");
    b[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    assert_eq!(reason(&b), DropReason::UnknownEtherType);
}

#[test]
fn arp_malformed_each_fixed_field() {
    for (off, val) in [(0usize, 2u8), (2, 0x86), (4, 7), (5, 5), (7, 3)] {
        let mut b = arp_request();
        b[ETH_HDR + off] = val;
        assert_eq!(reason(&b), DropReason::ArpMalformed, "offset {off}");
    }
}

#[test]
fn arp_bad_sender() {
    let mut b = arp_request();
    b[ETH_HDR + 8] |= 1;
    assert_eq!(reason(&b), DropReason::ArpBadSender);
    let mut b = arp_request();
    b[ETH_HDR + 14..ETH_HDR + 18].fill(0);
    assert_eq!(reason(&b), DropReason::ArpBadSender);
}

#[test]
fn ipv4_version() {
    let mut b = udp_frame(b"");
    b[ETH_HDR] = 0x65;
    assert_eq!(reason(&b), DropReason::Ipv4Version);
}

#[test]
fn ipv4_options() {
    let mut b = udp_frame(b"");
    b[ETH_HDR] = 0x46;
    assert_eq!(reason(&b), DropReason::Ipv4Options);
}

#[test]
fn ipv4_fragment_mf_offset_and_reserved_bit() {
    for flags in [0x2000u16, 0x0001, 0x8000] {
        let mut b = udp_frame(b"");
        b[ETH_HDR + 6..ETH_HDR + 8].copy_from_slice(&flags.to_be_bytes());
        assert_eq!(reason(&b), DropReason::Ipv4Fragment, "flags {flags:#x}");
    }
}

#[test]
fn ipv4_bad_length_beyond_frame_and_below_header() {
    for total in [200u16, 19] {
        let mut b = udp_frame(b"");
        b[ETH_HDR + 2..ETH_HDR + 4].copy_from_slice(&total.to_be_bytes());
        assert_eq!(reason(&b), DropReason::Ipv4BadLength, "total {total}");
    }
}

#[test]
fn ipv4_bad_checksum() {
    let mut b = udp_frame(b"");
    b[ETH_HDR + 8] ^= 1; // TTL
    assert_eq!(reason(&b), DropReason::Ipv4BadChecksum);
}

#[test]
fn ipv4_bad_src_broadcast_multicast_zero() {
    for src in [[255u8; 4], [224, 0, 0, 1], [0; 4], [127, 0, 0, 1]] {
        let mut b = udp_frame(b"");
        b[ETH_HDR + 12..ETH_HDR + 16].copy_from_slice(&src);
        fix_ip_csum(&mut b);
        assert_eq!(reason(&b), DropReason::Ipv4BadSrc, "src {src:?}");
    }
}

#[test]
fn not_udp() {
    let mut b = udp_frame(b"");
    b[ETH_HDR + 9] = 6;
    fix_ip_csum(&mut b);
    assert_eq!(reason(&b), DropReason::NotUdp);
}

fn tcp_frame() -> Vec<u8> {
    let mut b = udp_frame(b"tcp-ish payload");
    b[ETH_HDR + 9] = 6;
    b[ETH_HDR + 8] = 17; // TTL a re-encoder would overwrite
    b[ETH_HDR + 4] = 0xab; // identification likewise
    fix_ip_csum(&mut b);
    b
}

#[test]
fn inside_parser_accepts_any_protocol_verbatim() {
    let b = tcp_frame();
    let f = parse_frame_ip(&b).unwrap();
    let Body::Ipv4(p) = f.body else { panic!("not ipv4") };
    assert_eq!((p.src, p.dst, p.proto), (HOST_IP, GW_IP, 6));
    assert_eq!(p.packet, &b[ETH_HDR..]);
}

#[test]
fn inside_parser_drops_ethernet_padding() {
    let mut b = tcp_frame();
    let n = b.len() - ETH_HDR;
    b.extend_from_slice(&[0xee; 7]);
    let Body::Ipv4(p) = parse_frame_ip(&b).unwrap().body else { panic!("not ipv4") };
    assert_eq!(p.packet.len(), n);
}

#[test]
fn inside_parser_keeps_ipv4_header_rules() {
    let mut b = tcp_frame();
    b[ETH_HDR + 6] = 0x20; // MF
    fix_ip_csum(&mut b);
    assert_eq!(parse_frame_ip(&b).unwrap_err(), DropReason::Ipv4Fragment);
    let mut b = tcp_frame();
    b[ETH_HDR + 10] ^= 1;
    assert_eq!(parse_frame_ip(&b).unwrap_err(), DropReason::Ipv4BadChecksum);
}

#[test]
fn ipv4_body_re_emits_byte_identical() {
    let b = tcp_frame();
    let f = parse_frame_ip(&b).unwrap();
    let mut out = [0u8; MAX_FRAME];
    let n = emit(&f, &mut out).unwrap();
    assert_eq!(&out[..n], &b[..]);
}

#[test]
fn emit_refuses_an_ipv4_body_that_does_not_parse_to_itself() {
    let b = tcp_frame();
    let Body::Ipv4(p) = parse_frame_ip(&b).unwrap().body else { panic!("not ipv4") };
    let lie = Frame {
        eth: EthAddrs { src: GW_MAC, dst: HOST_MAC },
        body: Body::Ipv4(Ip4Packet { src: GW_IP, ..p }),
    };
    assert_eq!(emit(&lie, &mut [0u8; MAX_FRAME]), Err(EmitError::Invalid));
}

#[test]
fn outside_parser_still_rejects_non_udp() {
    assert_eq!(reason(&tcp_frame()), DropReason::NotUdp);
}

#[test]
fn udp_bad_length() {
    let mut b = udp_frame(b"abcd");
    b[ETH_HDR + IPV4_HDR + 5] -= 1;
    assert_eq!(reason(&b), DropReason::UdpBadLength);
}

#[test]
fn udp_bad_checksum() {
    let mut b = udp_frame(b"abcd");
    *b.last_mut().unwrap() ^= 1;
    assert_eq!(reason(&b), DropReason::UdpBadChecksum);
}

/// One frame per reason. The exhaustive match makes a new `DropReason`
/// a compile error here until it has a triggering frame.
fn frame_for(r: DropReason) -> Option<Vec<u8>> {
    let mut b = udp_frame(b"abcd");
    match r {
        DropReason::TooShort => b.truncate(13),
        DropReason::TooLong => b.resize(MAX_FRAME + 1, 0),
        DropReason::EthBadSrc => b[6] |= 1,
        DropReason::UnknownEtherType => b[12] = 0x86,
        DropReason::ArpMalformed => {
            b = arp_request();
            b[ETH_HDR + 7] = 3;
        }
        DropReason::ArpBadSender => {
            b = arp_request();
            b[ETH_HDR + 8] |= 1;
        }
        DropReason::Ipv4Version => b[ETH_HDR] = 0x65,
        DropReason::Ipv4Options => b[ETH_HDR] = 0x46,
        DropReason::Ipv4Fragment => b[ETH_HDR + 6] = 0x20,
        DropReason::Ipv4BadLength => b[ETH_HDR + 2] = 0x10,
        DropReason::Ipv4BadChecksum => b[ETH_HDR + 8] ^= 1,
        DropReason::Ipv4BadSrc => {
            b[ETH_HDR + 12] = 224;
            fix_ip_csum(&mut b);
        }
        DropReason::NotUdp => {
            b[ETH_HDR + 9] = 6;
            fix_ip_csum(&mut b);
        }
        DropReason::UdpBadLength => b[ETH_HDR + IPV4_HDR + 5] -= 1,
        DropReason::UdpBadChecksum => *b.last_mut().unwrap() ^= 1,
        // Forwarding only; see `forward_*` tests below.
        DropReason::TtlExpired => return None,
    }
    Some(b)
}

#[test]
fn every_parser_drop_reason_is_produced_by_its_frame() {
    for &r in DropReason::ALL {
        if let Some(f) = frame_for(r) {
            assert_eq!(reason(&f), r);
        }
    }
}

fn ip_with_ttl(ttl: u8) -> Vec<u8> {
    let mut b = udp_frame(b"abcd");
    b[ETH_HDR + 8] = ttl;
    fix_ip_csum(&mut b);
    b[ETH_HDR..].to_vec()
}

#[test]
fn forward_decrements_ttl_and_fixes_the_checksum() {
    let p = ip_with_ttl(64);
    let mut out = [0u8; MAX_FRAME];
    let n = forward_ipv4(&p, &mut out).unwrap();
    assert_eq!(n, p.len());
    assert_eq!(out[8], 63);
    assert_eq!(csum_fold(csum_add(0, &out[..IPV4_HDR])), 0);
    assert_eq!(&out[IPV4_HDR..n], &p[IPV4_HDR..]);
    assert!(parse_ipv4_packet(&out[..n]).is_ok());
}

#[test]
fn forward_boundary_is_ttl_two() {
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(forward_ipv4(&ip_with_ttl(2), &mut out).map(|_| out[8]), Ok(1));
    assert_eq!(forward_ipv4(&ip_with_ttl(1), &mut out), Err(DropReason::TtlExpired));
    assert_eq!(forward_ipv4(&ip_with_ttl(0), &mut out), Err(DropReason::TtlExpired));
}

#[test]
fn forward_refuses_what_the_parser_refuses() {
    let mut p = ip_with_ttl(64);
    p[10] ^= 1;
    assert_eq!(forward_ipv4(&p, &mut [0u8; MAX_FRAME]), Err(DropReason::Ipv4BadChecksum));
}

#[test]
fn emit_refuses_invalid_source() {
    let f = Frame {
        eth: EthAddrs { src: [0xff; 6], dst: GW_MAC },
        body: Body::Udp4(Udp4 { src: HOST_IP, dst: GW_IP, sport: 1, dport: 2, payload: b"" }),
    };
    assert_eq!(emit(&f, &mut [0u8; MAX_FRAME]), Err(EmitError::Invalid));
}

#[test]
fn emit_reports_small_buffer() {
    let b = arp_request();
    let f = parse_frame(&b).unwrap();
    assert_eq!(emit(&f, &mut [0u8; ETH_HDR + ARP_LEN - 1]), Err(EmitError::TooSmall));
}

#[test]
fn fuzz_parse_never_panics_and_round_trips() {
    bolero::check!().for_each(|bytes: &[u8]| check(bytes));
}
