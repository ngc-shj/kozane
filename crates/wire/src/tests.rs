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

/// The reason `ingress` drops an outside frame for: `parse_frame`'s, and
/// for TCP (refused there as NotUdp) `parse_tcp`'s on the re-parse.
fn outside_reason(b: &[u8]) -> DropReason {
    match parse_frame(b) {
        Err(DropReason::NotUdp) => match parse_frame_ip(b) {
            Ok(Frame { body: Body::Ipv4(p), .. }) => parse_tcp(&p).map_or_else(|r| r, |_| panic!("accepted TCP")),
            other => panic!("re-parse: {other:?}"),
        },
        other => other.unwrap_err(),
    }
}

/// An IPv4/TCP datagram from HOST_IP:40000 to GW_IP:443, checksums right,
/// its data offset what `options` (a multiple of 4 bytes) make it.
fn tcp_packet(flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend_from_slice(&40000u16.to_be_bytes());
    seg.extend_from_slice(&443u16.to_be_bytes());
    seg.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    seg.extend_from_slice(&0x0a0b_0c0du32.to_be_bytes());
    seg.push((((TCP_HDR + options.len()) / 4) as u8) << 4);
    seg.push(flags);
    seg.extend_from_slice(&64240u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 0, 0]);
    seg.extend_from_slice(options);
    seg.extend_from_slice(payload);
    let mut p = std::vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, IPPROTO_TCP, 0, 0];
    p.extend_from_slice(&HOST_IP);
    p.extend_from_slice(&GW_IP);
    let total = (IPV4_HDR + seg.len()) as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    let c = csum_fold(csum_add(0, &p));
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&seg);
    fix_tcp_csum(&mut p);
    p
}

/// Recomputes the TCP checksum of an IPv4/TCP datagram after a mutation.
fn fix_tcp_csum(p: &mut [u8]) {
    p[IPV4_HDR + 16] = 0;
    p[IPV4_HDR + 17] = 0;
    let seg = &p[IPV4_HDR..];
    let pseudo = csum_add(csum_add(0, &p[12..16]), &p[16..20]) + u32::from(IPPROTO_TCP) + seg.len() as u32;
    let c = csum_fold(csum_add(pseudo, seg));
    p[IPV4_HDR + 16..IPV4_HDR + 18].copy_from_slice(&c.to_be_bytes());
}

fn tcp(p: &[u8]) -> Result<TcpHeader<'_>, DropReason> {
    parse_tcp(&parse_ipv4_packet(p).unwrap())
}

/// The same datagram in an Ethernet frame from HOST_MAC to GW_MAC.
fn tcp_frame_of(p: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&GW_MAC);
    f.extend_from_slice(&HOST_MAC);
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f.extend_from_slice(p);
    f
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
        // GRE: a protocol nothing serves (TCP has its own reasons below).
        DropReason::NotUdp => {
            b[ETH_HDR + 9] = 47;
            fix_ip_csum(&mut b);
        }
        DropReason::UdpBadLength => b[ETH_HDR + IPV4_HDR + 5] -= 1,
        DropReason::UdpBadChecksum => *b.last_mut().unwrap() ^= 1,
        // Forwarding only; see `forward_*` tests below.
        DropReason::TtlExpired => return None,
        DropReason::TcpBadLength => {
            let mut p = tcp_packet(TCP_SYN, &[], b"");
            p.truncate(IPV4_HDR + TCP_HDR - 1);
            p[2..4].copy_from_slice(&((IPV4_HDR + TCP_HDR - 1) as u16).to_be_bytes());
            p[10] = 0;
            p[11] = 0;
            let c = csum_fold(csum_add(0, &p[..IPV4_HDR]));
            p[10..12].copy_from_slice(&c.to_be_bytes());
            b = tcp_frame_of(&p);
        }
        DropReason::TcpBadOffset => {
            let mut p = tcp_packet(TCP_SYN, &[], b"");
            p[IPV4_HDR + 12] = 4 << 4;
            fix_tcp_csum(&mut p);
            b = tcp_frame_of(&p);
        }
        DropReason::TcpBadChecksum => {
            let mut p = tcp_packet(TCP_SYN, &[], b"");
            p[IPV4_HDR + 16] ^= 1;
            b = tcp_frame_of(&p);
        }
        DropReason::TcpBadPort => {
            let mut p = tcp_packet(TCP_SYN, &[], b"");
            p[IPV4_HDR..IPV4_HDR + 2].fill(0);
            fix_tcp_csum(&mut p);
            b = tcp_frame_of(&p);
        }
        DropReason::TcpBadFlags => b = tcp_frame_of(&tcp_packet(TCP_SYN | TCP_FIN, &[], b"")),
        DropReason::TcpBadOptions => b = tcp_frame_of(&tcp_packet(TCP_SYN, &[2, 1, 0, 0], b"")),
        // `ingress_core::tls_egress` only.
        DropReason::TcpEgressRefused => return None,
    }
    Some(b)
}

#[test]
fn every_parser_drop_reason_is_produced_by_its_frame() {
    for &r in DropReason::ALL {
        if let Some(f) = frame_for(r) {
            assert_eq!(outside_reason(&f), r);
        }
    }
}

// ---- parse_tcp (M6 plan C2) ----

#[test]
fn a_tcp_segment_parses_to_its_fields() {
    let p = tcp_packet(TCP_ACK | TCP_PSH, &[], b"hello");
    let t = tcp(&p).unwrap();
    assert_eq!((t.src_port, t.dst_port, t.seq, t.ack), (40000, 443, 0x0102_0304, 0x0a0b_0c0d));
    assert_eq!((t.data_offset, t.flags, t.window, t.payload), (5, TCP_ACK | TCP_PSH, 64240, &b"hello"[..]));
    assert!(!t.is_syn_request());
}

#[test]
fn a_linux_syn_with_its_options_parses() {
    // MSS 1460, SACK permitted, timestamps, NOP, window scale 7.
    let opts = [2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7];
    let p = tcp_packet(TCP_SYN, &opts, b"");
    let t = tcp(&p).unwrap();
    assert_eq!((t.data_offset, t.payload.len()), (10, 0));
    assert!(t.is_syn_request());
    assert!(!tcp(&tcp_packet(TCP_SYN | TCP_ACK, &opts, b"")).unwrap().is_syn_request());
}

#[test]
fn tcp_header_length_bound_is_twenty_bytes() {
    let p = tcp_packet(TCP_ACK, &[], b"");
    assert_eq!(tcp(&p).map(|t| t.payload.len()), Ok(0));
    let short = &p[..IPV4_HDR + TCP_HDR - 1];
    let pkt = Ip4Packet { src: HOST_IP, dst: GW_IP, proto: IPPROTO_TCP, packet: short };
    assert_eq!(parse_tcp(&pkt), Err(DropReason::TcpBadLength));
}

#[test]
fn tcp_segment_length_bound_is_what_a_frame_carries() {
    let max = MAX_FRAME - ETH_HDR - IPV4_HDR - TCP_HDR;
    let p = tcp_packet(TCP_ACK, &[], &std::vec![7; max]);
    assert_eq!(tcp(&p).map(|t| t.payload.len()), Ok(max));
    let mut long = p.clone();
    long.push(7);
    let pkt = Ip4Packet { src: HOST_IP, dst: GW_IP, proto: IPPROTO_TCP, packet: &long };
    assert_eq!(parse_tcp(&pkt), Err(DropReason::TcpBadLength));
}

#[test]
fn tcp_data_offset_bounds_are_five_and_fifteen_words_within_the_segment() {
    let mut p = tcp_packet(TCP_ACK, &[], b"");
    p[IPV4_HDR + 12] = 4 << 4;
    fix_tcp_csum(&mut p);
    assert_eq!(tcp(&p), Err(DropReason::TcpBadOffset), "4 words");
    let p = tcp_packet(TCP_ACK, &[1; 40], b"x");
    let t = tcp(&p).unwrap();
    assert_eq!((t.data_offset, t.payload), (15, &b"x"[..]), "15 words");
    // 6 words claimed, 5 present.
    let mut p = tcp_packet(TCP_ACK, &[], b"");
    p[IPV4_HDR + 12] = 6 << 4;
    fix_tcp_csum(&mut p);
    assert_eq!(tcp(&p), Err(DropReason::TcpBadOffset), "past the segment");
    // 6 words claimed, exactly 6 present (the 4 data bytes become options).
    let mut p = tcp_packet(TCP_ACK, &[], &[1, 1, 1, 1]);
    p[IPV4_HDR + 12] = 6 << 4;
    fix_tcp_csum(&mut p);
    assert_eq!(tcp(&p).map(|t| (t.data_offset, t.payload.len())), Ok((6, 0)), "at the segment's end");
}

#[test]
fn tcp_checksum_is_checked_on_every_segment() {
    let good = tcp_packet(TCP_ACK, &[], b"data");
    assert!(tcp(&good).is_ok());
    for at in [IPV4_HDR, IPV4_HDR + 13, IPV4_HDR + 16, good.len() - 1] {
        let mut p = good.clone();
        p[at] ^= 0x10;
        assert_eq!(tcp(&p), Err(DropReason::TcpBadChecksum), "byte {at}");
    }
    // The pseudo-header binds the addresses: the same segment claimed from
    // another source fails.
    let p = parse_ipv4_packet(&good).unwrap();
    assert_eq!(parse_tcp(&Ip4Packet { src: [10, 0, 2, 3], ..p }), Err(DropReason::TcpBadChecksum));
}

#[test]
fn tcp_port_zero_is_refused_on_either_side_and_one_accepted() {
    for at in [0, 2] {
        let mut p = tcp_packet(TCP_SYN, &[], b"");
        p[IPV4_HDR + at..IPV4_HDR + at + 2].copy_from_slice(&0u16.to_be_bytes());
        fix_tcp_csum(&mut p);
        assert_eq!(tcp(&p), Err(DropReason::TcpBadPort), "offset {at}");
        p[IPV4_HDR + at + 1] = 1;
        fix_tcp_csum(&mut p);
        assert!(tcp(&p).is_ok(), "port 1 at {at}");
    }
}

#[test]
fn syn_with_fin_or_rst_is_refused_and_other_combinations_accepted() {
    for flags in [TCP_SYN | TCP_FIN, TCP_SYN | TCP_RST, TCP_SYN | TCP_ACK | TCP_FIN, 0xff] {
        assert_eq!(tcp(&tcp_packet(flags, &[], b"")), Err(DropReason::TcpBadFlags), "flags {flags:#x}");
    }
    for flags in [TCP_SYN, TCP_SYN | TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST, TCP_RST | TCP_ACK, 0] {
        assert!(tcp(&tcp_packet(flags, &[], b"")).is_ok(), "flags {flags:#x}");
    }
}

#[test]
fn tcp_options_are_walked_by_length() {
    let ok = |o: &[u8]| tcp(&tcp_packet(TCP_SYN, o, b"")).is_ok();
    assert!(ok(&[2, 2, 1, 1]), "length 2");
    assert!(ok(&[1, 1, 2, 2]), "NOPs then length 2");
    assert!(ok(&[1, 2, 3, 0xee]), "length to the header's end");
    assert!(ok(&[0, 0xff, 0xff, 0xff]), "anything after end of list");
    let bad = |o: &[u8]| tcp(&tcp_packet(TCP_SYN, o, b"")).map(|_| ());
    assert_eq!(bad(&[2, 1, 0, 0]), Err(DropReason::TcpBadOptions), "length 1");
    assert_eq!(bad(&[2, 0, 0, 0]), Err(DropReason::TcpBadOptions), "length 0");
    assert_eq!(bad(&[1, 2, 4, 0]), Err(DropReason::TcpBadOptions), "length past the header");
    assert_eq!(bad(&[1, 1, 1, 8]), Err(DropReason::TcpBadOptions), "kind without a length byte");
}

#[test]
fn another_protocol_is_not_tcp() {
    let b = tcp_packet(TCP_SYN, &[], b"");
    let p = parse_ipv4_packet(&b).unwrap();
    assert_eq!(parse_tcp(&Ip4Packet { proto: 17, ..p }), Err(DropReason::NotUdp));
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
