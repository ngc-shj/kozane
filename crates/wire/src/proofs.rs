//! Kani harnesses for `parse_frame` and `parse_tcp`. Run with
//! `cargo kani -p wire`.

use super::*;

const MAX_LEN: usize = 64;

fn any_frame_bytes(buf: &[u8; MAX_LEN]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);
    buf.get(..len).unwrap_or(&[])
}

/// No panic for any input of length 0..=64, and every outcome is reachable
/// (an unsatisfiable cover means the harness or the parser is broken).
#[kani::proof]
#[kani::unwind(66)]
fn parse_is_total_and_all_outcomes_reachable() {
    let buf: [u8; MAX_LEN] = kani::any();
    let r = parse_frame(any_frame_bytes(&buf));
    kani::cover!(matches!(r, Ok(Frame { body: Body::Arp(_), .. })));
    kani::cover!(matches!(r, Ok(Frame { body: Body::Udp4(u), .. }) if !u.payload.is_empty()));
    // Exhaustive: a new DropReason fails to compile until it has a cover.
    if let Err(reason) = r {
        match reason {
            DropReason::TooShort => kani::cover!(true),
            // Needs > MAX_FRAME bytes; covered by `oversized_frame_is_dropped`.
            DropReason::TooLong => {}
            DropReason::EthBadSrc => kani::cover!(true),
            DropReason::UnknownEtherType => kani::cover!(true),
            DropReason::ArpMalformed => kani::cover!(true),
            DropReason::ArpBadSender => kani::cover!(true),
            DropReason::Ipv4Version => kani::cover!(true),
            DropReason::Ipv4Options => kani::cover!(true),
            DropReason::Ipv4Fragment => kani::cover!(true),
            DropReason::Ipv4BadLength => kani::cover!(true),
            DropReason::Ipv4BadChecksum => kani::cover!(true),
            DropReason::Ipv4BadSrc => kani::cover!(true),
            DropReason::NotUdp => kani::cover!(true),
            DropReason::UdpBadLength => kani::cover!(true),
            DropReason::UdpBadChecksum => kani::cover!(true),
            // Produced by `forward_ipv4`, never by the parser.
            DropReason::TtlExpired => {}
            // `parse_tcp`'s (`parse_tcp_checks_every_accepted_header`) and
            // `ingress_core::tls_egress`'s, never `parse_frame`'s.
            DropReason::TcpBadLength
            | DropReason::TcpBadOffset
            | DropReason::TcpBadChecksum
            | DropReason::TcpBadPort
            | DropReason::TcpBadFlags
            | DropReason::TcpBadOptions
            | DropReason::TcpEgressRefused => {}
        }
    }
}

/// TooLong needs > MAX_FRAME bytes; checked separately with a cheap length-only input.
#[kani::proof]
fn oversized_frame_is_dropped() {
    let buf = [0u8; MAX_FRAME + 1];
    assert_eq!(parse_frame(&buf), Err(DropReason::TooLong));
}

/// Accepted frames re-emit to an equal frame.
#[kani::proof]
#[kani::unwind(66)]
fn accepted_frames_round_trip() {
    let buf: [u8; MAX_LEN] = kani::any();
    let bytes = any_frame_bytes(&buf);
    // Same property bolero checks (`check_into`), parsing once so the covers
    // do not double the problem size (a second parse made CBMC fail). A
    // frame parsed from <= 64 bytes re-emits in <= 64 bytes.
    let mut out = [0u8; MAX_LEN];
    if let Ok(f) = check_into(bytes, &mut out) {
        // Without these the harness would pass vacuously if nothing were accepted.
        kani::cover!(matches!(f.body, Body::Arp(_)));
        kani::cover!(matches!(f.body, Body::Udp4(u) if !u.payload.is_empty()));
    }
}

/// Inside-NIC parser: total, and accepted frames (any IPv4 protocol,
/// forwarded verbatim) re-emit to an equal frame.
#[kani::proof]
#[kani::unwind(66)]
fn parse_ip_is_total_and_round_trips() {
    let buf: [u8; MAX_LEN] = kani::any();
    let bytes = any_frame_bytes(&buf);
    let mut out = [0u8; MAX_LEN];
    let r = check_ip_into(bytes, &mut out);
    kani::cover!(matches!(r, Ok(Frame { body: Body::Ipv4(p), .. }) if p.proto != 17));
    kani::cover!(matches!(r, Ok(Frame { body: Body::Ipv4(p), .. }) if p.packet.len() > IPV4_HDR));
    kani::cover!(matches!(r, Ok(Frame { body: Body::Arp(_), .. })));
    kani::cover!(r == Err(DropReason::Ipv4BadChecksum));
    assert!(!matches!(r, Ok(Frame { body: Body::Udp4(_), .. })));
}

/// Forwarding keeps the datagram parseable, lowers TTL by exactly one,
/// changes nothing else but the checksum, and refuses TTL <= 1.
#[kani::proof]
#[kani::unwind(50)]
fn forward_decrements_ttl_and_keeps_the_datagram_valid() {
    let buf: [u8; 48] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let input = buf.get(..len).unwrap_or(&[]);
    let mut out = [0u8; 48];
    match forward_ipv4(input, &mut out) {
        Ok(n) => {
            let before = parse_ipv4_packet(input).ok().map(|p| p.packet);
            let after = out.get(..n).unwrap_or(&[]);
            assert!(parse_ipv4_packet(after).is_ok());
            if let Some(b) = before {
                assert!(b.len() == n && b[8] > 1 && after[8] == b[8] - 1);
                for i in 0..n {
                    if i != 8 && i != 10 && i != 11 {
                        assert!(after[i] == b[i]);
                    }
                }
            }
            kani::cover!(true);
        }
        Err(e) => {
            kani::cover!(e == DropReason::TtlExpired);
        }
    }
    // Deny side, proved rather than covered: a datagram the parser accepts
    // with TTL 0 or 1 is always refused as TtlExpired.
    if let Ok(p) = parse_ipv4_packet(input) {
        if p.packet[8] <= 1 {
            // Pins reachability directly, not by inference through
            // forward_ipv4's internal order.
            kani::cover!(p.packet[8] == 1);
            kani::cover!(p.packet[8] == 0);
            assert!(forward_ipv4(input, &mut out) == Err(DropReason::TtlExpired));
        }
    }
}

/// `parse_tcp` (M6 plan C2) over any segment of 0..=64 bytes behind any
/// IPv4 header, from any addresses, of any protocol: no panic; an accepted
/// header is TCP, its data offset is 5..=15 words and within the segment,
/// the data is the rest of the segment, both ports are nonzero, SYN never
/// comes with FIN or RST, and the checksum over the pseudo-header holds.
#[kani::proof]
#[kani::unwind(66)]
fn parse_tcp_checks_every_accepted_header() {
    let buf: [u8; IPV4_HDR + MAX_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);
    let packet = buf.get(..IPV4_HDR + len).unwrap_or(&[]);
    let pkt = Ip4Packet { src: kani::any(), dst: kani::any(), proto: kani::any(), packet };
    let r = parse_tcp(&pkt);
    if let Ok(t) = r {
        let segment = &packet[IPV4_HDR..];
        let header = usize::from(t.data_offset) * 4;
        assert!(pkt.proto == IPPROTO_TCP);
        assert!(t.data_offset >= 5 && t.data_offset <= 15 && header <= segment.len());
        assert!(t.payload.len() == segment.len() - header);
        assert!(t.src_port != 0 && t.dst_port != 0);
        assert!(t.flags & TCP_SYN == 0 || t.flags & (TCP_FIN | TCP_RST) == 0);
        let pseudo = csum_add(csum_add(0, &pkt.src), &pkt.dst) + u32::from(IPPROTO_TCP) + segment.len() as u32;
        assert!(csum_fold(csum_add(pseudo, segment)) == 0);
    }
    kani::cover!(matches!(r, Ok(t) if !t.payload.is_empty()));
    kani::cover!(matches!(r, Ok(t) if t.data_offset > 5));
    kani::cover!(matches!(r, Ok(t) if t.is_syn_request()));
    kani::cover!(r == Err(DropReason::NotUdp));
    kani::cover!(r == Err(DropReason::TcpBadLength));
    kani::cover!(r == Err(DropReason::TcpBadOffset));
    kani::cover!(r == Err(DropReason::TcpBadChecksum));
    kani::cover!(r == Err(DropReason::TcpBadPort));
    kani::cover!(r == Err(DropReason::TcpBadFlags));
    kani::cover!(r == Err(DropReason::TcpBadOptions));
}
