//! Kani harnesses for `parse_frame`. Run with `cargo kani -p wire`.

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
