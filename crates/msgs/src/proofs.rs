//! Kani harnesses for the link decoders.

use super::*;

/// Every decoder is total, and whatever decodes re-encodes to the
/// same bytes (so no field is silently dropped).
#[kani::proof]
#[kani::unwind(20)]
fn small_decoders_are_total_and_round_trip() {
    let buf: [u8; 16] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let b = buf.get(..len).unwrap_or(&[]);
    let mut out = [0u8; 16];
    if let Ok(m) = ToIngress::decode(b) {
        kani::cover!(matches!(m, ToIngress::Outbound { .. }));
        kani::cover!(matches!(m, ToIngress::EndpointUpdate { .. }));
        assert!(m.encode(&mut out) == Some(len) && out.get(..len) == Some(b));
    }
    if let Ok(m) = Transport::decode(b) {
        kani::cover!(!m.msg.is_empty());
        assert!(m.encode(&mut out) == Some(len) && out.get(..len) == Some(b));
    }
}

/// Longest `RpDatagram` on the wire (RespHello) plus one byte, so every
/// accepted length and a too-long input are both in range.
const RP_MAX: usize = EP_LEN + 1132 + 1;

/// The message is up to 1132 bytes, too long for a byte-wise comparison
/// under Kani, so the round trip is shown structurally: the endpoint is the
/// first 6 bytes, `msg` is exactly the rest of the input, and re-encoding
/// writes the endpoint back and returns the input length.
#[kani::proof]
#[kani::unwind(8)]
fn rp_datagram_decode_is_total() {
    let buf: [u8; RP_MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let b = buf.get(..len).unwrap_or(&[]);
    let mut out = [0u8; RP_MAX];
    match RpDatagram::decode(b) {
        Ok(m) => {
            kani::cover!(m.msg.len() == 1092);
            kani::cover!(m.msg.len() == 1132);
            kani::cover!(m.msg.len() == 176);
            kani::cover!(m.msg.len() == 64);
            assert!(RP_LENS.contains(&m.msg.len()));
            assert!(core::ptr::eq(m.msg, b.get(EP_LEN..).unwrap_or(&[])));
            assert!(m.encode(&mut out) == Some(len) && out.get(..EP_LEN) == b.get(..EP_LEN));
        }
        Err(Malformed) => {
            kani::cover!(len == EP_LEN + 1133);
            kani::cover!(len == EP_LEN + 175);
            assert!(len.checked_sub(EP_LEN).is_none_or(|n| !RP_LENS.contains(&n)));
        }
    }
}

#[kani::proof]
#[kani::unwind(40)]
fn psk_install_decode_is_total() {
    let buf: [u8; PSK_INSTALL_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let b = buf.get(..len).unwrap_or(&[]);
    let mut out = [0u8; PSK_INSTALL_LEN + 1];
    match PskInstall::decode(b) {
        Ok(m) => {
            kani::cover!(m.peer == u16::MAX);
            assert!(len == PSK_INSTALL_LEN);
            assert!(m.encode(&mut out) == Some(len) && out.get(..len) == Some(b));
        }
        Err(Malformed) => {
            kani::cover!(len == PSK_INSTALL_LEN + 1);
            kani::cover!(len == PSK_INSTALL_LEN - 1);
            assert!(len != PSK_INSTALL_LEN);
        }
    }
}

/// Longest `RpReply` (tag, index, RespHello) plus one byte.
const RP_REPLY_MAX: usize = 2 + 1132 + 1;

/// `RpReply::decode` is total and closed: a `Reply` is exactly tag 1, an
/// index and a reply length; `NoReply` is exactly the one tag byte; the
/// message is the rest of the input and re-encodes to the same length.
#[kani::proof]
#[kani::unwind(8)]
fn rp_reply_decode_is_total() {
    let buf: [u8; RP_REPLY_MAX] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let b = buf.get(..len).unwrap_or(&[]);
    let mut out = [0u8; RP_REPLY_MAX];
    match RpReply::decode(b) {
        Ok(RpReply::Reply { index, msg }) => {
            kani::cover!(msg.len() == 1132);
            kani::cover!(msg.len() == 64);
            assert!(RP_REPLY_LENS.contains(&msg.len()));
            assert!(b.first() == Some(&1) && b.get(1) == Some(&index));
            assert!(core::ptr::eq(msg, b.get(2..).unwrap_or(&[])));
            assert!(RpReply::Reply { index, msg }.encode(&mut out) == Some(len));
        }
        Ok(RpReply::NoReply) => {
            assert!(b == [2]);
        }
        Err(Malformed) => {
            kani::cover!(len == 2 + 1092);
            kani::cover!(len == 2);
        }
    }
}
