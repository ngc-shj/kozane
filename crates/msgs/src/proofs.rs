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

/// `chunk_ref`'s contract, the one trusted function under Verus (M4 plan C1,
/// C3): for every `N` the decoders borrow, and any input up to `N + 8`
/// bytes and any offset, it is `Some` exactly when the `N` bytes at `at` are
/// in range, and then it is those bytes, borrowed from `b` itself.
macro_rules! chunk_ref_contract {
    ($name:ident, $n:expr) => {
        #[kani::proof]
        #[kani::unwind(10)]
        fn $name() {
            const N: usize = $n;
            let buf: [u8; N + 8] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= buf.len());
            let b = buf.get(..len).unwrap_or(&[]);
            let at: usize = kani::any();
            let r = chunk_ref::<N>(b, at);
            let in_range = at.checked_add(N).is_some_and(|end| end <= b.len());
            assert!(r.is_some() == in_range);
            // Borrowed in place: the result starts at `b[at]`, so its `N`
            // bytes are `b[at..at + N]` (a byte compare would only re-read
            // the same memory, and costs an unwind per byte).
            if let Some(c) = r {
                assert!(core::ptr::eq(c.as_ptr(), b.as_ptr().wrapping_add(at)));
            }
        }
    };
}

chunk_ref_contract!(chunk_ref_initiation, INITIATION_LEN);
chunk_ref_contract!(chunk_ref_response, RESPONSE_LEN);
chunk_ref_contract!(chunk_ref_key, 32);
