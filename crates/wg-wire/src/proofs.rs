//! Kani harnesses for the codecs and the replay window. Run with
//! `cargo kani -p wg-wire`.

use super::replay::ReplayWindow;
use super::*;

const MAX_LEN: usize = INITIATION_LEN + 4;

fn any_bytes(buf: &[u8; MAX_LEN]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);
    buf.get(..len).unwrap_or(&[])
}

#[kani::proof]
#[kani::unwind(150)]
fn initiation_parse_is_total() {
    let buf: [u8; MAX_LEN] = kani::any();
    let r = MessageInitiation::parse(any_bytes(&buf));
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::WrongLength));
    kani::cover!(r == Err(WireError::WrongType));
    kani::cover!(r == Err(WireError::ReservedNonZero));
    if let Ok(m) = r {
        let mut out = [0u8; INITIATION_LEN];
        assert_eq!(m.emit(&mut out), Ok(INITIATION_LEN));
        assert_eq!(MessageInitiation::parse(&out), Ok(m));
    }
}

#[kani::proof]
#[kani::unwind(150)]
fn response_parse_is_total() {
    let buf: [u8; MAX_LEN] = kani::any();
    let r = MessageResponse::parse(any_bytes(&buf));
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::WrongLength));
    kani::cover!(r == Err(WireError::WrongType));
    kani::cover!(r == Err(WireError::ReservedNonZero));
    if let Ok(m) = r {
        let mut out = [0u8; RESPONSE_LEN];
        assert_eq!(m.emit(&mut out), Ok(RESPONSE_LEN));
        assert_eq!(MessageResponse::parse(&out), Ok(m));
    }
}

#[kani::proof]
#[kani::unwind(150)]
fn cookie_reply_parse_is_total() {
    let buf: [u8; MAX_LEN] = kani::any();
    let r = CookieReply::parse(any_bytes(&buf));
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::WrongLength));
    kani::cover!(r == Err(WireError::WrongType));
    kani::cover!(r == Err(WireError::ReservedNonZero));
    if let Ok(m) = r {
        let mut out = [0u8; COOKIE_REPLY_LEN];
        assert_eq!(m.emit(&mut out), Ok(COOKIE_REPLY_LEN));
        assert_eq!(CookieReply::parse(&out), Ok(m));
    }
}

#[kani::proof]
#[kani::unwind(150)]
fn transport_parse_is_total() {
    let buf: [u8; MAX_LEN] = kani::any();
    let bytes = any_bytes(&buf);
    let r = Transport::parse(bytes);
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(WireError::TooShort));
    kani::cover!(r == Err(WireError::WrongType));
    kani::cover!(r == Err(WireError::ReservedNonZero));
    if let Ok(t) = r {
        assert!(t.ciphertext.len() >= TAG_LEN);
        assert_eq!(t.ciphertext.len() + TRANSPORT_HEADER_LEN, bytes.len());
    }
}

/// After any prior accept, a counter accepted once is rejected the second time.
#[kani::proof]
#[kani::unwind(66)]
fn replay_window_rejects_second_use() {
    let mut w = ReplayWindow::<64>::new();
    let prior: u64 = kani::any();
    w.check_and_update(prior);
    let c: u64 = kani::any();
    let first = w.check_and_update(c);
    let second = w.check_and_update(c);
    if first {
        assert!(!second);
    }
    kani::cover!(first);
    // Rejected for being replayed or too old, not for the message limit.
    kani::cover!(!first && c < REJECT_AFTER_MESSAGES);
    kani::cover!(!first && c == prior);
}
