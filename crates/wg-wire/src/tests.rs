#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use super::replay::ReplayWindow;
use super::*;

fn initiation() -> MessageInitiation {
    MessageInitiation {
        sender: 0x0403_0201,
        ephemeral: [0x11; 32],
        enc_static: [0x22; 48],
        enc_timestamp: [0x33; 28],
        mac1: [0x44; 16],
        mac2: [0x55; 16],
    }
}

fn response() -> MessageResponse {
    MessageResponse {
        sender: 0x0807_0605,
        receiver: 0x0c0b_0a09,
        ephemeral: [0x66; 32],
        enc_nothing: [0x77; 16],
        mac1: [0x88; 16],
        mac2: [0x99; 16],
    }
}

#[test]
fn initiation_layout_matches_the_whitepaper() {
    let mut b = [0u8; INITIATION_LEN];
    assert_eq!(initiation().emit(&mut b), Ok(INITIATION_LEN));
    assert_eq!(&b[..8], &[1, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(&b[8..40], &[0x11; 32]);
    assert_eq!(&b[40..88], &[0x22; 48]);
    assert_eq!(&b[88..116], &[0x33; 28]);
    assert_eq!(&b[INITIATION_MAC1_OFFSET..132], &[0x44; 16]);
    assert_eq!(&b[132..148], &[0x55; 16]);
    assert_eq!(MessageInitiation::parse(&b), Ok(initiation()));
}

#[test]
fn response_layout_matches_the_whitepaper() {
    let mut b = [0u8; RESPONSE_LEN];
    assert_eq!(response().emit(&mut b), Ok(RESPONSE_LEN));
    assert_eq!(&b[..12], &[2, 0, 0, 0, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(&b[12..44], &[0x66; 32]);
    assert_eq!(&b[44..RESPONSE_MAC1_OFFSET], &[0x77; 16]);
    assert_eq!(&b[60..76], &[0x88; 16]);
    assert_eq!(&b[76..92], &[0x99; 16]);
    assert_eq!(MessageResponse::parse(&b), Ok(response()));
}

#[test]
fn initiation_rejects_wrong_length_type_and_reserved() {
    let mut b = [0u8; INITIATION_LEN + 1];
    initiation().emit(&mut b).unwrap();
    assert_eq!(MessageInitiation::parse(&b), Err(WireError::WrongLength));
    assert_eq!(MessageInitiation::parse(&b[..INITIATION_LEN - 1]), Err(WireError::WrongLength));
    let mut m = [0u8; INITIATION_LEN];
    m.copy_from_slice(&b[..INITIATION_LEN]);
    m[0] = MSG_RESPONSE;
    assert_eq!(MessageInitiation::parse(&m), Err(WireError::WrongType));
    for i in 1..4 {
        let mut m2 = [0u8; INITIATION_LEN];
        m2.copy_from_slice(&b[..INITIATION_LEN]);
        m2[i] = 1;
        assert_eq!(MessageInitiation::parse(&m2), Err(WireError::ReservedNonZero), "byte {i}");
    }
}

#[test]
fn response_rejects_wrong_type_and_reserved() {
    let mut b = [0u8; RESPONSE_LEN];
    response().emit(&mut b).unwrap();
    let mut m = b;
    m[0] = MSG_INITIATION;
    assert_eq!(MessageResponse::parse(&m), Err(WireError::WrongType));
    let mut m = b;
    m[3] = 0x80;
    assert_eq!(MessageResponse::parse(&m), Err(WireError::ReservedNonZero));
    assert_eq!(MessageResponse::parse(&b[..91]), Err(WireError::WrongLength));
}

#[test]
fn emitters_refuse_short_buffers() {
    assert_eq!(initiation().emit(&mut [0u8; INITIATION_LEN - 1]), Err(WireError::BufferTooSmall));
    assert_eq!(response().emit(&mut [0u8; RESPONSE_LEN - 1]), Err(WireError::BufferTooSmall));
    assert_eq!(emit_transport_header(1, 2, &mut [0u8; 15]), Err(WireError::BufferTooSmall));
}

#[test]
fn transport_header_round_trips_and_keeps_the_ciphertext() {
    let mut b = [0xabu8; 40];
    assert_eq!(emit_transport_header(0xdead_beef, 0x0102_0304_0506_0708, &mut b), Ok(16));
    assert_eq!(&b[..16], &[4, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde, 8, 7, 6, 5, 4, 3, 2, 1]);
    let t = Transport::parse(&b).unwrap();
    assert_eq!(t.receiver, 0xdead_beef);
    assert_eq!(t.counter, 0x0102_0304_0506_0708);
    assert_eq!(t.ciphertext, &[0xab; 24]);
}

#[test]
fn transport_requires_a_full_tag_and_type_4() {
    let mut b = [0u8; TRANSPORT_MIN_LEN];
    emit_transport_header(1, 0, &mut b).unwrap();
    assert_eq!(Transport::parse(&b).unwrap().ciphertext.len(), TAG_LEN);
    assert_eq!(Transport::parse(&b[..TRANSPORT_MIN_LEN - 1]), Err(WireError::TooShort));
    b[0] = MSG_INITIATION;
    assert_eq!(Transport::parse(&b), Err(WireError::WrongType));
    b[0] = MSG_TRANSPORT;
    b[2] = 1;
    assert_eq!(Transport::parse(&b), Err(WireError::ReservedNonZero));
}

/// Port of Linux `drivers/net/wireguard/selftest/counter.c`. Linux's
/// COUNTER_WINDOW_SIZE is our `WINDOW`; every case keeps its number.
fn linux_counter_selftest<const BITS: usize>() {
    let w = ReplayWindow::<BITS>::WINDOW;
    let lim = w + 1;
    let ram = REJECT_AFTER_MESSAGES;
    let mut c = ReplayWindow::<BITS>::new();
    let mut n = 0u32;
    let mut t = |c: &mut ReplayWindow<BITS>, v: u64, expect: bool| {
        n += 1;
        assert_eq!(c.check_and_update(v), expect, "case {n} (counter {v}, BITS {BITS})");
    };
    #[rustfmt::skip]
    let cases: [(u64, bool); 34] = [
        (0, true), (1, true), (1, false), (9, true), (8, true), (7, true), (7, false),
        (lim, true), (lim - 1, true), (lim - 1, false), (lim - 2, true), (2, true), (2, false),
        (lim + 16, true), (3, false), (lim + 16, false), (lim * 4, true),
        (lim * 4 - (lim - 1), true), (10, false), (lim * 4 - lim, false),
        (lim * 4 - (lim + 1), false), (lim * 4 - (lim - 2), true), (lim * 4 + 1 - lim, false),
        (0, false), (ram, false), (ram - 1, true), (ram, false), (ram - 1, false),
        (ram - 2, true), (ram + 1, false), (ram + 2, false), (ram - 2, false), (ram - 3, true),
        (0, false),
    ];
    for (v, e) in cases {
        t(&mut c, v, e);
    }

    let mut c = ReplayWindow::<BITS>::new();
    for i in 1..=w {
        t(&mut c, i, true);
    }
    t(&mut c, 0, true);
    t(&mut c, 0, false);

    let mut c = ReplayWindow::<BITS>::new();
    for i in 2..=w + 1 {
        t(&mut c, i, true);
    }
    t(&mut c, 1, true);
    t(&mut c, 0, false);

    let mut c = ReplayWindow::<BITS>::new();
    for i in (0..=w).rev() {
        t(&mut c, i, true);
    }

    let mut c = ReplayWindow::<BITS>::new();
    for i in (1..=w + 1).rev() {
        t(&mut c, i, true);
    }
    t(&mut c, 0, false);

    let mut c = ReplayWindow::<BITS>::new();
    for i in (1..=w).rev() {
        t(&mut c, i, true);
    }
    t(&mut c, w + 1, true);
    t(&mut c, 0, false);

    let mut c = ReplayWindow::<BITS>::new();
    for i in (1..=w).rev() {
        t(&mut c, i, true);
    }
    t(&mut c, 0, true);
    t(&mut c, w + 1, true);
}

#[test]
fn replay_window_passes_linux_counter_selftest_at_2048() {
    linux_counter_selftest::<2048>();
}

#[test]
fn replay_window_passes_linux_counter_selftest_at_64() {
    linux_counter_selftest::<64>();
}

#[test]
fn replay_window_is_exactly_bits_minus_one_wide() {
    let mut c = ReplayWindow::<64>::new();
    assert!(c.check_and_update(100));
    assert!(c.check_and_update(100 - 63));
    assert!(!c.check_and_update(100 - 64));
}

/// Every parser is total and whatever parses re-emits to the same bytes; the
/// replay window agrees with a set-based model of its specification (exact
/// window of BITS - 1 below the highest accepted counter). Beyond Kani's
/// 152-byte bound: transport messages of any length (code review T2).
fn fuzz_one(bytes: &[u8]) {
    let mut out = [0u8; 2048];
    if let Ok(m) = MessageInitiation::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    if let Ok(m) = MessageResponse::parse(bytes) {
        let n = m.emit(&mut out).unwrap();
        assert_eq!(&out[..n], bytes);
    }
    if let Ok(t) = Transport::parse(bytes) {
        let n = emit_transport_header(t.receiver, t.counter, &mut out).unwrap();
        assert_eq!(&out[..n], &bytes[..n]);
        assert_eq!(t.ciphertext, &bytes[n..]);
    }
    // Replay window vs model, counters from consecutive byte pairs so they
    // fall inside and outside the window often.
    let mut w = ReplayWindow::<64>::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut max: Option<u64> = None;
    for pair in bytes.as_chunks::<2>().0 {
        let c = u64::from(u16::from_le_bytes(*pair));
        let expect = !seen.contains(&c) && max.is_none_or(|m| c + ReplayWindow::<64>::WINDOW >= m);
        assert_eq!(w.check_and_update(c), expect, "counter {c}, max {max:?}");
        if expect {
            seen.insert(c);
            max = Some(max.map_or(c, |m| m.max(c)));
        }
    }
}

#[test]
fn fuzz_parsers_never_panic_and_round_trip() {
    bolero::check!().for_each(fuzz_one);
}
