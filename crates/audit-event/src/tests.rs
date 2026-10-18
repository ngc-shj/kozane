#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]

extern crate std;

use std::vec::Vec;

use super::*;

fn run(c: &mut Coalescer, ev: Event, n: u32, out: &mut Vec<Record>) {
    for _ in 0..n {
        let _ = c.record(ev, |r| {
            out.push(r);
            true
        });
    }
}

#[test]
fn first_occurrence_emits() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::ArpReplied, 1, &mut out);
    assert_eq!(out, [Record { code: 0x0001, _reserved: 0, a: 1, b: 0 }]);
}

#[test]
fn second_through_sixty_fourth_do_not_emit() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::UdpEchoed, 64, &mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn sixty_fifth_emits_with_running_total() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::UdpEchoed, 65, &mut out);
    assert_eq!(out.iter().map(|r| r.a).collect::<Vec<_>>(), [1, 65]);
}

#[test]
fn kinds_are_counted_independently() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::FrameDropped { reason: 3 }, 2, &mut out);
    run(&mut c, Event::FrameDropped { reason: 4 }, 1, &mut out);
    let codes: Vec<_> = out.iter().map(|r| r.code).collect();
    assert_eq!(codes, [FRAME_DROPPED_BASE | 3, FRAME_DROPPED_BASE | 4]);
}

#[test]
fn full_ring_counts_overflow_and_next_push_carries_it() {
    let mut c = Coalescer::new();
    // Ring full for the first occurrence of two kinds.
    let _ = c.record(Event::ArpReplied, |_| false);
    let _ = c.record(Event::UdpEchoed, |_| false);
    assert_eq!(c.overflow(), 2);
    let mut got = None;
    let _ = c.record(Event::RingCorrupt, |r| {
        got = Some(r);
        true
    });
    assert_eq!(got.unwrap().b, 2);
    assert_eq!(c.overflow(), 0);
}

#[test]
fn out_of_range_drop_reason_is_clamped_not_aliased_to_other_events() {
    let ev = Event::FrameDropped { reason: 0xffff };
    assert_eq!(ev.code(), FRAME_DROPPED_BASE | 0x3f);
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, ev, 1, &mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn flood_of_k_events_yields_ceil_k_over_64_records() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::FrameDropped { reason: 1 }, 1000, &mut out);
    assert_eq!(out.len(), 1000usize.div_ceil(64));
    assert_eq!(out.last().unwrap().a % 64, 1);
}

#[test]
fn record_reports_offered_even_when_ring_is_full() {
    // The caller notifies audit on every offer; a full ring must still
    // produce a notification so audit wakes and drains it.
    let mut c = Coalescer::new();
    assert!(c.record(Event::ArpReplied, |_| false));
}

#[test]
fn record_reports_not_offered_while_coalescing() {
    let mut c = Coalescer::new();
    assert!(c.record(Event::ArpReplied, |_| true));
    assert!(!c.record(Event::ArpReplied, |_| true));
}

#[test]
fn every_fixed_event_round_trips_through_its_code() {
    for ev in Event::FIXED {
        assert_eq!(Event::from_fixed_code(ev.code()), Some(ev));
    }
}

#[test]
fn fixed_codes_are_distinct_and_outside_frame_dropped_range() {
    let codes: Vec<u16> = Event::FIXED.iter().map(|e| e.code()).collect();
    for (i, a) in codes.iter().enumerate() {
        assert!(*a < FRAME_DROPPED_BASE);
        assert!(!codes[i + 1..].contains(a));
    }
}

#[test]
fn fixed_list_names_every_non_parameterised_variant() {
    // Exhaustive match: a new variant must be classified here, and if it
    // is fixed, added to FIXED (checked by the count).
    let fixed = |e: Event| match e {
        Event::ArpReplied
        | Event::UdpEchoed
        | Event::RingCorrupt
        | Event::RxNoBuffer
        | Event::TxNoBuffer
        | Event::BadDescriptor
        | Event::NotForUs
        | Event::NoService
        | Event::Spoofed
        | Event::DeviceFault
        | Event::FrameTooLong
        | Event::HandshakeOk
        | Event::HandshakeUnknownPeer
        | Event::HandshakeDecrypt
        | Event::HandshakeReplay
        | Event::HandshakeFlood
        | Event::HandshakeKeyRefused
        | Event::HandshakeOther
        | Event::WgBadMessage
        | Event::WgBadMac1
        | Event::WgRateLimited
        | Event::SessionInstalled
        | Event::SessionCollision
        | Event::TransportRejected
        | Event::SpoofedSource
        | Event::NoSession
        | Event::UnknownNeighbor
        | Event::SessionPromoted
        | Event::SessionExpired
        | Event::HandshakeKeyRateLimited
        | Event::TransportUnknownIndex => true,
        Event::FrameDropped { .. } => false,
    };
    assert!(Event::FIXED.iter().all(|e| fixed(*e)));
    assert_eq!(Event::FIXED.len(), 31);
}

#[test]
fn decode_classifies_fixed_dropped_and_unknown_codes() {
    assert_eq!(decode(Event::NoService.code()), Decoded::Fixed(Event::NoService));
    assert_eq!(decode(FRAME_DROPPED_BASE | 11), Decoded::FrameDropped(11));
    assert_eq!(decode(0x7777), Decoded::Unknown);
    assert_eq!(decode(FRAME_DROPPED_BASE + 0x40), Decoded::Unknown);
    // Upper edge of the FrameDropped range, and the first code after the
    // fixed range.
    assert_eq!(decode(FRAME_DROPPED_BASE + 0x3f), Decoded::FrameDropped(0x3f));
    assert_eq!(decode(0x0019), Decoded::Unknown);
}

#[test]
fn unknown_codes_share_one_coalesced_counter() {
    let mut u = UnknownCodes::new();
    let due: Vec<u32> = (0..130).filter_map(|_| u.record()).collect();
    assert_eq!(due, [1, 65, 129]);
}
