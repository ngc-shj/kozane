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
        | Event::TransportUnknownIndex
        | Event::WgUnderLoad
        | Event::WgLoadCleared
        | Event::WgCookieSent
        | Event::WgCookieSuppressed
        | Event::WgCookieDropped
        | Event::WgMac2Accepted
        | Event::CookieSecretExpired
        | Event::CookieSecretUnavailable
        | Event::ArpSuppressed
        | Event::HandshakePskMissing
        | Event::HandshakePskStale
        | Event::RpBadMac
        | Event::RpRateLimited
        | Event::RpTypeDropped
        | Event::RpInitHello
        | Event::RpBiscuitReplay
        | Event::RpPskExported
        | Event::RpPskInstallFailed
        | Event::RpRngFailed
        | Event::RpDecapsRateLimited
        | Event::RpPqRecordStuck
        | Event::RpPqSyncDead
        | Event::RpUnderLoad
        | Event::RpLoadCleared
        | Event::RpCookieSecretExpired
        | Event::RpCookieSecretUnavailable
        | Event::RpCookieReplySent
        | Event::RpCookieAccepted
        | Event::RpCookieSuppressed
        | Event::Ready => true,
        Event::FrameDropped { .. }
        | Event::RpCostHighWater { .. }
        | Event::StackHighWater { .. }
        | Event::Halted { .. }
        | Event::KeyUnavailable { .. }
        | Event::KeyStackHighWater { .. } => false,
    };
    assert!(Event::FIXED.iter().all(|e| fixed(*e)));
    assert_eq!(Event::FIXED.len(), 61);
}

#[test]
fn never_coalesced_kind_emits_every_occurrence() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::WgUnderLoad, 65, &mut out);
    assert_eq!(out.len(), 65);
    assert_eq!(out[1], Record { code: Event::WgUnderLoad.code(), _reserved: 0, a: 2, b: 0 });
    assert_eq!(out[64].a, 65);
}

#[test]
fn coalesced_cookie_kind_does_not_emit_its_second_occurrence() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::WgCookieSent, 2, &mut out);
    assert_eq!(out.iter().map(|r| r.a).collect::<Vec<_>>(), [1]);
}

#[test]
fn arp_suppressed_is_coalesced_and_counted_apart_from_arp_replied() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::ArpReplied, 1, &mut out);
    run(&mut c, Event::ArpSuppressed, 65, &mut out);
    let got: Vec<_> = out.iter().map(|r| (r.code, r.a)).collect();
    assert_eq!(got, [(0x0001, 1), (0x003c, 1), (0x003c, 65)]);
}

#[test]
fn only_state_edge_kinds_are_never_coalesced() {
    let never: Vec<Event> = Event::FIXED.iter().copied().filter(|e| !e.is_coalesced()).collect();
    assert_eq!(
        never,
        [
            Event::WgUnderLoad,
            Event::WgLoadCleared,
            Event::CookieSecretExpired,
            Event::CookieSecretUnavailable,
            Event::RpPqRecordStuck,
            Event::RpPqSyncDead,
            Event::RpUnderLoad,
            Event::RpLoadCleared,
            Event::RpCookieSecretExpired,
            Event::RpCookieSecretUnavailable,
            Event::Ready,
        ]
    );
    assert!(Event::FrameDropped { reason: 0 }.is_coalesced());
    assert!(!Event::RpCostHighWater { us: 0 }.is_coalesced());
}

#[test]
fn never_coalesced_kind_is_counted_apart_from_coalesced_ones() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::WgCookieDropped, 1000, &mut out);
    run(&mut c, Event::CookieSecretUnavailable, 1, &mut out);
    assert_eq!(out.len(), 1000usize.div_ceil(64) + 1);
    let last = out.last().unwrap();
    assert_eq!((last.code, last.a), (Event::CookieSecretUnavailable.code(), 1));
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
    assert_eq!(decode(0x0049), Decoded::Fixed(Event::RpPqRecordStuck));
    assert_eq!(decode(0x004a), Decoded::Fixed(Event::RpPqSyncDead));
    assert_eq!(decode(0x0051), Decoded::Fixed(Event::RpCookieSuppressed));
    assert_eq!(decode(0x0052), Decoded::StackHighWater);
    assert_eq!(decode(0x0053), Decoded::Fixed(Event::Ready));
    assert_eq!(decode(0x0054), Decoded::Halted);
    assert_eq!(decode(0x0055), Decoded::KeyUnavailable);
    assert_eq!(decode(0x0056), Decoded::KeyStackHighWater);
    assert_eq!(decode(0x0057), Decoded::Unknown);
}

#[test]
fn ready_is_emitted_on_every_occurrence_and_decodes_as_itself() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::Ready, 2, &mut out);
    assert_eq!(out.iter().map(|r| (r.code, r.a)).collect::<Vec<_>>(), [(0x0053, 1), (0x0053, 2)]);
    assert_eq!(Event::Ready.name(), "Ready");
    assert_eq!(decode(Event::Ready.code()), Decoded::Fixed(Event::Ready));
}

#[test]
fn halted_carries_its_reason_not_a_count() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::Halted { reason: 3 }, 2, &mut out);
    assert_eq!(out, [Record { code: HALTED, _reserved: 0, a: 3, b: 0 }; 2]);
    assert_eq!(decode(HALTED), Decoded::Halted);
}

#[test]
fn key_unavailable_carries_the_boot_error_code_not_a_count() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::KeyUnavailable { code: 7 }, 2, &mut out);
    assert_eq!(out, [Record { code: KEY_UNAVAILABLE, _reserved: 0, a: 7, b: 0 }; 2]);
    assert_eq!(decode(KEY_UNAVAILABLE), Decoded::KeyUnavailable);
}

#[test]
fn key_stack_high_water_is_its_own_kind_apart_from_the_producers_mark() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::StackHighWater { bytes: 61_808 }, 1, &mut out);
    run(&mut c, Event::KeyStackHighWater { bytes: 100_096 }, 1, &mut out);
    let got: Vec<_> = out.iter().map(|r| (r.code, r.a)).collect();
    assert_eq!(got, [(STACK_HIGH_WATER, 61_808), (KEY_STACK_HIGH_WATER, 100_096)]);
    assert!(!Event::KeyStackHighWater { bytes: 0 }.is_coalesced());
    assert_eq!(decode(KEY_STACK_HIGH_WATER), Decoded::KeyStackHighWater);
}

#[test]
fn m5_codes_are_distinct_from_every_other_code() {
    let m5 = [HALTED, KEY_UNAVAILABLE, KEY_STACK_HIGH_WATER];
    let mut others: Vec<u16> = Event::FIXED.iter().map(|e| e.code()).collect();
    others.extend([COST_HIGH_WATER, STACK_HIGH_WATER]);
    for (i, c) in m5.iter().enumerate() {
        assert!(*c < FRAME_DROPPED_BASE);
        assert!(!others.contains(c));
        assert!(!m5[i + 1..].contains(c));
    }
}

#[test]
fn stack_high_water_carries_its_bytes_and_is_never_coalesced() {
    let ev = Event::StackHighWater { bytes: 61_808 };
    assert_eq!(ev.code(), STACK_HIGH_WATER);
    assert_eq!(ev.value(), Some(61_808));
    assert!(!ev.is_coalesced());
    assert_eq!(decode(ev.code()), Decoded::StackHighWater);
}

#[test]
fn unknown_codes_share_one_coalesced_counter() {
    let mut u = UnknownCodes::new();
    let due: Vec<u32> = (0..130).filter_map(|_| u.record()).collect();
    assert_eq!(due, [1, 65, 129]);
}

#[test]
fn cost_high_water_record_carries_the_exact_cost_not_a_count() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::RpCostHighWater { us: 123_457 }, 1, &mut out);
    run(&mut c, Event::RpCostHighWater { us: 200_001 }, 1, &mut out);
    assert_eq!(
        out,
        [
            Record { code: COST_HIGH_WATER, _reserved: 0, a: 123_457, b: 0 },
            Record { code: COST_HIGH_WATER, _reserved: 0, a: 200_001, b: 0 },
        ]
    );
}

#[test]
fn cost_high_water_is_never_coalesced() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::RpCostHighWater { us: 7 }, 65, &mut out);
    assert_eq!(out.len(), 65);
    assert!(out.iter().all(|r| r.a == 7));
}

#[test]
fn cost_high_water_code_is_distinct_and_decodes_as_its_own_kind() {
    assert!(Event::FIXED.iter().all(|e| e.code() != COST_HIGH_WATER));
    assert_eq!(Event::RpCostHighWater { us: 1 }.code(), COST_HIGH_WATER);
    assert_eq!(decode(COST_HIGH_WATER), Decoded::CostHighWater);
    assert_eq!(Event::RpCostHighWater { us: 1 }.name(), "RpCostHighWater");
}

#[test]
fn cost_high_water_does_not_share_a_counter_with_fixed_kinds() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::RpInitHello, 2, &mut out);
    run(&mut c, Event::RpCostHighWater { us: 9 }, 1, &mut out);
    run(&mut c, Event::FrameDropped { reason: 0x3f }, 1, &mut out);
    let got: Vec<_> = out.iter().map(|r| (r.code, r.a)).collect();
    assert_eq!(got, [(Event::RpInitHello.code(), 1), (COST_HIGH_WATER, 9), (FRAME_DROPPED_BASE | 0x3f, 1)]);
}

#[test]
fn stack_high_water_is_never_coalesced_and_keeps_its_own_slot() {
    let mut c = Coalescer::new();
    let mut out = Vec::new();
    run(&mut c, Event::StackHighWater { bytes: 61_696 }, 65, &mut out);
    assert_eq!(out.len(), 65);
    assert!(out.iter().all(|r| r.code == STACK_HIGH_WATER && r.a == 61_696));
    let mut out = Vec::new();
    run(&mut c, Event::RpCostHighWater { us: 9 }, 1, &mut out);
    run(&mut c, Event::StackHighWater { bytes: 4 }, 1, &mut out);
    run(&mut c, Event::RpInitHello, 1, &mut out);
    let got: Vec<_> = out.iter().map(|r| (r.code, r.a)).collect();
    assert_eq!(got, [(COST_HIGH_WATER, 9), (STACK_HIGH_WATER, 4), (Event::RpInitHello.code(), 1)]);
}

fn emitted(costs: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut hw = CostHighWater::new();
    costs.into_iter().filter_map(|us| hw.observe(us)).map(|e| e.value().unwrap()).collect()
}

#[test]
fn first_cost_always_emits() {
    assert_eq!(emitted([5_000]), [5_000]);
}

#[test]
fn monotone_costs_emit_at_most_log_one_and_an_eighth_of_the_range_plus_one() {
    let (min, max) = (1_000u32, 64_000u32);
    let got = emitted(min..=max);
    let bound = ((f64::from(max) / f64::from(min)).ln() / 1.125f64.ln()).ceil() as usize + 1;
    assert!(got.len() <= bound, "{} events > bound {bound}", got.len());
    // Each emission is at least 1/8 above the one before it.
    assert!(got.windows(2).all(|w| u64::from(w[1]) * 8 >= u64::from(w[0]) * 9));
    // The last emitted value is within 1/8 of the true maximum.
    let last = *got.last().unwrap();
    assert!(u64::from(max) * 8 < u64::from(last) * 9, "last {last} too far below {max}");
}

#[test]
fn a_rise_inside_one_power_of_two_bucket_still_emits() {
    // 1100 and 1240 both lie in [1024, 2048): a log2-bucket gate would
    // stay silent, the 1/8 rule must not.
    assert_eq!(emitted([1_100, 1_240]), [1_100, 1_240]);
}

#[test]
fn rise_of_exactly_one_eighth_emits_and_just_below_does_not() {
    assert_eq!(emitted([1_000, 1_124]), [1_000]);
    assert_eq!(emitted([1_000, 1_125]), [1_000, 1_125]);
}

#[test]
fn the_gate_compares_with_the_last_emitted_value_not_the_last_seen() {
    // 1100 and 1200 are each less than 1/8 above their predecessor, but
    // 1200 is at least 1/8 above the last emission (1000), so it fires.
    assert_eq!(emitted([1_000, 1_100, 1_200]), [1_000, 1_200]);
}

#[test]
fn lower_or_equal_costs_never_emit() {
    assert_eq!(emitted([1_000, 1_000, 999, 1]), [1_000]);
}

#[test]
fn a_run_of_zero_costs_emits_once() {
    assert_eq!(emitted([0, 0, 0]), [0]);
}

#[test]
fn a_lost_cost_record_is_offered_again_at_the_same_cost() {
    let mut h = CostHighWater::new();
    let mut offered = Vec::new();
    h.observe_with(1_000, |e| {
        offered.push(e);
        true
    });
    // 2 000 is due but the ring is full: the mark must not move.
    h.observe_with(2_000, |e| {
        offered.push(e);
        false
    });
    h.observe_with(2_000, |e| {
        offered.push(e);
        true
    });
    assert_eq!(
        offered,
        [Event::RpCostHighWater { us: 1_000 }, Event::RpCostHighWater { us: 2_000 }, Event::RpCostHighWater { us: 2_000 }]
    );
}

#[test]
fn a_delivered_cost_record_moves_the_mark() {
    let mut h = CostHighWater::new();
    h.observe_with(2_000, |_| true);
    let mut offered = 0;
    // Below 2 000 + 1/8: not due once 2 000 was delivered.
    h.observe_with(2_249, |_| {
        offered += 1;
        true
    });
    assert_eq!(offered, 0);
}

#[test]
fn record_delivered_reports_what_reached_the_ring() {
    let mut c = Coalescer::new();
    let ev = Event::RpCostHighWater { us: 5 };
    assert_eq!(c.record_delivered(ev, |_| true), (true, true));
    assert_eq!(c.record_delivered(ev, |_| false), (true, false), "a full ring is offered, not delivered");
    // A coalesced event between emissions is neither.
    let co = Event::RpPskExported;
    assert_eq!(c.record_delivered(co, |_| true), (true, true));
    let mut pushed = false;
    assert_eq!(
        c.record_delivered(co, |_| {
            pushed = true;
            true
        }),
        (false, false)
    );
    assert!(!pushed, "a coalesced-away event is not offered to the ring");
}
