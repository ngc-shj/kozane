//! Kani harnesses for the `policy`, `InnerDenied` and per-peer code ranges
//! (M8 plan C9, C12, F41, F43, F45):
//! over every slot, reason and value, the encoding stays in its range and
//! the decoding names exactly what was encoded, or `Unknown` for an
//! out-of-range input; no code decodes as the heartbeat (M9 plan C3); and
//! the log never writes past its page.

use super::*;

/// I9.1: `PolicyRejected` decodes as its own slot and reason when both are
/// in range, and as `Unknown` otherwise; its counter slot is in bounds.
#[kani::proof]
fn policy_rejected_encodes_and_decodes_exactly() {
    let (slot, reason, version): (u16, u16, u32) = (kani::any(), kani::any(), kani::any());
    let ev = Event::PolicyRejected { slot, reason, version };
    let code = ev.code();
    assert!((POLICY_REJECTED_BASE..=POLICY_REJECTED_UNKNOWN).contains(&code));
    if slot < POLICY_SLOTS && reason < POLICY_REASONS {
        assert!(decode(code) == Decoded::PolicyRejected { slot, reason });
    } else {
        assert!(decode(code) == Decoded::Unknown);
    }
    assert!(ev.slot() < SLOTS);
    assert!(ev.value() == Some(version));
    kani::cover!(slot < POLICY_SLOTS && reason < POLICY_REASONS);
}

/// I9.2: the same for `PolicyUnavailable`, `PolicyAccepted` and
/// `ReleaseSeq`.
#[kani::proof]
fn policy_unavailable_accepted_and_release_seq_encode_and_decode_exactly() {
    let (small, value): (u16, u32) = (kani::any(), kani::any());
    let unavailable = Event::PolicyUnavailable { reason: small, current: value };
    let code = unavailable.code();
    assert!((POLICY_UNAVAILABLE_BASE..=POLICY_UNAVAILABLE_BASE + POLICY_REASONS).contains(&code));
    if small < POLICY_REASONS {
        assert!(decode(code) == Decoded::PolicyUnavailable(small));
    } else {
        assert!(decode(code) == Decoded::Unknown);
    }
    let accepted = Event::PolicyAccepted { slot: small, version: value };
    let code = accepted.code();
    assert!((POLICY_ACCEPTED_BASE..=POLICY_ACCEPTED_BASE + POLICY_SLOTS).contains(&code));
    if small < POLICY_SLOTS {
        assert!(decode(code) == Decoded::PolicyAccepted(small));
    } else {
        assert!(decode(code) == Decoded::Unknown);
    }
    let seq = Event::ReleaseSeq { seq: value };
    assert!(decode(seq.code()) == Decoded::ReleaseSeq);
    for ev in [unavailable, accepted, seq] {
        assert!(ev.slot() < SLOTS);
        assert!(ev.value() == Some(value));
        assert!(!ev.is_coalesced());
    }
}

/// I9.3: no code outside the policy ranges decodes as a policy kind, so a
/// producer cannot have another kind's code read as a policy line.
#[kani::proof]
fn only_policy_codes_decode_as_policy_kinds() {
    let code: u16 = kani::any();
    let policy = matches!(
        decode(code),
        Decoded::PolicyAccepted(_) | Decoded::PolicyUnavailable(_) | Decoded::PolicyRejected { .. } | Decoded::ReleaseSeq
    );
    if policy {
        assert!((POLICY_ACCEPTED_BASE..POLICY_REJECTED_UNKNOWN).contains(&code));
    }
}

/// I9.5 (M8 plan C9, F43, F45): `InnerDenied` decodes as its own peer and
/// reason when both are in range, and as `Unknown` otherwise (the block's
/// reserved last code, or `INNER_DENIED_UNKNOWN` for a peer out of range);
/// no other code decodes as it; its counter slot is in bounds.
#[kani::proof]
fn inner_denied_encodes_and_decodes_exactly() {
    let (peer, reason): (u16, u16) = (kani::any(), kani::any());
    let ev = Event::InnerDenied { peer, reason };
    let code = ev.code();
    assert!((INNER_DENIED_BASE..=INNER_DENIED_UNKNOWN).contains(&code));
    if peer < INNER_PEERS && usize::from(reason) < INNER_REASON_NAMES.len() {
        assert!(decode(code) == Decoded::InnerDenied { peer, reason });
    } else {
        assert!(decode(code) == Decoded::Unknown);
    }
    if peer >= INNER_PEERS {
        assert!(code == INNER_DENIED_UNKNOWN);
    }
    assert!(ev.slot() < SLOTS);
    assert!(ev.is_coalesced() && ev.value().is_none());
    let other: u16 = kani::any();
    if let Decoded::InnerDenied { peer, reason } = decode(other) {
        assert!(Event::InnerDenied { peer, reason }.code() == other);
    }
    kani::cover!(peer == INNER_PEERS - 1 && usize::from(reason) == INNER_REASON_NAMES.len() - 1);
    kani::cover!(peer < INNER_PEERS && usize::from(reason) == INNER_REASON_NAMES.len());
}

/// I9.6 (M8 plan C12, F45): each per-peer kind decodes as its own kind and
/// peer when the peer is in range and as `Unknown` (its range's unknown)
/// otherwise; no other code decodes as one; its counter slot is in bounds
/// and it carries its value uncoalesced.
#[kani::proof]
fn peer_kinds_encode_and_decode_exactly() {
    let (peer, value): (u16, u32) = (kani::any(), kani::any());
    let port = value as u16;
    let kinds = [
        (Event::PeerHandshake { peer, index: value }, Decoded::PeerHandshake(peer), PEER_HANDSHAKE_BASE, value),
        (Event::PeerEndpointIp { peer, ip: value }, Decoded::PeerEndpointIp(peer), PEER_ENDPOINT_IP_BASE, value),
        (Event::PeerEndpointPort { peer, port }, Decoded::PeerEndpointPort(peer), PEER_ENDPOINT_PORT_BASE, u32::from(port)),
    ];
    for (ev, decoded, base, a) in kinds {
        let code = ev.code();
        assert!((base..=base + PEERS).contains(&code));
        if peer < PEERS {
            assert!(decode(code) == decoded);
        } else {
            assert!(code == base + PEERS);
            assert!(decode(code) == Decoded::Unknown);
        }
        assert!(ev.slot() < SLOTS);
        assert!(!ev.is_coalesced() && ev.value() == Some(a));
    }
    let other: u16 = kani::any();
    match decode(other) {
        Decoded::PeerHandshake(p) => assert!(Event::PeerHandshake { peer: p, index: 0 }.code() == other),
        Decoded::PeerEndpointIp(p) => assert!(Event::PeerEndpointIp { peer: p, ip: 0 }.code() == other),
        Decoded::PeerEndpointPort(p) => assert!(Event::PeerEndpointPort { peer: p, port: 0 }.code() == other),
        _ => {}
    }
    kani::cover!(peer == PEERS - 1);
    kani::cover!(peer == PEERS);
}

/// M9 plan C3: no code a ring can carry decodes as an event named
/// `HEARTBEAT`, the name of `audit`'s own liveness line. The bound covers
/// both loops: `decode`'s search of `Event::FIXED` (64 entries) and the
/// memcmp over a name (26 bytes at most), plus the loop exit.
#[kani::proof]
#[kani::unwind(66)]
fn no_code_decodes_as_the_heartbeat() {
    let code: u16 = kani::any();
    if let Decoded::Fixed(ev) = decode(code) {
        assert!(ev.name().as_bytes() != HEARTBEAT.as_bytes());
    }
    kani::cover!(matches!(decode(code), Decoded::Fixed(_)));
}

/// I9.4: the log writer writes only inside its page, and the reader's
/// range never leaves the slots, whatever the page's count says.
#[kani::proof]
#[kani::unwind(10)]
fn the_log_stays_inside_its_page() {
    let mut w = log::Writer::new();
    let pushes: usize = kani::any();
    kani::assume(pushes <= log::SLOTS + 1);
    for _ in 0..pushes {
        let r = Record { code: kani::any(), _reserved: kani::any(), a: kani::any(), b: kani::any() };
        let _ = w.push(r, |at, _| assert!(at < log::WORDS));
    }
    let range = log::pending(kani::any(), kani::any());
    assert!(range.start <= range.end && range.end <= log::SLOTS);
}
