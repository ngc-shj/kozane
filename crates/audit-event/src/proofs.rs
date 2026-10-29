//! Kani harnesses for the `policy` code ranges (M8 plan C9, F41, F45):
//! over every slot, reason and value, the encoding stays in its range and
//! the decoding names exactly what was encoded, or `Unknown` for an
//! out-of-range input; and the log never writes past its page.

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
