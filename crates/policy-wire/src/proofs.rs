//! Kani harnesses (M8 plan C1/C5). Run with `cargo kani -p policy-wire`,
//! one job at a time (the M8 deviation log: no two Kani jobs on one host).

use super::*;

// --- I1.1: the walk is total and in bounds, by its step functions ---------
//
// `walk_structure` is two loops (at most `MAX_PEERS` and `MAX_GROUPS`
// iterations) over `walk_peer` and `walk_group`, then a tail check on
// `slot.get(..)`. Each step is proved here on a small symbolic buffer from an
// arbitrary start: `Ok` means it moved forward and stayed inside the
// buffer. The loops compose them by induction; the crate's lints rule out
// any panic (no indexing, unwrap or unchecked arithmetic). Proving the
// whole walk at once timed out (deviation log, slice 1).

/// A small rp key length: the step skips `K` bytes between `wg_pub` and
/// `groups`, which this keeps inside the small buffer.
const PROOF_K: usize = 4;
/// One peer at `PROOF_K` with up to `MAX_ALLOWED` prefixes fits.
const PEER_BUF: usize = 32 + PROOF_K + 2 + MAX_ALLOWED * PREFIX_LEN + 2;
/// One group with up to three rules fits; the rule loop's other iterations
/// are the same body (unwind covers `MAX_RULES`).
const GROUP_BUF: usize = 1 + 3 * RULE_LEN + 1;

#[kani::proof]
#[kani::unwind(9)]
fn peer_step_moves_forward_inside_the_buffer() {
    let slot: [u8; PEER_BUF] = kani::any();
    let start: usize = kani::any();
    kani::assume(start <= PEER_BUF);
    let group_count: u8 = kani::any();
    let r = walk_peer::<PROOF_K>(&slot, start, group_count, None);
    kani::cover!(r.is_ok());
    if let Ok((next, wg)) = r {
        assert!(start < next && next <= PEER_BUF);
        assert!(wg.len() == 32);
    }
}

#[kani::proof]
#[kani::unwind(17)]
fn group_step_moves_forward_inside_the_buffer() {
    let slot: [u8; GROUP_BUF] = kani::any();
    let start: usize = kani::any();
    kani::assume(start <= GROUP_BUF);
    let r = walk_group(&slot, start);
    kani::cover!(r.is_ok());
    if let Ok(next) = r {
        assert!(start < next && next <= GROUP_BUF);
    }
}

// --- I5.3: `select` is correct over all small symbolic inputs -----------

fn any_slot_view() -> SlotView {
    let kind: u8 = kani::any();
    kani::assume(kind < 4);
    match kind {
        0 => SlotView::Empty,
        1 => SlotView::Malformed,
        2 => SlotView::BadSignature,
        _ => {
            let version: u32 = kani::any();
            let min_release: u32 = kani::any();
            let prev_sha256: [u8; 32] = kani::any();
            let body_sha256: [u8; 32] = kani::any();
            SlotView::Valid { version, min_release, prev_sha256, body_sha256 }
        }
    }
}

/// True if `view` would be `select`'s candidate for `current`/`release_seq`
/// (the reference the proof checks `select` against, kept independent of
/// `classify` by not sharing its code).
fn is_valid_candidate(current: u32, release_seq: u32, view: SlotView) -> bool {
    match view {
        SlotView::Valid { version, min_release, .. } => (version == current || Some(version) == current.checked_add(1)) && min_release <= release_seq,
        _ => false,
    }
}

fn view_version(view: SlotView) -> Option<u32> {
    match view {
        SlotView::Valid { version, .. } => Some(version),
        _ => None,
    }
}

/// `anchor` verifies `next`'s `prev` link: valid at exactly `current`, its
/// body what `next` names as its predecessor.
fn anchors(current: u32, anchor: SlotView, next: SlotView) -> bool {
    match (anchor, next) {
        (SlotView::Valid { version, body_sha256, .. }, SlotView::Valid { prev_sha256, .. }) => version == current && body_sha256 == prev_sha256,
        _ => false,
    }
}

/// I5.3 deny, with I5.1's version binding: a used slot is a candidate at
/// exactly `current`; an advanced one is a candidate at `current+1` whose
/// `prev` the other slot anchors; two candidates at one version with
/// different bodies are always `Equivocation`.
#[kani::proof]
#[kani::unwind(33)]
fn select_never_uses_or_advances_a_non_candidate_slot() {
    let current: u32 = kani::any();
    let release_seq: u32 = kani::any();
    let a = any_slot_view();
    let b = any_slot_view();
    let d = select(current, release_seq, a, b);
    match d {
        Decision::Use { slot: Slot::A } => {
            assert!(is_valid_candidate(current, release_seq, a) && view_version(a) == Some(current));
        }
        Decision::Use { slot: Slot::B } => {
            assert!(is_valid_candidate(current, release_seq, b) && view_version(b) == Some(current));
        }
        Decision::Advance { slot: Slot::A } => {
            assert!(is_valid_candidate(current, release_seq, a) && view_version(a) == current.checked_add(1));
            assert!(anchors(current, b, a));
        }
        Decision::Advance { slot: Slot::B } => {
            assert!(is_valid_candidate(current, release_seq, b) && view_version(b) == current.checked_add(1));
            assert!(anchors(current, a, b));
        }
        Decision::Refuse { .. } => {}
    }
    if let (SlotView::Valid { version: va, body_sha256: ba, .. }, SlotView::Valid { version: vb, body_sha256: bb, .. }) = (a, b)
        && is_valid_candidate(current, release_seq, a)
        && is_valid_candidate(current, release_seq, b)
        && va == vb
        && ba != bb
    {
        assert!(d == Decision::Refuse { reason: Reject::Equivocation });
    }
}

/// Reachability for the deny harness above: both a use and an advance occur.
#[kani::proof]
#[kani::unwind(33)]
fn select_reaches_use_and_advance() {
    let current: u32 = kani::any();
    let release_seq: u32 = kani::any();
    let d = select(current, release_seq, any_slot_view(), any_slot_view());
    kani::cover!(matches!(d, Decision::Use { .. }));
    kani::cover!(matches!(d, Decision::Advance { .. }));
    kani::cover!(matches!(d, Decision::Refuse { reason: Reject::Equivocation }));
    kani::cover!(matches!(d, Decision::Refuse { reason: Reject::PrevMismatch }));
}

/// I5.3 allow: if slot A is the unique `current`-version candidate (B is
/// not a candidate at all), `select` uses it.
#[kani::proof]
#[kani::unwind(33)]
fn select_uses_the_sole_current_candidate() {
    let current: u32 = kani::any();
    let release_seq: u32 = kani::any();
    let min_release: u32 = kani::any();
    kani::assume(min_release <= release_seq);
    let prev_sha256: [u8; 32] = kani::any();
    let body_sha256: [u8; 32] = kani::any();
    let a = SlotView::Valid { version: current, min_release, prev_sha256, body_sha256 };
    let b = any_slot_view();
    kani::assume(!is_valid_candidate(current, release_seq, b));
    assert!(select(current, release_seq, a, b) == Decision::Use { slot: Slot::A });
}

/// I5.3 allow: a `current+1` candidate whose `prev_sha256` matches the
/// other slot's verified body at exactly `current` advances, whatever the
/// anchor's own floor.
#[kani::proof]
#[kani::unwind(33)]
fn select_advances_past_a_matching_anchor_regardless_of_its_floor() {
    let current: u32 = kani::any();
    let next = match current.checked_add(1) {
        Some(n) => n,
        None => return,
    };
    let anchor_min_release: u32 = kani::any();
    let release_seq: u32 = kani::any();
    let next_min_release: u32 = kani::any();
    kani::assume(next_min_release <= release_seq);
    let anchor_body: [u8; 32] = kani::any();
    let a = SlotView::Valid { version: current, min_release: anchor_min_release, prev_sha256: [0; 32], body_sha256: anchor_body };
    let b = SlotView::Valid { version: next, min_release: next_min_release, prev_sha256: anchor_body, body_sha256: [1; 32] };
    assert!(select(current, release_seq, a, b) == Decision::Advance { slot: Slot::B });
}

// --- I5.1: the init step machine, nondeterministic replies --------------

fn any_state_reply() -> StateReply {
    if kani::any() {
        StateReply::Refused
    } else {
        StateReply::Ok { current: kani::any(), pcr9: kani::any() }
    }
}

fn any_advance_reply() -> AdvanceReply {
    if kani::any() { AdvanceReply::Refused } else { AdvanceReply::Ok(kani::any()) }
}

/// I5.1: `Verified{version = current+1}` only after an ADVANCE reply
/// equal to `current+1`; a refused STATE never yields `Verified`; a PCR 9
/// mismatch never yields `Verified`.
#[kani::proof]
#[kani::unwind(33)]
fn verified_next_version_needs_a_matching_advance_reply() {
    let expected_pcr9: [u8; 32] = kani::any();
    let release_seq: u32 = kani::any();
    let a = any_slot_view();
    let b = any_slot_view();
    let reply = any_state_reply();
    let state_refused = matches!(reply, StateReply::Refused);
    let pcr9_matches = matches!(reply, StateReply::Ok { pcr9, .. } if pcr9 == expected_pcr9);

    match after_state(reply, &expected_pcr9, release_seq, a, b) {
        Step::Done(Outcome::Verified { slot, version, .. }) => {
            assert!(!state_refused);
            assert!(pcr9_matches);
            // Without an ADVANCE, only a slot already at `current` is used.
            let current = match reply {
                StateReply::Ok { current, .. } => current,
                StateReply::Refused => unreachable!(),
            };
            let view = if slot == Slot::A { a } else { b };
            kani::cover!(true, "a slot used without an advance");
            assert!(version == current && view_version(view) == Some(current));
        }
        Step::Done(Outcome::Unavailable { reason: Reject::StateRefused }) => assert!(state_refused),
        Step::Done(Outcome::Unavailable { reason: Reject::MeasureMismatch }) => assert!(!state_refused && !pcr9_matches),
        Step::Done(Outcome::Unavailable { .. }) => assert!(!state_refused && pcr9_matches),
        Step::Advance(pending) => {
            assert!(!state_refused && pcr9_matches);
            let advance = any_advance_reply();
            match after_advance(pending, advance) {
                Outcome::Verified { version, .. } => {
                    kani::cover!(true);
                    // The reply itself, not the machine's own arithmetic:
                    // only a confirmed `current + 1` from the TPM verifies.
                    assert!(matches!(advance, AdvanceReply::Ok(v) if Some(v) == pending.current.checked_add(1)));
                    assert!(Some(version) == pending.current.checked_add(1))
                }
                Outcome::Unavailable { reason } => assert!(reason == Reject::AdvanceFailed),
            }
        }
    }
}

// --- the `policy` PD's audit helper (M8 slice 3) ---------------------------

/// `not_candidate` says "candidate" exactly when the independent reference
/// does, and never names `Equivocation`, `PrevMismatch` or a state reason
/// (it judges one slot alone), so a `PolicyRejected` line never contradicts
/// `select`.
#[kani::proof]
fn not_candidate_agrees_with_the_candidate_reference() {
    let current: u32 = kani::any();
    let release_seq: u32 = kani::any();
    let view = any_slot_view();
    let r = not_candidate(current, release_seq, view);
    assert!(r.is_none() == is_valid_candidate(current, release_seq, view));
    assert!(!matches!(
        r,
        Some(Reject::Equivocation | Reject::PrevMismatch | Reject::StateRefused | Reject::MeasureMismatch | Reject::AdvanceFailed | Reject::WrongFleet)
    ));
    kani::cover!(r.is_none());
}
