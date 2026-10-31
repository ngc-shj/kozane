#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Kani harnesses (M8 plan C10, F32, F42, D-18): the ready input is the
//! auditkey channel alone, no call precedes it, and each poll moves the due
//! point past its own seq, with the ready checkpoint taken once. Run with
//! `cargo kani -p audit-core`. The chain (libcrux's SHA-256) is out of
//! reach; its unit tests carry known answers.

use super::*;

/// Any notified set, as a badge: `ready_input` is true exactly when the
/// auditkey channel's bit is set.
#[kani::proof]
#[kani::unwind(65)]
fn ready_input_is_the_auditkey_bit_alone() {
    let badge: u64 = kani::any();
    let channels = (0..64usize).filter(|i| badge & (1u64 << i) != 0);
    assert!(ready_input(channels) == (badge & (1u64 << CH_AUDITKEY) != 0));
    kani::cover!(badge != 0 && badge & (1u64 << CH_AUDITKEY) == 0, "other channels only");
}

fn any_state() -> Checkpoints {
    Checkpoints {
        notified: kani::any(),
        ready: kani::any(),
        all: kani::any(),
        ready_done: kani::any(),
        due: kani::any(),
        in_flight: kani::any(),
    }
}

/// One poll from any state: a `Call` only once notified and not in flight;
/// anything but `Idle` was due (the ready checkpoint, once, or the due
/// point reached) and moved the due point to `next_seq + CHECKPOINT_EVERY`
/// (saturating), its call carrying exactly that seq, chain and lost.
#[kani::proof]
fn one_poll_of_the_schedule() {
    let before = any_state();
    let mut s = before;
    let next_seq: u64 = kani::any();
    let chain: [u8; CHAIN_LEN] = kani::any();
    let lost: u64 = kani::any();
    let action = s.poll(next_seq, chain, lost);
    let ready_due = !before.ready_done && before.notified && before.ready == before.all && next_seq > 0;
    match action {
        Action::Idle => {
            assert!(before.in_flight || (!ready_due && next_seq < before.due));
            assert!(s == before);
        }
        Action::Call(words) => {
            assert!(before.notified && !before.in_flight && s.in_flight);
            assert!(ready_due || next_seq >= before.due);
            assert!(auditkey_core::parse(&words) == Some(Request { seq: next_seq, chain, lost }));
        }
        Action::Unsigned(reason) => {
            assert!(!before.notified && reason == REASON_PENDING && !s.in_flight);
            assert!(next_seq >= before.due);
        }
    }
    if action != Action::Idle {
        assert!(s.due == next_seq.saturating_add(CHECKPOINT_EVERY));
        assert!(s.ready_done == (before.ready_done || ready_due));
        assert!(s.notified == before.notified && s.ready == before.ready && s.all == before.all);
    }
    kani::cover!(matches!(action, Action::Call(_)) && next_seq < before.due, "the ready checkpoint");
    kani::cover!(matches!(action, Action::Unsigned(_)), "a pending checkpoint");
}

/// From a boot's start, over any three polls with no ready input: never a
/// `Call` (F32: no PPC before the notification).
#[kani::proof]
#[kani::unwind(4)]
fn no_call_without_the_ready_input() {
    let mut s = Checkpoints::new(kani::any());
    let seqs: [u64; 3] = kani::any();
    let sources: [usize; 3] = kani::any();
    for (seq, src) in seqs.into_iter().zip(sources) {
        s.source_ready(src);
        assert!(!matches!(s.poll(seq, [0; CHAIN_LEN], 0), Action::Call(_)));
    }
}

/// A reply always ends the call in flight, and only `OK` with a full reply
/// can be a signature; `REFUSED` and an Unavailable label are their own
/// reasons.
#[kani::proof]
#[kani::unwind(20)]
fn a_reply_ends_the_call() {
    let mut s = any_state();
    let label: u64 = kani::any();
    let words: [u64; SIGN_REPLY_WORDS] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= words.len());
    let out = s.reply(label, &words[..len]);
    assert!(!s.in_flight);
    if let Outcome::Signed(_) = out {
        assert!(label == OK && len == SIGN_REPLY_WORDS);
    }
    if label == REFUSED {
        assert!(out == Outcome::Unsigned(REASON_REFUSED));
    }
}
