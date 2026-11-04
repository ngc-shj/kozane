#![allow(clippy::arithmetic_side_effects, clippy::unwrap_used, clippy::panic)]

//! Kani harnesses for the initiator's state core (M9 plan C7, P13): one
//! step lemma per transition, each from an arbitrary state, as M8's D-17
//! states invariants by induction rather than over sequences. Run with
//! `cargo kani -p rosenpass-core`. No cryptography is in reach: the core
//! has none, and `initiator`'s crypto is covered by the unit tests and the
//! upstream vectors.
//!
//! Each lemma pins down, for its transition:
//! - the graph: the phases it may leave from and the one it reaches;
//! - I7.3: exactly which inputs are refused, and that a refusal returns no
//!   state (the receiver is borrowed, so the caller's state is the one it
//!   had; `initiator` commits only on `Ok`);
//! - the deadlines: a registered retry lies in `(now, now + END)`, and a
//!   retransmission's is later than the one it answered;
//! - the counter: it saturates and never wraps.

use super::*;

impl kani::Arbitrary for Phase {
    fn any() -> Self {
        match kani::any::<u8>() % 4 {
            0 => Phase::Idle,
            1 => Phase::SentInitHello,
            2 => Phase::SentInitConf,
            _ => Phase::Established,
        }
    }
}

fn any_state() -> InitiatorState {
    InitiatorState {
        phase: kani::any(),
        sidi: kani::any(),
        created_at: kani::any(),
        retry_at: kani::any(),
        tx_count: kani::any(),
        jitter: kani::any(),
        established_at: kani::any(),
    }
}

const fn expires(s: &InitiatorState) -> u64 {
    s.created_at.saturating_add(REJECT_AFTER_TIME_NS)
}

/// A retry registered at `now` for a message's first send.
fn first_retry_bounded(next: &InitiatorState, now: u64) {
    assert!(next.tx_count == 1 && next.retry_at > now);
    let delay = next.retry_at - now;
    assert!(delay >= RETRANSMIT_DELAY_BEGIN_NS / 2 && delay < RETRANSMIT_DELAY_BEGIN_NS);
}

/// The delay for any count and jitter: within [BEGIN/2, END), and never
/// shorter for a later retransmission.
#[kani::proof]
#[kani::unwind(34)]
fn retransmit_delay_is_bounded_and_monotone() {
    let n: u32 = kani::any();
    let j: u8 = kani::any();
    let d = retransmit_delay(n, j).unwrap();
    assert!(d >= RETRANSMIT_DELAY_BEGIN_NS / 2 && d < RETRANSMIT_DELAY_END_NS);
    if let Some(m) = n.checked_add(1) {
        assert!(retransmit_delay(m, j).unwrap() >= d);
    }
    kani::cover!(n == u32::MAX);
    kani::cover!(d == RETRANSMIT_DELAY_END_NS * (256 + u64::from(j)) / 512, "capped");
}

/// `start` from any phase reaches SentInitHello for the new sidi, with a
/// fresh counter and lifetime; it is refused only when the retry would not
/// fit in a u64.
#[kani::proof]
fn start_from_any_state() {
    let s = any_state();
    let (now, sidi, jitter) = (kani::any(), kani::any(), kani::any());
    match s.start(now, sidi, jitter) {
        Ok(next) => {
            assert!(next.phase == Phase::SentInitHello && next.sidi == sidi && next.created_at == now);
            assert!(next.jitter == jitter && next.established_at == 0);
            first_retry_bounded(&next, now);
            assert!(next.deadline() == Some(next.retry_at));
        }
        Err(e) => {
            assert!(e == StateError::Overflow);
            assert!(now > u64::MAX - RETRANSMIT_DELAY_BEGIN_NS);
        }
    }
    kani::cover!(s.phase == Phase::SentInitConf, "replaces a handshake in flight");
}

/// `resp_hello` moves SentInitHello to SentInitConf for our live session
/// alone, keeping its sidi and lifetime; every other input is refused.
#[kani::proof]
// The state's `==` is a memcmp over `jitter` (16 bytes): the bound covers
// it plus the loop exit (M9 deviation D-19).
#[kani::unwind(18)]
fn resp_hello_from_any_state() {
    let s = any_state();
    let (now, sid, jitter): (u64, _, _) = (kani::any(), kani::any(), kani::any());
    let r = s.resp_hello(now, sid, jitter);
    match r {
        Ok(next) => {
            assert!(s.phase == Phase::SentInitHello && next.phase == Phase::SentInitConf);
            assert!(sid == s.sidi && next.sidi == s.sidi && next.created_at == s.created_at);
            assert!(now < expires(&s) && next.jitter == jitter);
            first_retry_bounded(&next, now);
            assert!(next.deadline().is_some_and(|d| d > now));
        }
        Err(StateError::UnexpectedMessage) => assert!(s.phase != Phase::SentInitHello),
        Err(StateError::UnknownSession) => assert!(s.phase == Phase::SentInitHello && sid != s.sidi),
        Err(StateError::Expired) => assert!(s.phase == Phase::SentInitHello && sid == s.sidi && now >= expires(&s)),
        Err(StateError::Overflow) => assert!(now > u64::MAX - RETRANSMIT_DELAY_BEGIN_NS),
    }
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(StateError::UnexpectedMessage));
    kani::cover!(r == Err(StateError::UnknownSession));
    kani::cover!(r == Err(StateError::Expired));
}

/// `empty_data` moves SentInitConf to Established for our live session
/// alone: retransmission stops and the rekey clock starts at `now`.
#[kani::proof]
// The state's `==` is a memcmp over `jitter` (16 bytes): the bound covers
// it plus the loop exit (M9 deviation D-19).
#[kani::unwind(18)]
fn empty_data_from_any_state() {
    let s = any_state();
    let (now, sid): (u64, _) = (kani::any(), kani::any());
    let r = s.empty_data(now, sid);
    match r {
        Ok(next) => {
            assert!(s.phase == Phase::SentInitConf && next.phase == Phase::Established);
            assert!(sid == s.sidi && next.sidi == s.sidi && now < expires(&s));
            assert!(next.deadline().is_none() && next.tx_count == 0);
            assert!(next.rekey_at() == Some(now.saturating_add(REKEY_AFTER_TIME_INITIATOR_NS)));
        }
        Err(StateError::UnexpectedMessage) => assert!(s.phase != Phase::SentInitConf),
        Err(StateError::UnknownSession) => assert!(s.phase == Phase::SentInitConf && sid != s.sidi),
        Err(StateError::Expired) => assert!(s.phase == Phase::SentInitConf && sid == s.sidi && now >= expires(&s)),
        Err(StateError::Overflow) => panic!("empty_data registers no retry"),
    }
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(StateError::UnexpectedMessage));
    kani::cover!(r == Err(StateError::UnknownSession));
    kani::cover!(r == Err(StateError::Expired));
}

/// `cookie_reply` keeps the phase and everything but the retry, which is
/// due at once, and the counter, which saturates.
#[kani::proof]
// The state's `==` is a memcmp over `jitter` (16 bytes): the bound covers
// it plus the loop exit (M9 deviation D-19).
#[kani::unwind(18)]
fn cookie_reply_from_any_state() {
    let s = any_state();
    let (now, sid): (u64, _) = (kani::any(), kani::any());
    let r = s.cookie_reply(now, sid);
    let in_flight = matches!(s.phase, Phase::SentInitHello | Phase::SentInitConf);
    match r {
        Ok(next) => {
            assert!(in_flight && sid == s.sidi && now < expires(&s));
            assert!(next.retry_at == now && next.tx_count == s.tx_count.saturating_add(1));
            assert!(InitiatorState { retry_at: s.retry_at, tx_count: s.tx_count, ..next } == s);
        }
        Err(StateError::UnexpectedMessage) => assert!(!in_flight),
        Err(StateError::UnknownSession) => assert!(in_flight && sid != s.sidi),
        Err(StateError::Expired) => assert!(in_flight && sid == s.sidi && now >= expires(&s)),
        Err(StateError::Overflow) => panic!("cookie_reply registers no delay"),
    }
    kani::cover!(r.is_ok() && s.tx_count == u32::MAX, "saturates");
    kani::cover!(r == Err(StateError::UnexpectedMessage));
    kani::cover!(r == Err(StateError::UnknownSession));
    kani::cover!(r == Err(StateError::Expired));
}

/// `tick`: outside a handshake nothing changes; a dead handshake returns to
/// Idle; before the retry nothing changes; at or after it the message is
/// resent with a later retry and a saturating count, in the same phase.
#[kani::proof]
#[kani::unwind(34)]
fn tick_from_any_state() {
    let s = any_state();
    let now: u64 = kani::any();
    let in_flight = matches!(s.phase, Phase::SentInitHello | Phase::SentInitConf);
    let r = s.tick(now);
    match r {
        Ok((next, Tick::Nothing)) => {
            assert!(next == s);
            assert!(!in_flight || (now < expires(&s) && now < s.retry_at));
        }
        Ok((next, Tick::Expired)) => {
            assert!(in_flight && now >= expires(&s));
            assert!(next == InitiatorState::new() && next.deadline().is_none());
        }
        Ok((next, Tick::Retransmit)) => {
            assert!(in_flight && now < expires(&s) && now >= s.retry_at);
            assert!(InitiatorState { retry_at: s.retry_at, tx_count: s.tx_count, ..next } == s);
            assert!(next.tx_count == s.tx_count.saturating_add(1));
            assert!(next.retry_at > now && next.retry_at > s.retry_at);
            assert!(next.retry_at - now < RETRANSMIT_DELAY_END_NS);
        }
        Err(e) => {
            assert!(e == StateError::Overflow && in_flight && now >= s.retry_at);
            assert!(now > u64::MAX - RETRANSMIT_DELAY_END_NS);
        }
    }
    kani::cover!(matches!(r, Ok((_, Tick::Retransmit))) && s.tx_count == u32::MAX, "saturates");
    kani::cover!(matches!(r, Ok((_, Tick::Expired))));
    kani::cover!(matches!(r, Ok((_, Tick::Nothing))) && in_flight);
}
