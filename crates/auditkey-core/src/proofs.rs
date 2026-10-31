#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Kani harnesses (M8 plan C10, D7; S20, S25): the request parser is total
//! and exact, and the seq rule signs no two requests of one boot with
//! non-increasing seqs and spends its exemption at most once. Run with
//! `cargo kani -p auditkey-core`.

use super::*;

/// The parser over any word count up to two past a request: Ok exactly for
/// `SIGN_REQ_WORDS` words, and then each field is its word (the chain the
/// four middle words' little-endian bytes); `encode` inverts it.
#[kani::proof]
#[kani::unwind(50)]
fn the_parser_is_total_and_exact() {
    let words: [u64; SIGN_REQ_WORDS + 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= words.len());
    let input = words.get(..len).unwrap_or(&[]);
    let r = parse(input);
    assert!(r.is_some() == (len == SIGN_REQ_WORDS));
    if let Some(req) = r {
        assert!(req.seq == words[0] && req.lost == words[5]);
        let i: usize = kani::any();
        kani::assume(i < CHAIN_LEN);
        assert!(req.chain[i] == words[1 + i / 8].to_le_bytes()[i % 8]);
        assert!(encode(&req) == [words[0], words[1], words[2], words[3], words[4], words[5]]);
    }
    kani::cover!(r.is_some(), "a request parses");
    kani::cover!(r.is_none() && len > 0, "a wrong length is refused");
}

/// One step from any state: an admitted seq is above the last, and is
/// either due (`CHECKPOINT_EVERY` past it, without overflow) with the
/// exemption unchanged, or spends the exemption, which was unspent. A
/// refusal is `Overflow` exactly when the due point does not fit.
#[kani::proof]
fn one_step_of_the_seq_rule() {
    let rule = SeqRule { last: kani::any(), exempt_spent: kani::any() };
    let seq: u64 = kani::any();
    let due = rule.last.checked_add(CHECKPOINT_EVERY);
    match rule.next(seq) {
        Ok(next) => {
            assert!(seq > rule.last && next.last == seq);
            let was_due = due.is_some_and(|d| seq >= d);
            if was_due {
                assert!(next.exempt_spent == rule.exempt_spent);
            } else {
                assert!(!rule.exempt_spent && next.exempt_spent);
            }
            kani::cover!(was_due, "a due checkpoint");
            kani::cover!(!was_due, "the ready exemption");
        }
        Err(e) => {
            assert!(e == Refusal::Overflow || due.is_some());
            if e == Refusal::Overflow {
                assert!(due.is_none());
            }
            kani::cover!(e == Refusal::TooSoon, "too soon");
            kani::cover!(e == Refusal::Overflow, "an overflowing due point");
        }
    }
}

/// Over any three requests from a boot's start (S25): the seqs signed
/// strictly increase, so no two signatures share a seq or go backwards,
/// and at most one of them was not due.
#[kani::proof]
#[kani::unwind(4)]
fn signatures_strictly_increase_with_at_most_one_exemption() {
    let seqs: [u64; 3] = kani::any();
    let mut rule = SeqRule::new();
    let mut signed = 0u8;
    let mut exempt = 0u8;
    let mut last_signed: Option<u64> = None;
    for seq in seqs {
        let due = rule.last.checked_add(CHECKPOINT_EVERY).is_some_and(|d| seq >= d);
        if let Ok(next) = rule.next(seq) {
            if let Some(prev) = last_signed {
                assert!(seq > prev);
            }
            if !due {
                exempt = exempt.saturating_add(1);
            }
            signed = signed.saturating_add(1);
            last_signed = Some(seq);
            rule = next;
        }
    }
    assert!(exempt <= 1);
    assert!(last_signed.is_none_or(|s| s > 0), "seq 0 is never signed");
    kani::cover!(signed == 3, "three signatures");
    kani::cover!(signed == 3 && exempt == 1, "three signatures, one of them the ready one");
}
