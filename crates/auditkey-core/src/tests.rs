#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;

const SEED: [u8; 32] = [0x5A; 32];

fn region() -> [u8; secret_blob::audit::REGION_SIZE] {
    let mut r = [0u8; secret_blob::audit::REGION_SIZE];
    secret_blob::audit::write(&mut r, &SEED).unwrap();
    r
}

fn identity() -> Identity {
    Identity { srk_name: [0x0B; SRK_NAME_LEN], boot_id: [0xB0; BOOT_ID_LEN], reset: 7, restart: 2 }
}

fn request(seq: u64) -> Request {
    Request { seq, chain: core::array::from_fn(|i| i as u8), lost: 3 }
}

/// Calls `SIGN` for `seq` with the real signer; (label, reply bytes).
fn sign(o: &mut Oracle<'_>, seq: u64) -> (u64, Vec<u8>) {
    let mut reply = [0xEEu64; layout::tpm::MSG_WORDS];
    let (label, n) = o.handle(Some(Caller::Audit), SIGN, &encode(&request(seq)), &mut reply);
    let mut bytes = [0u8; layout::tpm::MSG_BYTES];
    layout::tpm::unpack(&reply[..n], n * 8, &mut bytes).unwrap();
    if label == OK {
        assert!(reply[n..].iter().all(|w| *w == 0xEE), "words past the reply were written");
    } else {
        assert!(n == 0 && reply.iter().all(|w| *w == 0), "a refusal left data");
    }
    (label, bytes[..n * 8].to_vec())
}

#[test]
fn a_request_round_trips_through_its_words() {
    let r = request(0x0102_0304_0506_0708);
    let words = encode(&r);
    assert_eq!(words[0], r.seq);
    assert_eq!(words[1].to_le_bytes(), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(words[5], r.lost);
    assert_eq!(parse(&words), Some(r));
}

#[test]
fn a_request_of_any_other_length_is_refused() {
    let words = encode(&request(64));
    for n in 0..=8 {
        let mut v = words.to_vec();
        v.resize(n, 0);
        assert_eq!(parse(&v).is_some(), n == SIGN_REQ_WORDS, "{n} words");
    }
}

#[test]
fn the_message_is_the_documented_fixed_width_tuple() {
    let m = message(&identity(), &request(0x1122));
    assert_eq!(m.len(), 133);
    assert_eq!(&m[..27], b"kozane-audit-checkpoint-v1\0");
    assert_eq!(&m[27..61], &[0x0B; 34]);
    assert_eq!(&m[61..77], &[0xB0; 16]);
    assert_eq!(&m[77..81], &7u32.to_be_bytes());
    assert_eq!(&m[81..85], &2u32.to_be_bytes());
    assert_eq!(&m[85..93], &0x1122u64.to_be_bytes());
    assert_eq!(&m[93..125], &request(0).chain);
    assert_eq!(&m[125..133], &3u64.to_be_bytes());
}

#[test]
fn every_field_changes_the_message() {
    let base = message(&identity(), &request(64));
    let mut id = identity();
    id.srk_name[33] ^= 1;
    assert_ne!(message(&id, &request(64)), base, "srk_name");
    let mut id = identity();
    id.boot_id[0] ^= 1;
    assert_ne!(message(&id, &request(64)), base, "boot_id");
    let mut id = identity();
    id.reset += 1;
    assert_ne!(message(&id, &request(64)), base, "reset");
    let mut id = identity();
    id.restart += 1;
    assert_ne!(message(&id, &request(64)), base, "restart");
    assert_ne!(message(&identity(), &request(65)), base, "seq");
    let mut r = request(64);
    r.chain[31] ^= 1;
    assert_ne!(message(&identity(), &r), base, "chain");
    let mut r = request(64);
    r.lost += 1;
    assert_ne!(message(&identity(), &r), base, "lost");
}

#[test]
fn a_reply_round_trips_and_other_lengths_are_refused() {
    let r = Reply { signature: [0x51; 64], identity: identity() };
    let b = encode_reply(&r);
    assert_eq!(b.len(), layout::auditkey::SIGN_REPLY_LEN);
    assert_eq!(&b[80..84], &7u32.to_le_bytes());
    assert_eq!(decode_reply(&b), Some(r));
    assert_eq!(decode_reply(&b[..b.len() - 1]), None);
    let mut long = b.to_vec();
    long.push(0);
    assert_eq!(decode_reply(&long), None);
}

#[test]
fn a_signed_checkpoint_verifies_under_the_seed_s_public_key() {
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    let (label, bytes) = sign(&mut o, CHECKPOINT_EVERY);
    assert_eq!(label, OK);
    let reply = decode_reply(&bytes[..layout::auditkey::SIGN_REPLY_LEN]).unwrap();
    assert_eq!(reply.identity, identity());
    let msg = message(&identity(), &request(CHECKPOINT_EVERY));
    assert_eq!(libcrux_ed25519::verify(&msg, &public_key(&SEED), &reply.signature), Ok(()));
    // Another seq's message does not verify under that signature.
    let other = message(&identity(), &request(CHECKPOINT_EVERY + 1));
    assert!(libcrux_ed25519::verify(&other, &public_key(&SEED), &reply.signature).is_err());
}

#[test]
fn the_seq_rule_spaces_signatures_by_checkpoint_every() {
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    assert_eq!(sign(&mut o, CHECKPOINT_EVERY).0, OK);
    assert_eq!(sign(&mut o, 2 * CHECKPOINT_EVERY).0, OK);
    // Equal and lower seqs, then one short of due: the exemption covers
    // only a larger seq, so these three are refused whatever it holds.
    assert_eq!(sign(&mut o, 2 * CHECKPOINT_EVERY).0, REFUSED, "the same seq twice");
    assert_eq!(sign(&mut o, CHECKPOINT_EVERY).0, REFUSED, "a lower seq");
    assert_eq!(o.rule().last(), 2 * CHECKPOINT_EVERY);
    assert!(!o.rule().exempt_spent());
}

#[test]
fn exactly_one_ready_checkpoint_is_exempt_and_it_still_needs_a_larger_seq() {
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    // The ready checkpoint early in the boot: not yet due, larger than 0.
    assert_eq!(sign(&mut o, 40).0, OK);
    assert!(o.rule().exempt_spent());
    assert_eq!(sign(&mut o, 41).0, REFUSED, "a second exemption");
    assert_eq!(sign(&mut o, 40 + CHECKPOINT_EVERY - 1).0, REFUSED, "one short of due");
    assert_eq!(sign(&mut o, 40 + CHECKPOINT_EVERY).0, OK, "due again from the ready one");
    // From a fresh boot, seq 0 (the boot's first line) is never signed.
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    assert_eq!(sign(&mut o, 0).0, REFUSED);
    assert!(!o.rule().exempt_spent(), "a refusal spends nothing");
}

#[test]
fn a_due_seq_that_overflows_is_refused_once_the_exemption_is_spent() {
    let rule = SeqRule { last: u64::MAX - 1, exempt_spent: false };
    assert_eq!(rule.next(u64::MAX), Ok(SeqRule { last: u64::MAX, exempt_spent: true }));
    let spent = SeqRule { last: u64::MAX - 1, exempt_spent: true };
    assert_eq!(spent.next(u64::MAX), Err(Refusal::Overflow));
    let top = SeqRule { last: u64::MAX, exempt_spent: false };
    assert_eq!(top.next(u64::MAX), Err(Refusal::Overflow), "nothing is above u64::MAX");
    let edge = SeqRule { last: u64::MAX - CHECKPOINT_EVERY, exempt_spent: true };
    assert_eq!(edge.next(u64::MAX), Ok(SeqRule { last: u64::MAX, exempt_spent: true }), "exactly due at the top");
}

#[test]
fn a_refused_or_failed_sign_leaves_the_rule_and_zeroes_the_reply() {
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    let mut reply = [0xEEu64; 16];
    let words = encode(&request(CHECKPOINT_EVERY));
    let fail: SignFn = |_, _, _| false;
    assert_eq!(o.handle_with(fail, Some(Caller::Audit), SIGN, &words, &mut reply), (BAD_REQUEST, 0));
    assert!(reply.iter().all(|w| *w == 0));
    assert_eq!(*o.rule(), SeqRule::new(), "a failed signature spends nothing");
    assert_eq!(o.handle(Some(Caller::Audit), SIGN, &words, &mut reply).0, OK);
}

#[test]
fn another_caller_label_or_size_is_a_bad_request() {
    let mut r = region();
    let mut o = Oracle::boot(&mut r, identity()).unwrap();
    let words = encode(&request(CHECKPOINT_EVERY));
    let mut reply = [0xEEu64; 16];
    assert_eq!(o.handle(None, SIGN, &words, &mut reply), (BAD_REQUEST, 0));
    assert!(reply.iter().all(|w| *w == 0));
    assert_eq!(o.handle(Some(Caller::Audit), SIGN + 1, &words, &mut reply), (BAD_REQUEST, 0));
    assert_eq!(o.handle(Some(Caller::Audit), SIGN, &words[..5], &mut reply), (BAD_REQUEST, 0));
    assert_eq!(*o.rule(), SeqRule::new());
}

#[test]
fn a_bad_blob_is_unavailable_and_wiped() {
    let mut r = region();
    r[SEED_AT_FOR_TEST] ^= 1;
    let e = Oracle::boot(&mut r, identity()).err();
    assert_eq!(e, Some(BootError::Blob(BlobError::BadChecksum)));
    assert!(r.iter().all(|b| *b == 0), "the region was not wiped");
    let mut tls = [0u8; secret_blob::tls::REGION_SIZE];
    secret_blob::tls::write(&mut tls, &[1; 32], &[2; 32]).unwrap();
    assert_eq!(Oracle::boot(&mut tls, identity()).err(), Some(BootError::Blob(BlobError::BadMagic)));
}

const SEED_AT_FOR_TEST: usize = secret_blob::audit::SEED_AT;

#[test]
fn an_unavailable_auditkey_answers_its_code_and_no_data() {
    let mut reply = [0xEEu64; 16];
    let code = BootError::UnsealRefused.code();
    assert_eq!(unavailable(Some(Caller::Audit), code, &mut reply), (unavailable_label(code), 0));
    assert!(reply.iter().all(|w| *w == 0));
    assert_eq!(unavailable_code(unavailable_label(code)), Some(code));
    assert_eq!(unavailable(None, code, &mut reply), (BAD_REQUEST, 0));
    assert_eq!(unavailable_code(OK), None);
    assert_eq!(unavailable_code(REFUSED), None);
}

#[test]
fn codes_are_distinct_and_above_tlskey_s() {
    let all = [
        BootError::Blob(BlobError::BadMagic),
        BootError::Blob(BlobError::BadVersion),
        BootError::Blob(BlobError::BadChecksum),
        BootError::Blob(BlobError::NonZeroPadding),
        BootError::Blob(BlobError::TooSmall),
        BootError::RngUnavailable,
        BootError::EnvelopeInvalid,
        BootError::TpmUnavailable,
        BootError::SrkMismatch,
        BootError::UnsealRefused,
        BootError::TpmResponseInvalid,
        BootError::EnvelopeOpen,
        BootError::TpmCapFailed,
    ];
    for (i, a) in all.iter().enumerate() {
        assert!(a.code() > 0x80 && a.code() <= 0xff, "{a:?}");
        assert!(!a.message().is_empty());
        for b in &all[i + 1..] {
            assert_ne!(a.code(), b.code(), "{a:?} {b:?}");
        }
    }
}
