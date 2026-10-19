#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

//! Fixtures in `testdata/` (committed, test-only keys):
//! - `rp-genkey-{a,b}.pqsk`: `rp genkey` output of upstream rosenpass
//!   9e72f1eb (liboqs layout, 13568 B);
//! - `rp-genkey-{a,b}.pqpk.blake2s`: BLAKE2s-256 of the matching `pqpk`;
//! - `liboqs-{a,b}.{ct,shk}`: liboqs 0.8.0 (oqs-sys) encapsulation to that
//!   `pqpk`, and its shared key, checked by liboqs decapsulation when made.

extern crate std;

use std::boxed::Box;

use super::*;

const SK_A: &[u8; pq::LIBOQS_SK_LEN] = include_bytes!("../testdata/rp-genkey-a.pqsk");
const SK_B: &[u8; pq::LIBOQS_SK_LEN] = include_bytes!("../testdata/rp-genkey-b.pqsk");
const PK_HASH_A: &[u8; 32] = include_bytes!("../testdata/rp-genkey-a.pqpk.blake2s");
const PK_HASH_B: &[u8; 32] = include_bytes!("../testdata/rp-genkey-b.pqpk.blake2s");
const CT_A: &[u8; pq::CT_LEN] = include_bytes!("../testdata/liboqs-a.ct");
const CT_B: &[u8; pq::CT_LEN] = include_bytes!("../testdata/liboqs-b.ct");
const SHK_A: &[u8; 32] = include_bytes!("../testdata/liboqs-a.shk");
const SHK_B: &[u8; 32] = include_bytes!("../testdata/liboqs-b.shk");
const BLOB_SEED: [u8; 32] = [0x5e; 32];

fn cmr_sk(oqs: &[u8; pq::LIBOQS_SK_LEN]) -> Box<[u8; pq::SK_LEN]> {
    let mut sk = Box::new([0u8; pq::SK_LEN]);
    pq::cmr_sk_from_liboqs(&mut sk, oqs);
    sk
}

/// A valid blob for key `oqs`, its public key hash and a liboqs KAT pair.
fn region(oqs: &[u8; pq::LIBOQS_SK_LEN], pk_hash: &[u8; 32], ct: &[u8; pq::CT_LEN], shk: &[u8; 32]) -> Box<[u8; pq::REGION_SIZE]> {
    let mut r = Box::new([0u8; pq::REGION_SIZE]);
    let f = pq::Fields {
        secret_key: &cmr_sk(oqs),
        spkm_hash: pk_hash,
        kat_ct: ct,
        kat_shk_hash: &blake2s(&[shk]),
        blob_seed: &BLOB_SEED,
    };
    pq::write(&mut r, &f).unwrap();
    r
}

fn region_a() -> Box<[u8; pq::REGION_SIZE]> {
    region(SK_A, PK_HASH_A, CT_A, SHK_A)
}

/// Test-only blob splice (fixture b): replaces the secret key in place and
/// reseals the checksum, keeping every other field.
fn splice_sk(r: &mut [u8; pq::REGION_SIZE], sk: &[u8; pq::SK_LEN]) {
    r[pq::SK_OFFSET..pq::SK_OFFSET + pq::SK_LEN].copy_from_slice(sk);
    let sum = blake2s(&[&r[..pq::CHECKSUM_OFFSET]]);
    r[pq::CHECKSUM_OFFSET..pq::CHECKSUM_OFFSET + 32].copy_from_slice(&sum);
}

/// The cmr key's two parts in the wrong order: what a conversion that
/// forgets to move liboqs's leading 576 bytes would produce (fixture c).
fn swap_halves(sk: &[u8; pq::SK_LEN]) -> Box<[u8; pq::SK_LEN]> {
    let mut out = Box::new([0u8; pq::SK_LEN]);
    let moved = &sk[pq::SK_LEN - 576..];
    let rest = &sk[40..pq::SK_LEN - 576];
    out[40..40 + 576].copy_from_slice(moved);
    out[40 + 576..].copy_from_slice(rest);
    out
}

struct FakeEntropy {
    random: Option<u8>,
    cntpct: u64,
}

impl BootEntropy for FakeEntropy {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        match self.random {
            Some(b) => {
                out.fill(b);
                true
            }
            None => false,
        }
    }

    fn cntpct(&mut self) -> u64 {
        self.cntpct
    }
}

fn entropy() -> FakeEntropy {
    FakeEntropy { random: Some(0x77), cntpct: 1234 }
}

fn oracle(r: &[u8]) -> Oracle<'_> {
    Oracle::boot(r, PK_HASH_A, &mut entropy()).unwrap()
}

fn bucket() -> Bucket {
    Bucket::new(100, 1)
}

const PQ: Option<Caller> = Some(Caller::Pq);

/// A `PQ_DECAPS` request: the ciphertext in 24 little-endian words.
fn decaps_req(ct: &[u8; pq::CT_LEN]) -> [u64; PQ_DECAPS_REQ_WORDS] {
    let mut bytes = [0u8; PQ_DECAPS_REQ_WORDS * 8];
    bytes[..pq::CT_LEN].copy_from_slice(ct);
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn shk_of(reply: &[u64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (c, w) in out.chunks_mut(8).zip(reply) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---- boot checks (M3 plan C2 fixtures a/b/c) ----

#[test]
fn matching_blob_boots() {
    let r = region_a();
    assert!(validate(&r[..], PK_HASH_A).is_ok());
    assert!(Oracle::boot(&r[..], PK_HASH_A, &mut entropy()).is_ok());
}

#[test]
fn foreign_blob_halts_on_the_public_key_hash() {
    // (a): a complete, valid blob for another key on this image.
    let r = region(SK_B, PK_HASH_B, CT_B, SHK_B);
    assert!(validate(&r[..], PK_HASH_B).is_ok(), "the foreign blob is valid on its own image");
    assert_eq!(validate(&r[..], PK_HASH_A).err(), Some(BootError::SpkmMismatch));
}

#[test]
fn another_valid_secret_key_with_kat_and_hash_kept_halts_on_the_kat() {
    // (b): only the secret key differs; the splice is checked against the
    // secret-blob layout, so it changes nothing else.
    let mut r = region_a();
    let before = Blob::parse(&r[..]).map(|b| (*b.spkm_hash(), *b.kat_ct(), *b.kat_shk_hash(), *b.blob_seed())).unwrap();
    splice_sk(&mut r, &cmr_sk(SK_B));
    let b = Blob::parse(&r[..]).unwrap();
    assert_eq!(b.secret_key(), &*cmr_sk(SK_B));
    assert_eq!((*b.spkm_hash(), *b.kat_ct(), *b.kat_shk_hash(), *b.blob_seed()), before);
    assert_eq!(validate(&r[..], PK_HASH_A).err(), Some(BootError::KatMismatch));
}

#[test]
fn secret_key_with_swapped_halves_halts_on_the_kat() {
    // (c)
    let mut r = region_a();
    splice_sk(&mut r, &swap_halves(&cmr_sk(SK_A)));
    assert_eq!(validate(&r[..], PK_HASH_A).err(), Some(BootError::KatMismatch));
}

#[test]
fn malformed_region_reports_the_blob_error() {
    let mut r = region_a();
    r[pq::KAT_CT_OFFSET] ^= 1;
    assert_eq!(validate(&r[..], PK_HASH_A).err(), Some(BootError::Blob(BlobError::BadChecksum)));
    assert_eq!(validate(&[0u8; pq::REGION_SIZE], PK_HASH_A).err(), Some(BootError::Blob(BlobError::BadMagic)));
}

#[test]
fn rndr_failure_halts_the_boot() {
    let r = region_a();
    let mut e = FakeEntropy { random: None, cntpct: 1 };
    assert_eq!(Oracle::boot(&r[..], PK_HASH_A, &mut e).err(), Some(BootError::RndrUnavailable));
}

#[test]
fn boot_error_messages_are_distinct() {
    let all = [
        BootError::SpkmMismatch,
        BootError::KatMismatch,
        BootError::RndrUnavailable,
        BootError::Blob(BlobError::BadMagic),
        BootError::Blob(BlobError::BadVersion),
        BootError::Blob(BlobError::BadPeerCount),
        BootError::Blob(BlobError::BadChecksum),
        BootError::Blob(BlobError::NonZeroPadding),
        BootError::Blob(BlobError::TooSmall),
    ];
    // A variant missing from the list fails here.
    assert_eq!(core::mem::variant_count::<BootError>(), 4);
    assert_eq!(all.len() - 3, core::mem::variant_count::<BlobError>());
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.message(), b.message());
        }
    }
}

// ---- decapsulation ----

#[test]
fn liboqs_ciphertext_decapsulates_to_the_upstream_key() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut reply = [0u64; MAX_WORDS];
    let (label, n) = o.handle(PQ, &mut bucket(), 0, LABEL_PQ_DECAPS, &decaps_req(CT_A), &mut reply);
    assert_eq!((label, n), (OK, PQ_DECAPS_REPLY_WORDS));
    assert_eq!(shk_of(&reply[..n]), *SHK_A);
    assert!(reply[n..].iter().all(|w| *w == 0));
}

#[test]
fn ciphertext_for_another_key_yields_a_different_key_not_an_error() {
    // Implicit rejection: no error to observe, only a different key.
    let r = region_a();
    let o = oracle(&r[..]);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(PQ, &mut bucket(), 0, LABEL_PQ_DECAPS, &decaps_req(CT_B), &mut reply).0, OK);
    assert_ne!(shk_of(&reply[..4]), *SHK_A);
    assert_ne!(shk_of(&reply[..4]), *SHK_B);
}

#[test]
fn per_call_key_copy_is_zeroed_and_the_blob_left_intact() {
    let r = region_a();
    let snapshot = r.clone();
    let blob = Blob::parse(&r[..]).unwrap();
    let mut scratch = Box::new([0xa5u8; pq::SK_LEN]);
    let mut shk = [0u8; 32];
    decapsulate(&mut scratch, blob.secret_key(), CT_A, &mut shk);
    assert_eq!(shk, *SHK_A);
    assert!(scratch.iter().all(|b| *b == 0));
    assert_eq!(r, snapshot);
}

// ---- request rules ----

#[test]
fn decaps_request_must_be_exactly_24_words() {
    let r = region_a();
    let o = oracle(&r[..]);
    let req = decaps_req(CT_A);
    let mut reply = [0u64; MAX_WORDS];
    let mut b = Bucket::new(1, 1000);
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &req[..23], &mut reply), (ERR_BAD_REQUEST, 0));
    let mut long = [0u64; 25];
    long[..24].copy_from_slice(&req);
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &long, &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    // The refusals spent nothing: the one-call bucket still serves 24 words.
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &req, &mut reply), (OK, PQ_DECAPS_REPLY_WORDS));
}

#[test]
fn non_zero_trailing_bytes_are_refused_without_spending_the_bucket() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    // Bytes 188..192 are the top four bytes of word 23.
    for byte in 4..8 {
        let mut req = decaps_req(CT_A);
        req[23] |= 1u64 << (8 * byte);
        assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &req, &mut reply), (ERR_BAD_REQUEST, 0), "byte {byte}");
        assert_eq!(reply, [0; MAX_WORDS]);
    }
    // Byte 187 is ciphertext: setting it is a valid (if wrong) request.
    let mut req = decaps_req(CT_A);
    req[23] ^= 1u64 << 24;
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_DECAPS, &req, &mut reply).0, OK);
}

#[test]
fn boot_seed_request_takes_no_words() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(PQ, &mut bucket(), 0, LABEL_PQ_BOOT_SEED, &[0], &mut reply), (ERR_BAD_REQUEST, 0));
}

// ---- caller table ----

/// Labels outside `Pq`'s row: either side of the table and the largest.
const OUTSIDE_TABLE: [u64; 3] = [0, 3, u64::MAX];

#[test]
fn pq_allowed_labels_succeed() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(PQ, &mut bucket(), 0, LABEL_PQ_DECAPS, &decaps_req(CT_A), &mut reply).0, OK);
    assert_eq!(o.handle(PQ, &mut bucket(), 0, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, OK);
    assert!(Caller::Pq.allows(LABEL_PQ_DECAPS) && Caller::Pq.allows(LABEL_PQ_BOOT_SEED));
}

#[test]
fn labels_outside_the_pq_row_are_refused_without_spending_the_bucket() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    let decaps = decaps_req(CT_A);
    for label in OUTSIDE_TABLE {
        assert!(!Caller::Pq.allows(label), "{label}");
        for req in [&[][..], &[0; 4], &decaps[..]] {
            assert_eq!(o.handle(PQ, &mut b, 0, label, req, &mut reply), (ERR_BAD_REQUEST, 0), "{label}");
            assert_eq!(reply, [0; MAX_WORDS]);
        }
    }
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, ERR_RATE_LIMITED);
}

#[test]
fn unknown_caller_is_refused_for_every_label_without_spending_the_bucket() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(o.handle(None, &mut b, 0, LABEL_PQ_DECAPS, &decaps_req(CT_A), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(o.handle(None, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, OK);
}

#[test]
fn exhausted_bucket_refuses_until_refilled() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut b = Bucket::new(PQ_KEY_BURST, PQ_KEY_INTERVAL_NS);
    let mut reply = [0u64; MAX_WORDS];
    for _ in 0..PQ_KEY_BURST {
        assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, OK);
    }
    assert_eq!(o.handle(PQ, &mut b, 0, LABEL_PQ_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(o.handle(PQ, &mut b, PQ_KEY_INTERVAL_NS, LABEL_PQ_BOOT_SEED, &[], &mut reply).0, OK);
}

// ---- boot seed ----

#[test]
fn boot_seed_is_the_same_for_every_call_of_one_boot() {
    let r = region_a();
    let o = oracle(&r[..]);
    let mut first = [0u64; MAX_WORDS];
    let mut again = [0u64; MAX_WORDS];
    assert_eq!(o.handle(PQ, &mut bucket(), 0, LABEL_PQ_BOOT_SEED, &[], &mut first), (OK, PQ_BOOT_SEED_REPLY_WORDS));
    assert_eq!(o.handle(PQ, &mut bucket(), 5, LABEL_PQ_BOOT_SEED, &[], &mut again).0, OK);
    assert_eq!(first, again);
    let want = blake2s(&[b"pq-boot-seed", &BLOB_SEED, &[0x77; 32], &1234u64.to_le_bytes()]);
    assert_eq!(shk_of(&first[..4]), want);
}

#[test]
fn boot_seed_depends_on_every_input() {
    let base = *boot_seed(&BLOB_SEED, &mut entropy()).unwrap();
    assert_ne!(*boot_seed(&[0x5f; 32], &mut entropy()).unwrap(), base);
    assert_ne!(*boot_seed(&BLOB_SEED, &mut FakeEntropy { random: Some(0x78), cntpct: 1234 }).unwrap(), base);
    assert_ne!(*boot_seed(&BLOB_SEED, &mut FakeEntropy { random: Some(0x77), cntpct: 1235 }).unwrap(), base);
}

#[test]
fn pq_and_hs_boot_seeds_differ_even_from_identical_inputs() {
    // `key` derives hs's seed as BLAKE2s(blob seed ‖ RNDR ‖ CNTPCT)
    // (crates/pds/key); the label keeps pq's apart even if every input
    // coincided.
    let hs = blake2s(&[&BLOB_SEED, &[0x77; 32], &1234u64.to_le_bytes()]);
    let pq = *boot_seed(&BLOB_SEED, &mut entropy()).unwrap();
    assert_ne!(pq, hs);
    assert_ne!(pq, [0; 32]);
}
