#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

const GW_PRIVATE: [u8; 32] = [0x11; 32];
const PEER_PRIVATE: [u8; 32] = [0x22; 32];
const SEED: [u8; 32] = [0x5e; 32];

fn clamped(k: [u8; 32]) -> Key32 {
    let mut k = Key32::from_bytes(k);
    crypto::clamp(&mut k);
    k
}

fn gw_public() -> [u8; 32] {
    crypto::public_key(&clamped(GW_PRIVATE))
}

fn peer_publics() -> [[u8; 32]; 2] {
    [crypto::public_key(&clamped(PEER_PRIVATE)), [0x33; 32]]
}

fn region() -> [u8; secret_blob::REGION_SIZE] {
    let mut r = [0u8; secret_blob::REGION_SIZE];
    let p = peer_publics();
    secret_blob::write(&mut r, clamped(GW_PRIVATE).as_bytes(), &[0x99; 32], &p).unwrap();
    r
}

fn oracle(r: &[u8]) -> Oracle<'_> {
    let peers = peer_publics();
    let blob = validate(r, &gw_public(), peers.iter()).unwrap();
    Oracle::new(blob, Key32::from_bytes(SEED))
}

fn bucket() -> Bucket {
    Bucket::new(100, 1)
}

const HS: Option<Caller> = Some(Caller::Hs);

#[test]
fn valid_region_passes_validation() {
    let r = region();
    let peers = peer_publics();
    assert!(validate(&r, &gw_public(), peers.iter()).is_ok());
}

#[test]
fn wrong_gateway_key_is_a_distinct_boot_error() {
    let r = region();
    let peers = peer_publics();
    assert_eq!(validate(&r, &[0x44; 32], peers.iter()).err(), Some(BootError::GatewayKeyMismatch));
}

#[test]
fn mismatched_peer_key_is_a_distinct_boot_error() {
    let r = region();
    let mut peers = peer_publics();
    peers[1][0] ^= 1;
    assert_eq!(validate(&r, &gw_public(), peers.iter()).err(), Some(BootError::PeerMismatch));
}

#[test]
fn peers_in_another_order_do_not_validate() {
    let r = region();
    let peers = peer_publics();
    assert_eq!(validate(&r, &gw_public(), peers.iter().rev()).err(), Some(BootError::PeerMismatch));
}

#[test]
fn peer_count_mismatch_and_bad_format_report_the_blob_error() {
    let r = region();
    let peers = peer_publics();
    assert_eq!(validate(&r, &gw_public(), peers[..1].iter()).err(), Some(BootError::Blob(BlobError::BadPeerCount)));
    let mut bad = r;
    bad[0] ^= 1;
    assert_eq!(validate(&bad, &gw_public(), peers.iter()).err(), Some(BootError::Blob(BlobError::BadMagic)));
}

#[test]
fn boot_error_messages_are_distinct() {
    let all = all_boot_errors(blob_successor);
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.message(), b.message());
        }
    }
}

/// Every BootError: the eleven plain kinds, then each BlobError reached by
/// `next`. The walk must visit every BlobError and BootError must have
/// exactly the twelve kinds listed, or this fails.
fn all_boot_errors(next: impl Fn(BlobError) -> Option<BlobError>) -> [BootError; 17] {
    let mut all = [BootError::GatewayKeyMismatch; 17];
    all[1] = BootError::PeerMismatch;
    all[2] = BootError::RngUnavailable;
    all[3] = BootError::SeedDerivation;
    all[4] = BootError::EnvelopeInvalid;
    all[5] = BootError::TpmUnavailable;
    all[6] = BootError::SrkMismatch;
    all[7] = BootError::UnsealRefused;
    all[8] = BootError::TpmResponseInvalid;
    all[9] = BootError::EnvelopeOpen;
    all[10] = BootError::TpmCapFailed;
    let mut n = 11;
    let mut e = Some(BlobError::BadMagic);
    while let Some(v) = e {
        all[n] = BootError::Blob(v);
        n += 1;
        e = next(v);
    }
    assert_eq!(n, all.len(), "every BlobError listed");
    assert_eq!(n - 11, core::mem::variant_count::<BlobError>());
    assert_eq!(core::mem::variant_count::<BootError>(), 12);
    all
}

/// Every BlobError, walked through an exhaustive successor match: a new
/// variant fails to compile until it gets an arm, and its arm must name a
/// successor (or end the walk), so leaving it out of the comparison takes a
/// deliberately wrong arm rather than a forgotten line.
fn blob_successor(e: BlobError) -> Option<BlobError> {
    match e {
        BlobError::BadMagic => Some(BlobError::BadVersion),
        BlobError::BadVersion => Some(BlobError::BadPeerCount),
        BlobError::BadPeerCount => Some(BlobError::BadChecksum),
        BlobError::BadChecksum => Some(BlobError::NonZeroPadding),
        BlobError::NonZeroPadding => Some(BlobError::TooSmall),
        BlobError::TooSmall => None,
    }
}

#[test]
fn boot_error_codes_are_distinct_nonzero_and_fit_the_unavailable_label() {
    let all = all_boot_errors(blob_successor);
    for (i, a) in all.iter().enumerate() {
        assert!((1..=0xff).contains(&a.code()), "{a:?}");
        assert_eq!(unavailable_code(unavailable_label(a.code())), Some(a.code()), "{a:?}");
        for b in &all[i + 1..] {
            assert_ne!(a.code(), b.code());
        }
    }
}

#[test]
fn each_unseal_failure_has_its_own_boot_error() {
    use tpm2::boot::UnsealError;
    let all = [
        UnsealError::Rng,
        UnsealError::EnvelopeInvalid,
        UnsealError::TpmUnavailable,
        UnsealError::SrkMismatch,
        UnsealError::UnsealRefused,
        UnsealError::ResponseInvalid,
        UnsealError::EnvelopeOpen,
        UnsealError::CapFailed,
    ];
    assert_eq!(all.len(), core::mem::variant_count::<UnsealError>());
    assert_eq!(BootError::from(UnsealError::Rng), BootError::RngUnavailable);
    assert_eq!(BootError::from(UnsealError::SrkMismatch).code(), 13);
    assert_eq!(BootError::from(UnsealError::UnsealRefused).code(), 14);
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(BootError::from(*a), BootError::from(*b), "{a:?} and {b:?}");
        }
    }
}

#[test]
fn no_other_reply_label_reads_as_unavailable() {
    for label in [OK, ERR_BAD_REQUEST, ERR_ZERO_DH, ERR_RATE_LIMITED, ERR_CRYPTO, ERR_UNAVAILABLE - 1, ERR_UNAVAILABLE + 0x100] {
        assert_eq!(unavailable_code(label), None, "{label:#x}");
    }
}

#[test]
fn unavailable_answers_every_label_with_the_code_and_no_data() {
    let code = BootError::GatewayKeyMismatch.code();
    for label in [LABEL_STATIC_DH, LABEL_BOOT_SEED, 0, u64::MAX] {
        let mut reply = [u64::MAX; MAX_WORDS];
        let (got, n) = unavailable(HS, code, &mut reply);
        assert_eq!((unavailable_code(got), n), (Some(code), 0), "{label}");
        assert_eq!(reply, [0; MAX_WORDS]);
    }
}

#[test]
fn unavailable_refuses_an_unknown_caller_as_a_bad_request() {
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(unavailable(None, BootError::PeerMismatch.code(), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

#[test]
fn static_dh_matches_the_peer_side_computation() {
    let r = region();
    let o = oracle(&r);
    let peer_pub = peer_publics()[0];
    let mut reply = [0u64; MAX_WORDS];
    let (label, n) = o.handle(HS, &mut bucket(), 0, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply);
    assert_eq!((label, n), (OK, STATIC_DH_REPLY_WORDS));
    let expected = crypto::dh(&clamped(PEER_PRIVATE), &gw_public()).unwrap();
    assert_eq!(unpack32(&reply[..4]).unwrap(), *expected.as_bytes());
}

#[test]
fn low_order_point_is_refused_and_reply_zeroed() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(o.handle(HS, &mut bucket(), 0, LABEL_STATIC_DH, &[0; 4], &mut reply), (ERR_ZERO_DH, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

#[test]
fn boot_seed_returns_the_per_boot_value() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(HS, &mut bucket(), 0, LABEL_BOOT_SEED, &[], &mut reply), (OK, BOOT_SEED_REPLY_WORDS));
    assert_eq!(unpack32(&reply[..4]).unwrap(), SEED);
}

#[test]
fn wrong_sizes_and_unknown_labels_are_bad_requests() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [0u64; MAX_WORDS];
    let mut b = bucket();
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_STATIC_DH, &[0; 3], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_STATIC_DH, &[0; 5], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[0], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(HS, &mut b, 0, 0, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(HS, &mut b, 0, 99, &[0; 4], &mut reply), (ERR_BAD_REQUEST, 0));
}

#[test]
fn exhausted_bucket_refuses_until_refilled_and_bad_requests_cost_nothing() {
    let r = region();
    let o = oracle(&r);
    let mut b = Bucket::new(2, 1000);
    let mut reply = [0u64; MAX_WORDS];
    for _ in 0..10 {
        assert_eq!(o.handle(HS, &mut b, 0, 99, &[], &mut reply).0, ERR_BAD_REQUEST);
    }
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(o.handle(HS, &mut b, 1000, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

/// Labels outside `Hs`'s row: either side of the table, the retired
/// static-PSK label (2) and the largest label.
const OUTSIDE_TABLE: [u64; 4] = [0, 2, 4, u64::MAX];

#[test]
fn hs_allowed_labels_succeed() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [0u64; MAX_WORDS];
    let peer_pub = peer_publics()[0];
    assert_eq!(o.handle(HS, &mut bucket(), 0, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply).0, OK);
    assert_eq!(o.handle(HS, &mut bucket(), 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert!(Caller::Hs.allows(LABEL_STATIC_DH) && Caller::Hs.allows(LABEL_BOOT_SEED));
}

#[test]
fn labels_outside_the_hs_row_are_refused_without_spending_the_bucket() {
    let r = region();
    let o = oracle(&r);
    // A one-call bucket: if any refusal spent it, the final call would be
    // rate limited.
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    for label in OUTSIDE_TABLE {
        assert!(!Caller::Hs.allows(label), "{label}");
        for req in [&[][..], &[0; 1], &[0; 4], &[0; 5]] {
            assert_eq!(o.handle(HS, &mut b, 0, label, req, &mut reply), (ERR_BAD_REQUEST, 0), "{label}");
            assert_eq!(reply, [0; MAX_WORDS]);
        }
    }
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, ERR_RATE_LIMITED);
}

#[test]
fn unknown_caller_is_refused_for_every_label_without_spending_the_bucket() {
    let r = region();
    let o = oracle(&r);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    let peer_pub = peer_publics()[0];
    assert_eq!(o.handle(None, &mut b, 0, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(o.handle(None, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(HS, &mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

#[test]
fn pack_and_unpack_round_trip() {
    let v: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(unpack32(&pack32(&v)), Some(v));
}

struct FakeEntropy(bool);

impl BootEntropy for FakeEntropy {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        out.fill(0x42);
        self.0
    }

    fn cntpct(&mut self) -> u64 {
        7
    }
}

/// M5 plan C6: validation and the boot seed are one fallible step (the PD
/// wipes the region on its error). Allow: a valid region with entropy boots.
#[test]
fn boot_validates_and_derives_the_seed_in_one_step() {
    let r = region();
    let peers = peer_publics();
    let o = Oracle::boot(&r, &gw_public(), peers.iter(), &mut FakeEntropy(true)).unwrap();
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(HS, &mut bucket(), 0, LABEL_BOOT_SEED, &[], &mut reply).0, 0);
}

/// Deny: RNDR failing after a successful validation is a boot error, not a
/// half-booted oracle.
#[test]
fn boot_with_rndr_failing_after_validation_is_refused() {
    let r = region();
    let peers = peer_publics();
    assert!(matches!(
        Oracle::boot(&r, &gw_public(), peers.iter(), &mut FakeEntropy(false)),
        Err(BootError::RngUnavailable)
    ));
}
