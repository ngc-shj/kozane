#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use core::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const GW_PRIVATE: [u8; 32] = [0x11; 32];
const PEER_PRIVATE: [u8; 32] = [0x22; 32];
const SEED: [u8; 32] = [0x5e; 32];
/// RFC 6979 A.2.5's P-256 private key, the TLS scalar throughout.
const TLS_PRIVATE: [u8; 32] = hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not hex"),
    }
}

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

fn xy(private: &[u8; 32]) -> [u8; 64] {
    let mut s = Secret::<32>::zero();
    s.as_mut_bytes().copy_from_slice(private);
    tpm2::crypto::public_point(&s).unwrap()
}

fn tls_public() -> [u8; TLS_PUBLIC_LEN] {
    let mut p = [0x04; TLS_PUBLIC_LEN];
    p[1..].copy_from_slice(&xy(&TLS_PRIVATE));
    p
}

fn region_with(tls_private: &[u8; 32]) -> [u8; secret_blob::REGION_SIZE] {
    let mut r = [0u8; secret_blob::REGION_SIZE];
    let p = peer_publics();
    secret_blob::write(&mut r, clamped(GW_PRIVATE).as_bytes(), &[0x99; 32], tls_private, &p).unwrap();
    r
}

fn region() -> [u8; secret_blob::REGION_SIZE] {
    region_with(&TLS_PRIVATE)
}

fn validated(r: &mut [u8]) -> Result<Validated<'_>, BootError> {
    let peers = peer_publics();
    validate(r, &gw_public(), &tls_public(), peers.iter())
}

fn oracle(r: &mut [u8]) -> Oracle<'_> {
    Oracle::new(validated(r).unwrap(), Key32::from_bytes(SEED))
}

fn buckets() -> Buckets {
    Buckets::with(Bucket::new(100, 1), Bucket::new(100, 1))
}

const HS: Option<Caller> = Some(Caller::Hs);
const TLS: Option<Caller> = Some(Caller::Tls);

/// RNDR: every byte `byte`, or a failure.
struct FakeEntropy {
    ok: bool,
    byte: u8,
}


fn rndr() -> FakeEntropy {
    FakeEntropy { ok: true, byte: 0x42 }
}

impl Entropy for FakeEntropy {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        out.fill(self.byte);
        self.ok
    }

    fn cntpct(&mut self) -> u64 {
        7
    }
}

fn call(o: &Oracle<'_>, caller: Option<Caller>, b: &mut Buckets, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
    o.handle(caller, b, 0, &mut rndr(), label, req, reply)
}

#[test]
fn valid_region_passes_validation() {
    let mut r = region();
    let v = validated(&mut r).unwrap();
    assert_eq!(v.tls, Ok(()));
}

#[test]
fn wrong_gateway_key_is_a_distinct_boot_error() {
    let mut r = region();
    let peers = peer_publics();
    assert_eq!(validate(&mut r, &[0x44; 32], &tls_public(), peers.iter()).err(), Some(BootError::GatewayKeyMismatch));
}

#[test]
fn mismatched_peer_key_is_a_distinct_boot_error() {
    let mut r = region();
    let mut peers = peer_publics();
    peers[1][0] ^= 1;
    assert_eq!(validate(&mut r, &gw_public(), &tls_public(), peers.iter()).err(), Some(BootError::PeerMismatch));
}

#[test]
fn peers_in_another_order_do_not_validate() {
    let mut r = region();
    let peers = peer_publics();
    assert_eq!(validate(&mut r, &gw_public(), &tls_public(), peers.iter().rev()).err(), Some(BootError::PeerMismatch));
}

#[test]
fn peer_count_mismatch_and_bad_format_report_the_blob_error() {
    let mut r = region();
    let peers = peer_publics();
    assert_eq!(
        validate(&mut r, &gw_public(), &tls_public(), peers[..1].iter()).err(),
        Some(BootError::Blob(BlobError::BadPeerCount))
    );
    let mut bad = region();
    bad[0] ^= 1;
    assert_eq!(validate(&mut bad, &gw_public(), &tls_public(), peers.iter()).err(), Some(BootError::Blob(BlobError::BadMagic)));
}

#[test]
fn boot_error_messages_are_distinct() {
    let all = all_boot_errors(blob_successor);
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.message(), b.message());
        }
    }
    assert_ne!(TlsKeyError::Invalid.message(), TlsKeyError::Mismatch.message());
}

/// Every BootError: the ten plain kinds, then each BlobError reached by
/// `next`. The walk must visit every BlobError and BootError must have
/// exactly the eleven kinds listed, or this fails.
fn all_boot_errors(next: impl Fn(BlobError) -> Option<BlobError>) -> [BootError; 16] {
    let mut all = [BootError::GatewayKeyMismatch; 16];
    all[1] = BootError::PeerMismatch;
    all[2] = BootError::RndrUnavailable;
    all[3] = BootError::SeedDerivation;
    all[4] = BootError::EnvelopeInvalid;
    all[5] = BootError::TpmUnavailable;
    all[6] = BootError::SrkMismatch;
    all[7] = BootError::UnsealRefused;
    all[8] = BootError::TpmResponseInvalid;
    all[9] = BootError::EnvelopeOpen;
    let mut n = 10;
    let mut e = Some(BlobError::BadMagic);
    while let Some(v) = e {
        all[n] = BootError::Blob(v);
        n += 1;
        e = next(v);
    }
    assert_eq!(n, all.len(), "every BlobError listed");
    assert_eq!(n - 10, core::mem::variant_count::<BlobError>());
    assert_eq!(core::mem::variant_count::<BootError>(), 11);
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

/// Every TlsKeyError, by an exhaustive match (a new variant must be added).
fn all_tls_key_errors() -> [TlsKeyError; 2] {
    let all = [TlsKeyError::Invalid, TlsKeyError::Mismatch];
    for e in all {
        match e {
            TlsKeyError::Invalid | TlsKeyError::Mismatch => {}
        }
    }
    assert_eq!(all.len(), core::mem::variant_count::<TlsKeyError>());
    all
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

/// M6 plan D5: the TLS key's codes share the boot errors' space, so no
/// `code()` of either may collide with another.
#[test]
fn tls_key_codes_collide_with_no_boot_error_code_and_fit_the_label() {
    let mut codes: std::vec::Vec<u32> = all_boot_errors(blob_successor).iter().map(|e| e.code()).collect();
    for e in all_tls_key_errors() {
        assert!((1..=0xff).contains(&e.code()), "{e:?}");
        assert_eq!(unavailable_code(unavailable_label(e.code())), Some(e.code()), "{e:?}");
        codes.push(e.code());
    }
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), n, "a code is used twice");
    assert_eq!((TlsKeyError::Invalid.code(), TlsKeyError::Mismatch.code()), (17, 18));
}

#[test]
fn each_unseal_failure_has_its_own_boot_error() {
    use tpm2::boot::UnsealError;
    let all = [
        UnsealError::Rndr,
        UnsealError::EnvelopeInvalid,
        UnsealError::TpmUnavailable,
        UnsealError::SrkMismatch,
        UnsealError::UnsealRefused,
        UnsealError::ResponseInvalid,
        UnsealError::EnvelopeOpen,
    ];
    assert_eq!(all.len(), core::mem::variant_count::<UnsealError>());
    assert_eq!(BootError::from(UnsealError::Rndr), BootError::RndrUnavailable);
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
    for caller in [HS, TLS] {
        for label in [LABEL_STATIC_DH, LABEL_BOOT_SEED, LABEL_TLS_SIGN, 0, u64::MAX] {
            let mut reply = [u64::MAX; MAX_WORDS];
            let (got, n) = unavailable(caller, code, &mut reply);
            assert_eq!((unavailable_code(got), n), (Some(code), 0), "{label}");
            assert_eq!(reply, [0; MAX_WORDS]);
        }
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
    let mut r = region();
    let o = oracle(&mut r);
    let peer_pub = peer_publics()[0];
    let mut reply = [0u64; MAX_WORDS];
    let (label, n) = call(&o, HS, &mut buckets(), LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply);
    assert_eq!((label, n), (OK, STATIC_DH_REPLY_WORDS));
    let expected = crypto::dh(&clamped(PEER_PRIVATE), &gw_public()).unwrap();
    assert_eq!(unpack32(&reply[..4]).unwrap(), *expected.as_bytes());
}

#[test]
fn low_order_point_is_refused_and_reply_zeroed() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(call(&o, HS, &mut buckets(), LABEL_STATIC_DH, &[0; 4], &mut reply), (ERR_ZERO_DH, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

fn seed_of(o: &Oracle<'_>, caller: Option<Caller>, b: &mut Buckets) -> [u8; 32] {
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(o, caller, b, LABEL_BOOT_SEED, &[], &mut reply), (OK, BOOT_SEED_REPLY_WORDS));
    unpack32(&reply[..4]).unwrap()
}

/// M6 plan C5 (S14): each caller's seed is BLAKE2s(boot seed ‖ its tag),
/// `hs` included, so neither learns the other's or the per-boot value.
#[test]
fn boot_seed_is_derived_per_caller_and_differs_between_callers() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = buckets();
    let hs = seed_of(&o, HS, &mut b);
    let tls = seed_of(&o, TLS, &mut b);
    assert_eq!(hs, secret_blob::blake2s(&[&SEED, b"hs"]));
    assert_eq!(tls, secret_blob::blake2s(&[&SEED, b"tls"]));
    assert_ne!(hs, tls);
    assert_ne!(hs, SEED);
}

/// F12: a repeated call returns the same value and spends the caller's
/// bucket each time.
#[test]
fn repeated_boot_seed_calls_return_the_same_value_and_count_against_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Buckets::with(Bucket::new(100, 1), Bucket::new(2, 1000));
    let first = seed_of(&o, TLS, &mut b);
    assert_eq!(seed_of(&o, TLS, &mut b), first);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
}

#[test]
fn wrong_sizes_and_unknown_labels_are_bad_requests() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [0u64; MAX_WORDS];
    let mut b = buckets();
    assert_eq!(call(&o, HS, &mut b, LABEL_STATIC_DH, &[0; 3], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, HS, &mut b, LABEL_STATIC_DH, &[0; 5], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[0], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &[0; 3], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &[0; 5], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &[0; 8], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, HS, &mut b, 0, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, HS, &mut b, 99, &[0; 4], &mut reply), (ERR_BAD_REQUEST, 0));
}

#[test]
fn exhausted_bucket_refuses_until_refilled_and_bad_requests_cost_nothing() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Buckets::with(Bucket::new(2, 1000), Bucket::new(100, 1));
    let mut reply = [0u64; MAX_WORDS];
    for _ in 0..10 {
        assert_eq!(call(&o, HS, &mut b, 99, &[], &mut reply).0, ERR_BAD_REQUEST);
    }
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(o.handle(HS, &mut b, 1000, &mut rndr(), LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

/// M6 plan C5: per-caller buckets. `tls` exhausting its own leaves `hs`'s
/// whole, and the other way round.
#[test]
fn each_caller_spends_only_its_own_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Buckets::with(Bucket::new(1, 1000), Bucket::new(1, 1000));
    let mut reply = [0u64; MAX_WORDS];
    let hash = pack32(&[7; 32]);
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &hash, &mut reply).0, OK);
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &hash, &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
}

#[test]
fn production_buckets_have_the_documented_sizes() {
    let mut b = Buckets::new();
    for _ in 0..TLS_SIGN_BURST {
        assert!(b.of(Caller::Tls).take(0));
    }
    assert!(!b.of(Caller::Tls).take(0));
    assert!(b.of(Caller::Tls).take(TLS_SIGN_INTERVAL_NS));
    for _ in 0..KEY_BURST {
        assert!(b.of(Caller::Hs).take(0));
    }
    assert!(!b.of(Caller::Hs).take(0));
}

/// Labels outside `Hs`'s row: either side of the table, the retired
/// static-PSK label (2), `Tls`'s sign label and the largest label.
const OUTSIDE_HS: [u64; 5] = [0, 2, LABEL_TLS_SIGN, 5, u64::MAX];
/// Labels outside `Tls`'s row: `STATIC_DH` among them (M6 plan C5).
const OUTSIDE_TLS: [u64; 5] = [0, LABEL_STATIC_DH, 2, 5, u64::MAX];

#[test]
fn hs_allowed_labels_succeed() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [0u64; MAX_WORDS];
    let peer_pub = peer_publics()[0];
    assert_eq!(call(&o, HS, &mut buckets(), LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply).0, OK);
    assert_eq!(call(&o, HS, &mut buckets(), LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert!(Caller::Hs.allows(LABEL_STATIC_DH) && Caller::Hs.allows(LABEL_BOOT_SEED));
}

#[test]
fn tls_allowed_labels_succeed() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut buckets(), LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (OK, TLS_SIGN_REPLY_WORDS));
    assert_eq!(call(&o, TLS, &mut buckets(), LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert!(Caller::Tls.allows(LABEL_TLS_SIGN) && Caller::Tls.allows(LABEL_BOOT_SEED));
}

fn refused_without_spending(caller: Caller, outside: &[u64]) {
    let mut r = region();
    let o = oracle(&mut r);
    // One-call buckets: if any refusal spent one, the final call would be
    // rate limited.
    let mut b = Buckets::with(Bucket::new(1, 1000), Bucket::new(1, 1000));
    let mut reply = [u64::MAX; MAX_WORDS];
    let peer_pub = peer_publics()[0];
    for &label in outside {
        assert!(!caller.allows(label), "{label}");
        for req in [&[][..], &[0; 1], &[0; 4], &pack32(&peer_pub), &[0; 5], &[0; 8]] {
            assert_eq!(call(&o, Some(caller), &mut b, label, req, &mut reply), (ERR_BAD_REQUEST, 0), "{label}");
            assert_eq!(reply, [0; MAX_WORDS]);
        }
    }
    assert_eq!(call(&o, Some(caller), &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, Some(caller), &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, ERR_RATE_LIMITED);
}

#[test]
fn labels_outside_the_hs_row_are_refused_without_spending_the_bucket() {
    refused_without_spending(Caller::Hs, &OUTSIDE_HS);
}

/// M6 plan C5: `tls` gets no DH with the gateway's WireGuard key.
#[test]
fn labels_outside_the_tls_row_static_dh_included_are_refused_without_spending_the_bucket() {
    refused_without_spending(Caller::Tls, &OUTSIDE_TLS);
}

#[test]
fn unknown_caller_is_refused_for_every_label_without_spending_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Buckets::with(Bucket::new(1, 1000), Bucket::new(1, 1000));
    let mut reply = [u64::MAX; MAX_WORDS];
    let peer_pub = peer_publics()[0];
    assert_eq!(call(&o, None, &mut b, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(call(&o, None, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, None, &mut b, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

#[test]
fn pack_and_unpack_round_trip() {
    let v: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(unpack32(&pack32(&v)), Some(v));
}

/// M5 plan C6: validation and the boot seed are one fallible step (the PD
/// wipes the region on its error). Allow: a valid region with entropy boots.
#[test]
fn boot_validates_and_derives_the_seed_in_one_step() {
    let mut r = region();
    let peers = peer_publics();
    let o = Oracle::boot(&mut r, &gw_public(), &tls_public(), peers.iter(), &mut rndr()).unwrap();
    assert_eq!(o.tls_key(), Ok(()));
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, HS, &mut buckets(), LABEL_BOOT_SEED, &[], &mut reply).0, 0);
}

/// Deny: RNDR failing after a successful validation is a boot error, not a
/// half-booted oracle.
#[test]
fn boot_with_rndr_failing_after_validation_is_refused() {
    let mut r = region();
    let peers = peer_publics();
    assert!(matches!(
        Oracle::boot(&mut r, &gw_public(), &tls_public(), peers.iter(), &mut FakeEntropy { ok: false, byte: 0 }),
        Err(BootError::RndrUnavailable)
    ));
}

// ---------------------------------------------------------------- D5

fn d5_boot(tls_private: &[u8; 32]) -> ([u8; secret_blob::REGION_SIZE], TlsKeyError) {
    let mut r = region_with(tls_private);
    let peers = peer_publics();
    let o = Oracle::boot(&mut r, &gw_public(), &tls_public(), peers.iter(), &mut rndr()).expect("D5: the boot succeeds");
    let mut reply = [u64::MAX; MAX_WORDS];
    let mut b = buckets();
    // hs keeps both its labels.
    let peer_pub = peer_publics()[0];
    assert_eq!(call(&o, HS, &mut b, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply).0, OK);
    assert_eq!(call(&o, HS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    // tls keeps its seed; only the sign is Unavailable, with the code.
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    reply.fill(u64::MAX);
    let (label, n) = call(&o, TLS, &mut b, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply);
    assert_eq!(n, 0);
    assert_eq!(reply, [0; MAX_WORDS]);
    let code = unavailable_code(label).expect("an Unavailable label");
    let e = o.tls_key().unwrap_err();
    assert_eq!(code, e.code());
    (r, e)
}

/// M6 plan D5 (F10): a scalar whose point is not the certificate's.
#[test]
fn a_mismatched_tls_key_leaves_hs_working_and_tls_sign_unavailable_with_its_code() {
    let (r, e) = d5_boot(&[0x01; 32]);
    assert_eq!(e, TlsKeyError::Mismatch);
    // S-N3: the rejected scalar is wiped from the plaintext.
    assert!(r[secret_blob::TLS_PRIVATE_AT..secret_blob::TLS_PRIVATE_AT + 32].iter().all(|b| *b == 0));
}

#[test]
fn an_invalid_tls_scalar_is_its_own_code() {
    assert_eq!(d5_boot(&[0; 32]).1, TlsKeyError::Invalid);
    // n itself is not below the order.
    assert_eq!(d5_boot(&P256_N).1, TlsKeyError::Invalid);
    assert_eq!(d5_boot(&[0xff; 32]).1, TlsKeyError::Invalid);
}

/// The TLS verdict never decides the boot: a boot failure stays the boot
/// failure (allow side of D5 inverted).
#[test]
fn a_boot_error_wins_over_a_tls_key_error() {
    let mut r = region_with(&[0x01; 32]);
    let peers = peer_publics();
    assert_eq!(validate(&mut r, &[0x44; 32], &tls_public(), peers.iter()).err(), Some(BootError::GatewayKeyMismatch));
}

#[test]
fn check_tls_key_refuses_a_point_without_the_uncompressed_prefix() {
    let mut p = tls_public();
    assert_eq!(check_tls_key(&TLS_PRIVATE, &p), Ok(()));
    p[0] = 0x02;
    assert_eq!(check_tls_key(&TLS_PRIVATE, &p), Err(TlsKeyError::Mismatch));
}

// ---------------------------------------------------------------- TLS_SIGN

fn verify(content: &[u8], sig: &[u8; 64]) -> bool {
    libcrux_p256::ecdsa_verif_p256_sha2(content.len() as u32, content, &xy(&TLS_PRIVATE), &sig[..32], &sig[32..])
}

fn sig_of(reply: &[u64]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    for (c, w) in sig.chunks_mut(8).zip(reply) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    sig
}

fn content_for(hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut c = std::vec![0x20u8; 64];
    c.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    c.push(0);
    c.extend_from_slice(hash);
    c
}

/// RFC 8446 §4.4.3: `key` signs the server CertificateVerify content it
/// builds around the hash, not the hash or anything else (M6 plan C5).
#[test]
fn tls_sign_signs_the_server_certificate_verify_content_of_the_hash() {
    let mut r = region();
    let o = oracle(&mut r);
    let hash: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0xa5);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut buckets(), LABEL_TLS_SIGN, &pack32(&hash), &mut reply), (OK, 8));
    let sig = sig_of(&reply);
    let content = content_for(&hash);
    assert_eq!(content.len(), CV_CONTENT_LEN);
    assert!(verify(&content, &sig), "not a signature over the CertificateVerify content");
    assert!(!verify(&hash, &sig));
    let mut client = content.clone();
    client[64 + 9] = b'c'; // "client CertificateVerify"
    client[64 + 10..64 + 15].copy_from_slice(b"lient");
    assert!(!verify(&client, &sig));
}

#[test]
fn certificate_verify_content_is_the_rfc_8446_layout() {
    let mut c = Secret::<CV_CONTENT_LEN>::zero();
    certificate_verify_content(&mut c, &[9; 32]);
    assert_eq!(&c.as_bytes()[..], &content_for(&[9; 32])[..]);
}

/// L9: no RNDR, no k', no signature.
#[test]
fn tls_sign_with_rndr_failing_is_a_crypto_error_and_spends_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Buckets::with(Bucket::new(100, 1), Bucket::new(1, 1000));
    let mut reply = [u64::MAX; MAX_WORDS];
    let mut bad = FakeEntropy { ok: false, byte: 0x42 };
    assert_eq!(o.handle(TLS, &mut b, 0, &mut bad, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_CRYPTO, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_RATE_LIMITED, 0));
}

/// S7: k' is an input of the nonce, so two RNDR draws give two r for one
/// transcript (and both verify).
#[test]
fn two_k_prime_values_give_different_r_for_the_same_hash() {
    let mut r = region();
    let o = oracle(&mut r);
    let hash = pack32(&[3; 32]);
    let mut sigs = std::vec::Vec::new();
    for byte in [0x42, 0x43] {
        let mut reply = [0u64; MAX_WORDS];
        let mut e = FakeEntropy { ok: true, byte };
        assert_eq!(o.handle(TLS, &mut buckets(), 0, &mut e, LABEL_TLS_SIGN, &hash, &mut reply).0, OK);
        let sig = sig_of(&reply);
        assert!(verify(&content_for(&[3; 32]), &sig));
        sigs.push(sig);
    }
    assert_ne!(sigs[0][..32], sigs[1][..32]);
    // The same k' gives the same signature (the nonce is deterministic in it).
    let mut reply = [0u64; MAX_WORDS];
    let mut e = FakeEntropy { ok: true, byte: 0x42 };
    o.handle(TLS, &mut buckets(), 0, &mut e, LABEL_TLS_SIGN, &hash, &mut reply);
    assert_eq!(sig_of(&reply), sigs[0]);
}

fn sign_hex(msg: &[u8], extra: &[u8]) -> (std::string::String, std::string::String) {
    let mut sig = Secret::<64>::zero();
    assert!(sign_rfc6979(libcrux_sign, &mut sig, msg, &TLS_PRIVATE, extra));
    let hex = |b: &[u8]| b.iter().map(|x| std::format!("{x:02X}")).collect::<std::string::String>();
    (hex(&sig.as_bytes()[..32]), hex(&sig.as_bytes()[32..]))
}

/// RFC 6979 A.2.5, P-256 with SHA-256, empty k': both messages' signatures.
#[test]
fn rfc6979_a_2_5_signatures_are_reproduced_with_an_empty_additional_input() {
    let pub_xy = xy(&TLS_PRIVATE);
    assert_eq!(pub_xy[..32], hex32("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"));
    assert_eq!(pub_xy[32..], hex32("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"));
    assert_eq!(
        sign_hex(b"sample", &[]),
        (
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716".into(),
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8".into()
        )
    );
    assert_eq!(
        sign_hex(b"test", &[]),
        (
            "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367".into(),
            "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083".into()
        )
    );
}

/// The nonces a sign function was handed, and how many it refused first.
static NONCES: std::sync::Mutex<std::vec::Vec<[u8; 32]>> = std::sync::Mutex::new(std::vec::Vec::new());
static REFUSE_FIRST: AtomicUsize = AtomicUsize::new(0);

fn recording_sign(sig: &mut [u8; 64], msg: &[u8], private: &[u8; 32], nonce: &[u8; 32]) -> bool {
    let mut seen = NONCES.lock().unwrap();
    seen.push(*nonce);
    if seen.len() <= REFUSE_FIRST.load(Ordering::SeqCst) {
        return false;
    }
    libcrux_sign(sig, msg, private, nonce)
}

/// The candidates sign_rfc6979 hands `recording_sign` (which refuses the
/// first `refuse`), and its result. One test at a time holds the lock.
fn candidates(refuse: usize, msg: &[u8], extra: &[u8]) -> (bool, std::vec::Vec<[u8; 32]>, [u8; 64]) {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    NONCES.lock().unwrap().clear();
    REFUSE_FIRST.store(refuse, Ordering::SeqCst);
    let mut sig = Secret::<64>::zero();
    let ok = sign_rfc6979(recording_sign, &mut sig, msg, &TLS_PRIVATE, extra);
    (ok, NONCES.lock().unwrap().clone(), *sig.as_bytes())
}

use rfc6979::bigint::U256;
use sha2::{Digest, Sha256};

const N: U256 = U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

/// RustCrypto's generator: its first `count` candidates for (x, h, k').
fn reference_ks(x: &[u8; 32], h: &[u8; 32], extra: &[u8], count: usize) -> std::vec::Vec<[u8; 32]> {
    let mut g = rfc6979::KGenerator::<Sha256, U256>::new(x, h, extra, &N);
    (0..count)
        .map(|_| {
            let mut k = [0u8; 32];
            g.fill_next_k(&mut k);
            k
        })
        .collect()
}

#[test]
fn rfc6979_a_2_5_nonce_is_the_first_candidate() {
    let (ok, ks, _) = candidates(0, b"sample", &[]);
    assert!(ok);
    assert_eq!(ks, [hex32("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")]);
}

/// The step h.3 branch: a candidate the sign function refuses moves the
/// DRBG on, and the next candidate is the reference generator's second.
#[test]
fn a_refused_candidate_continues_with_the_next_drbg_output() {
    let extra = [0x5a; 32];
    let msg = b"forced rejection";
    let (ok, ks, sig) = candidates(1, msg, &extra);
    assert!(ok);
    let h: [u8; 32] = Sha256::digest(msg).into();
    assert_eq!(ks, reference_ks(&TLS_PRIVATE, &h, &extra, 2));
    assert!(verify(msg, &sig));
}

/// S-N4, F-N6: at most `MAX_NONCE_CANDIDATES`, then a failure with the
/// signature wiped.
#[test]
fn a_sign_function_that_keeps_refusing_stops_at_the_candidate_cap() {
    let (ok, ks, sig) = candidates(usize::MAX, b"cap", &[1; 32]);
    assert!(!ok);
    assert_eq!(ks.len(), MAX_NONCE_CANDIDATES);
    assert_eq!(MAX_NONCE_CANDIDATES, 8);
    assert_eq!(sig, [0; 64]);
    let h: [u8; 32] = Sha256::digest(b"cap").into();
    assert_eq!(ks, reference_ks(&TLS_PRIVATE, &h, &[1; 32], MAX_NONCE_CANDIDATES));
}

#[test]
fn tls_sign_answers_a_crypto_error_when_every_candidate_is_refused() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [u64::MAX; MAX_WORDS];
    fn never(_: &mut [u8; 64], _: &[u8], _: &[u8; 32], _: &[u8; 32]) -> bool {
        false
    }
    assert_eq!(o.tls_sign(never, &mut rndr(), &pack32(&[1; 32]), &mut reply), Err(ERR_CRYPTO));
}

/// splitmix64: reproducible test inputs (no OS randomness in crates/, P8).
struct Mix(u64);

impl Mix {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *b = (z ^ (z >> 31)) as u8;
        }
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
}

/// h mod n with RustCrypto's big integers: the reduction computed apart
/// from `bits2octets`.
fn reduced(h: &[u8; 32]) -> [u8; 32] {
    let v = U256::from_be_slice(h);
    let r = if v >= N { v.wrapping_sub(&N) } else { v };
    r.to_be_bytes().into()
}

fn our_ks(x: &[u8; 32], h: &[u8; 32], extra: &[u8], count: usize) -> std::vec::Vec<[u8; 32]> {
    let mut d = Drbg::new(x, &bits2octets(h), extra).unwrap();
    let mut k = Secret::<32>::zero();
    (0..count)
        .map(|i| {
            if i > 0 {
                d.reject().unwrap();
            }
            d.candidate(&mut k).unwrap();
            *k.as_bytes()
        })
        .collect()
}

/// S-N4: the DRBG against RustCrypto's `rfc6979` over random keys, hashes
/// and k' values, and hashes at and above n (whose reduction is checked
/// against an independent one first).
#[test]
fn the_drbg_matches_rustcrypto_rfc6979_over_random_inputs_and_hashes_at_or_above_n() {
    let mut m = Mix(0x6979);
    let n = N.to_be_bytes();
    let mut hashes: std::vec::Vec<[u8; 32]> = (0..64).map(|_| m.bytes32()).collect();
    hashes.push(n.into());
    hashes.push([0xff; 32]);
    let mut above = [0u8; 32];
    above.copy_from_slice(&n);
    above[31] = above[31].wrapping_add(1);
    hashes.push(above);
    for _ in 0..8 {
        // Above n: n's top 32 bits are all ones and its next 32 all zeros.
        let mut h = m.bytes32();
        h[..4].copy_from_slice(&[0xff; 4]);
        h[4] |= 1;
        assert!(U256::from_be_slice(&h) > N);
        hashes.push(h);
    }
    for h in &hashes {
        assert_eq!(bits2octets(h), reduced(h), "bits2octets({h:02x?})");
        let x = loop {
            let x = m.bytes32();
            if U256::from_be_slice(&x) < N && x != [0; 32] {
                break x;
            }
        };
        let mut extra = [0u8; 32];
        m.fill(&mut extra);
        for e in [&extra[..], &[][..]] {
            assert_eq!(our_ks(&x, h, e, 3), reference_ks(&x, h, e, 3), "x {x:02x?} h {h:02x?}");
        }
    }
}
