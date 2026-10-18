#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

const GW_PRIVATE: [u8; 32] = [0x11; 32];
const PEER_PRIVATE: [u8; 32] = [0x22; 32];
const PSKS: [[u8; 32]; 2] = [[0xa1; 32], [0xa2; 32]];
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
    secret_blob::write(&mut r, clamped(GW_PRIVATE).as_bytes(), &[0x99; 32], &[(p[0], PSKS[0]), (p[1], PSKS[1])]).unwrap();
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
    // Every BlobError, walked through an exhaustive successor match: a new
    // variant fails to compile until it gets an arm, and its arm must name
    // a successor (or end the walk), so leaving it out of the comparison
    // takes a deliberately wrong arm rather than a forgotten line.
    let next = |e: BlobError| match e {
        BlobError::BadMagic => Some(BlobError::BadVersion),
        BlobError::BadVersion => Some(BlobError::BadPeerCount),
        BlobError::BadPeerCount => Some(BlobError::BadChecksum),
        BlobError::BadChecksum => Some(BlobError::NonZeroPadding),
        BlobError::NonZeroPadding => Some(BlobError::TooSmall),
        BlobError::TooSmall => None,
    };
    let mut all = [BootError::GatewayKeyMismatch; 8];
    all[1] = BootError::PeerMismatch;
    let mut n = 2;
    let mut e = Some(BlobError::BadMagic);
    while let Some(v) = e {
        all[n] = BootError::Blob(v);
        n += 1;
        e = next(v);
    }
    assert_eq!(n, all.len(), "every BlobError compared");
    // The walk visits every variant, and BootError has exactly the three
    // kinds listed: a variant missing from either fails here.
    assert_eq!(n - 2, core::mem::variant_count::<BlobError>());
    assert_eq!(core::mem::variant_count::<BootError>(), 3);
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.message(), b.message());
        }
    }
}

#[test]
fn static_dh_matches_the_peer_side_computation() {
    let r = region();
    let o = oracle(&r);
    let peer_pub = peer_publics()[0];
    let mut reply = [0u64; MAX_WORDS];
    let (label, n) = o.handle(&mut bucket(), 0, LABEL_STATIC_DH, &pack32(&peer_pub), &mut reply);
    assert_eq!((label, n), (OK, STATIC_DH_REPLY_WORDS));
    let expected = crypto::dh(&clamped(PEER_PRIVATE), &gw_public()).unwrap();
    assert_eq!(unpack32(&reply[..4]).unwrap(), *expected.as_bytes());
}

#[test]
fn low_order_point_is_refused_and_reply_zeroed() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(o.handle(&mut bucket(), 0, LABEL_STATIC_DH, &[0; 4], &mut reply), (ERR_ZERO_DH, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

#[test]
fn psk_mix_is_kdf3_of_the_chaining_key_and_that_peers_psk() {
    let r = region();
    let o = oracle(&r);
    let c = [0x77u8; 32];
    let mut req = [0u64; PSK_MIX_REQ_WORDS];
    req[0] = 1;
    req[1..].copy_from_slice(&pack32(&c));
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(&mut bucket(), 0, LABEL_PSK_MIX, &req, &mut reply), (OK, PSK_MIX_REPLY_WORDS));
    let (c2, tau, kappa) = crypto::kdf3(&Key32::from_bytes(c), &PSKS[1]).unwrap();
    assert_eq!(unpack32(&reply[0..4]).unwrap(), *c2.as_bytes());
    assert_eq!(unpack32(&reply[4..8]).unwrap(), *tau.as_bytes());
    assert_eq!(unpack32(&reply[8..12]).unwrap(), *kappa.as_bytes());
}

#[test]
fn psk_mix_for_an_unknown_peer_is_refused() {
    let r = region();
    let o = oracle(&r);
    let mut req = [0u64; PSK_MIX_REQ_WORDS];
    req[0] = 2;
    assert_eq!(o.handle(&mut bucket(), 0, LABEL_PSK_MIX, &req, &mut [0; MAX_WORDS]), (ERR_UNKNOWN_PEER, 0));
}

#[test]
fn boot_seed_returns_the_per_boot_value() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(o.handle(&mut bucket(), 0, LABEL_BOOT_SEED, &[], &mut reply), (OK, BOOT_SEED_REPLY_WORDS));
    assert_eq!(unpack32(&reply[..4]).unwrap(), SEED);
}

#[test]
fn wrong_sizes_and_unknown_labels_are_bad_requests() {
    let r = region();
    let o = oracle(&r);
    let mut reply = [0u64; MAX_WORDS];
    let mut b = bucket();
    assert_eq!(o.handle(&mut b, 0, LABEL_STATIC_DH, &[0; 3], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(&mut b, 0, LABEL_STATIC_DH, &[0; 5], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(&mut b, 0, LABEL_PSK_MIX, &[0; 4], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(&mut b, 0, LABEL_BOOT_SEED, &[0], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(&mut b, 0, 0, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(o.handle(&mut b, 0, 99, &[0; 4], &mut reply), (ERR_BAD_REQUEST, 0));
}

#[test]
fn exhausted_bucket_refuses_until_refilled_and_bad_requests_cost_nothing() {
    let r = region();
    let o = oracle(&r);
    let mut b = Bucket::new(2, 1000);
    let mut reply = [0u64; MAX_WORDS];
    for _ in 0..10 {
        assert_eq!(o.handle(&mut b, 0, 99, &[], &mut reply).0, ERR_BAD_REQUEST);
    }
    assert_eq!(o.handle(&mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(&mut b, 0, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(o.handle(&mut b, 0, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(o.handle(&mut b, 1000, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

#[test]
fn pack_and_unpack_round_trip() {
    let v: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(unpack32(&pack32(&v)), Some(v));
}
