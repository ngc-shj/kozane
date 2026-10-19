#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]

use super::*;

fn sample() -> [u8; REGION_SIZE] {
    let mut out = [0u8; REGION_SIZE];
    write(&mut out, &[1; 32], &[2; 32], &[[3; 32], [5; 32]]).unwrap();
    out
}

#[test]
fn round_trip_exposes_fields() {
    let r = sample();
    let b = Blob::parse(&r, 2).unwrap();
    assert_eq!(b.gateway_private(), &[1; 32]);
    assert_eq!(b.boot_seed(), &[2; 32]);
    assert_eq!(b.peer(1), Some(&blake2s(&[&[5u8; 32]])));
    assert_eq!(b.peer(2), None);
}

#[test]
fn each_validation_failure_has_its_own_error() {
    let mut r = sample();
    r[0] ^= 1;
    assert_eq!(Blob::parse(&r, 2).err(), Some(BlobError::BadMagic));
    let mut r = sample();
    r[8] = 3;
    assert_eq!(Blob::parse(&r, 2).err(), Some(BlobError::BadVersion));
    assert_eq!(Blob::parse(&sample(), 3).err(), Some(BlobError::BadPeerCount));
    let mut r = sample();
    r[20] ^= 1; // gateway private key byte
    assert_eq!(Blob::parse(&r, 2).err(), Some(BlobError::BadChecksum));
    let mut r = sample();
    r[REGION_SIZE - 1] = 1;
    assert_eq!(Blob::parse(&r, 2).err(), Some(BlobError::NonZeroPadding));
    assert_eq!(Blob::parse(&r[..100], 2).err(), Some(BlobError::TooSmall));
}

/// A well-formed version 1 region: per-peer static PSKs after each hash.
fn v1_region() -> [u8; REGION_SIZE] {
    let mut r = [0u8; REGION_SIZE];
    let mut body = std::vec::Vec::new();
    body.extend_from_slice(&MAGIC);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[2; 32]);
    body.extend_from_slice(&blake2s(&[&[3u8; 32]]));
    body.extend_from_slice(&[4; 32]);
    let sum = blake2s(&[&body]);
    body.extend_from_slice(&sum);
    r[..body.len()].copy_from_slice(&body);
    r
}

#[test]
fn version_1_region_with_static_psks_is_refused() {
    assert_eq!(Blob::parse(&v1_region(), 1).err(), Some(BlobError::BadVersion));
}

#[test]
fn peer_entries_hold_only_the_key_hash() {
    // v2 drops the per-peer PSK: one peer more adds exactly one hash.
    let mut one = [0u8; REGION_SIZE];
    let mut two = [0u8; REGION_SIZE];
    let a = write(&mut one, &[1; 32], &[2; 32], &[[3; 32]]).unwrap();
    let b = write(&mut two, &[1; 32], &[2; 32], &[[3; 32], [5; 32]]).unwrap();
    assert_eq!(b - a, 32);
    assert_eq!(a, 8 + 4 + 4 + 32 + 32 + 32 + 32);
}

#[test]
fn writer_bounds_the_peer_count() {
    let mut r = [0u8; REGION_SIZE];
    assert_eq!(write(&mut r, &[1; 32], &[2; 32], &[]), None);
    let many = std::vec![[7u8; 32]; MAX_PEERS + 1];
    assert_eq!(write(&mut r, &[1; 32], &[2; 32], &many), None);
    assert!(write(&mut r, &[1; 32], &[2; 32], &many[..MAX_PEERS]).is_some());
}

#[test]
fn all_zero_region_is_rejected() {
    // The placeholder in the published image must never validate.
    assert_eq!(Blob::parse(&[0u8; REGION_SIZE], 1).err(), Some(BlobError::BadMagic));
}

#[test]
fn blake2s_matches_rfc7693_abc() {
    // RFC 7693 Appendix B: BLAKE2s-256("abc").
    let want = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
    let got: std::string::String = blake2s(&[b"abc"]).iter().map(|b| std::format!("{b:02x}")).collect();
    assert_eq!(got, want);
}

mod pq_blob {
    extern crate std;

    use super::super::pq::*;
    use super::super::{BlobError, blake2s};

    fn sk() -> [u8; SK_LEN] {
        core::array::from_fn(|i| (i % 251) as u8)
    }

    fn sample() -> std::boxed::Box<[u8; REGION_SIZE]> {
        let mut out = std::boxed::Box::new([0u8; REGION_SIZE]);
        let f = Fields {
            secret_key: &sk(),
            spkm_hash: &[0x11; 32],
            kat_ct: &[0x22; CT_LEN],
            kat_shk_hash: &[0x33; 32],
            blob_seed: &[0x44; 32],
        };
        assert_eq!(write(&mut out, &f), Some(USED_LEN));
        out
    }

    #[test]
    fn round_trip_exposes_fields() {
        let r = sample();
        let b = Blob::parse(&r[..]).unwrap();
        assert_eq!(b.secret_key(), &sk());
        assert_eq!(b.spkm_hash(), &[0x11; 32]);
        assert_eq!(b.kat_ct(), &[0x22; CT_LEN]);
        assert_eq!(b.kat_shk_hash(), &[0x33; 32]);
        assert_eq!(b.blob_seed(), &[0x44; 32]);
    }

    #[test]
    fn offsets_are_the_documented_layout() {
        // Pinned numerically, so a splice helper (fixture b) can rely on them.
        assert_eq!(
            [SK_OFFSET, SPKM_HASH_OFFSET, KAT_CT_OFFSET, KAT_SHK_HASH_OFFSET, BLOB_SEED_OFFSET, CHECKSUM_OFFSET, USED_LEN],
            [12, 13_620, 13_652, 13_840, 13_872, 13_904, 13_936]
        );
        let r = sample();
        assert_eq!(&r[..8], b"SOSPQKY1");
        assert_eq!(&r[SK_OFFSET..SK_OFFSET + SK_LEN], &sk()[..]);
        assert_eq!(&r[SPKM_HASH_OFFSET..KAT_CT_OFFSET], &[0x11; 32]);
        assert_eq!(&r[BLOB_SEED_OFFSET..CHECKSUM_OFFSET], &[0x44; 32]);
        assert_eq!(&r[CHECKSUM_OFFSET..USED_LEN], &blake2s(&[&r[..CHECKSUM_OFFSET]]));
        assert!(r[USED_LEN..].iter().all(|b| *b == 0));
    }

    #[test]
    fn each_validation_failure_has_its_own_error() {
        let mut r = sample();
        r[0] ^= 1;
        assert_eq!(Blob::parse(&r[..]).err(), Some(BlobError::BadMagic));
        let mut r = sample();
        r[8] = 2;
        assert_eq!(Blob::parse(&r[..]).err(), Some(BlobError::BadVersion));
        let mut r = sample();
        r[SK_OFFSET + 100] ^= 1;
        assert_eq!(Blob::parse(&r[..]).err(), Some(BlobError::BadChecksum));
        let mut r = sample();
        r[REGION_SIZE - 1] = 1;
        assert_eq!(Blob::parse(&r[..]).err(), Some(BlobError::NonZeroPadding));
        assert_eq!(Blob::parse(&r[..REGION_SIZE - 1]).err(), Some(BlobError::TooSmall));
    }

    #[test]
    fn magics_keep_the_two_blobs_apart() {
        let r = sample();
        assert_eq!(super::super::Blob::parse(&r[..super::super::REGION_SIZE], 1).err(), Some(BlobError::BadMagic));
        assert_eq!(Blob::parse(&std::vec![0u8; REGION_SIZE]).err(), Some(BlobError::BadMagic));
        let mut key = std::vec![0u8; REGION_SIZE];
        key[..super::super::REGION_SIZE].copy_from_slice(&super::sample());
        assert_eq!(Blob::parse(&key).err(), Some(BlobError::BadMagic));
    }

    #[test]
    fn liboqs_conversion_moves_the_trailing_576_bytes_and_round_trips() {
        let oqs: [u8; LIBOQS_SK_LEN] = core::array::from_fn(|i| (i % 253) as u8 ^ 0x5a);
        let mut cmr = [0xffu8; SK_LEN];
        cmr_sk_from_liboqs(&mut cmr, &oqs);
        assert_eq!(&cmr[..40], &[0; 40]);
        assert_eq!(&cmr[40..SK_LEN - 576], &oqs[576..]);
        assert_eq!(&cmr[SK_LEN - 576..], &oqs[..576]);
        let mut back = [0u8; LIBOQS_SK_LEN];
        liboqs_sk_from_cmr(&mut back, &cmr);
        assert_eq!(back, oqs);
    }
}

extern crate std;
