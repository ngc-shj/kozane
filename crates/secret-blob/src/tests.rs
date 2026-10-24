#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

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
fn offsets_are_the_documented_layout() {
    // Pinned numerically: tests/integration/run.py slices blob files by them.
    assert_eq!([GATEWAY_PRIVATE_AT, BOOT_SEED_AT, FIXED], [16, 48, 80]);
    let r = sample();
    assert_eq!(&r[8..12], &2u32.to_le_bytes());
    assert_eq!(&r[GATEWAY_PRIVATE_AT..BOOT_SEED_AT], &[1; 32]);
    assert_eq!(&r[BOOT_SEED_AT..FIXED], &[2; 32]);
    assert_eq!(&r[FIXED..FIXED + 32], &blake2s(&[&[3u8; 32]]));
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

/// A well-formed version 3 region (M6 slice 2): a TLS scalar after the
/// boot seed.
fn v3_region() -> [u8; REGION_SIZE] {
    let mut r = [0u8; REGION_SIZE];
    let mut body = std::vec::Vec::new();
    body.extend_from_slice(&MAGIC);
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[2; 32]);
    body.extend_from_slice(&[6; 32]);
    body.extend_from_slice(&blake2s(&[&[3u8; 32]]));
    let sum = blake2s(&[&body]);
    body.extend_from_slice(&sum);
    r[..body.len()].copy_from_slice(&body);
    r
}

#[test]
fn version_3_region_with_a_tls_scalar_is_refused() {
    // The TLS key has its own blob (M6 plan C12); `key` holds none.
    assert_eq!(Blob::parse(&v3_region(), 1).err(), Some(BlobError::BadVersion));
    // Allow side: the same fields without the scalar parse as version 2.
    let mut r = [0u8; REGION_SIZE];
    write(&mut r, &[1; 32], &[2; 32], &[[3; 32]]).unwrap();
    assert!(Blob::parse(&r, 1).is_ok());
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
    // v2 dropped the per-peer PSK: one peer more adds exactly one hash.
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
    assert_eq!(MAX_PEERS, 124);
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

mod tls_blob {
    extern crate std;

    use super::super::tls::*;
    use super::super::{BlobError, blake2s};

    fn sample() -> [u8; REGION_SIZE] {
        let mut out = [0u8; REGION_SIZE];
        assert_eq!(write(&mut out, &[0x61; 32], &[0x62; 32]), Some(USED_LEN));
        out
    }

    #[test]
    fn round_trip_exposes_fields() {
        let r = sample();
        let b = Blob::parse(&r).unwrap();
        assert_eq!(b.tls_private(), &[0x61; 32]);
        assert_eq!(b.boot_seed(), &[0x62; 32]);
    }

    #[test]
    fn offsets_are_the_documented_layout() {
        // Pinned numerically: tests/integration/run.py slices blob files by
        // them, and tools/package checks the checksum at CHECKSUM_AT.
        assert_eq!([TLS_PRIVATE_AT, BOOT_SEED_AT, CHECKSUM_AT, USED_LEN], [16, 48, 80, 112]);
        let r = sample();
        assert_eq!(&r[..8], b"SOSTLSK1");
        assert_eq!(&r[8..12], &1u32.to_le_bytes());
        assert_eq!(&r[12..16], &[0; 4]);
        assert_eq!(&r[TLS_PRIVATE_AT..BOOT_SEED_AT], &[0x61; 32]);
        assert_eq!(&r[BOOT_SEED_AT..CHECKSUM_AT], &[0x62; 32]);
        assert_eq!(&r[CHECKSUM_AT..USED_LEN], &blake2s(&[&r[..CHECKSUM_AT]]));
        assert!(r[USED_LEN..].iter().all(|b| *b == 0));
    }

    #[test]
    fn each_validation_failure_has_its_own_error() {
        let mut r = sample();
        r[0] ^= 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadMagic));
        for version in [0u32, 2] {
            let mut r = sample();
            r[8..12].copy_from_slice(&version.to_le_bytes());
            assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadVersion), "version {version}");
        }
        let mut r = sample();
        r[12] = 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadVersion), "reserved");
        let mut r = sample();
        r[TLS_PRIVATE_AT + 5] ^= 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadChecksum));
        let mut r = sample();
        r[REGION_SIZE - 1] = 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::NonZeroPadding));
        assert_eq!(Blob::parse(&r[..REGION_SIZE - 1]).err(), Some(BlobError::TooSmall));
        assert_eq!(Blob::parse(&[0u8; REGION_SIZE]).err(), Some(BlobError::BadMagic));
    }

    #[test]
    fn magics_keep_the_tls_and_key_blobs_apart() {
        // Both regions are 4096 bytes: only the magic tells them apart.
        let tls = sample();
        assert_eq!(super::super::Blob::parse(&tls, 1).err(), Some(BlobError::BadMagic));
        assert_eq!(Blob::parse(&super::sample()).err(), Some(BlobError::BadMagic));
    }
}

extern crate std;

/// tools/package re-implements the three layouts in Python; it is checked
/// here so either side drifting fails `unit`, not only a packaged boot.
#[test]
fn tools_package_mirrors_the_blob_layouts() {
    let package = include_str!("../../../tools/package");
    let ascii = |m: &[u8; 8]| std::string::String::from_utf8(m.to_vec()).unwrap();
    let key = std::format!(
        "KEY = BlobKind(\"secrets\", b\"{}\", {}, {}, _key_body)",
        ascii(&crate::MAGIC),
        crate::VERSION,
        crate::REGION_SIZE
    );
    let pq = std::format!(
        "PQ = BlobKind(\"pq_secrets\", b\"{}\", {}, {}, lambda _blob: {})",
        ascii(&crate::pq::MAGIC),
        crate::pq::VERSION,
        crate::pq::REGION_SIZE,
        crate::pq::CHECKSUM_OFFSET
    );
    // The TLS blob's checksum covers a fixed body (M6 plan C12).
    let tls = std::format!(
        "TLS = BlobKind(\"tls_secrets\", b\"{}\", {}, {}, lambda _blob: {})",
        ascii(&crate::tls::MAGIC),
        crate::tls::VERSION,
        crate::tls::REGION_SIZE,
        crate::tls::CHECKSUM_AT
    );
    assert!(package.contains(&key), "tools/package does not declare: {key}");
    assert!(package.contains(&pq), "tools/package does not declare: {pq}");
    assert!(package.contains(&tls), "tools/package does not declare: {tls}");
}

/// The number after `prefix` in tools/package's text, up to `end`.
fn package_number(package: &str, prefix: &str, end: &str) -> usize {
    let at = package.find(prefix).unwrap_or_else(|| panic!("tools/package has no {prefix:?}")) + prefix.len();
    let rest = &package[at..];
    rest[..rest.find(end).unwrap()].trim().parse().unwrap_or_else(|e| panic!("{prefix:?}: {e}"))
}

/// tools/package's `_key_body` (the length its checksum check covers) must
/// equal the body Rust writes, for several peer counts up to both limits:
/// its formula's constants are read from the script and evaluated here.
#[test]
fn tools_package_key_body_matches_the_written_body_for_several_peer_counts() {
    let package = include_str!("../../../tools/package");
    let fixed = package_number(package, "    return ", " + ");
    let per_peer = package_number(package, &std::format!("    return {fixed} + "), " * peers if 1 <= peers <= KEY_MAX_PEERS else None");
    let max_fixed = package_number(package, "KEY_MAX_PEERS = (4096 - ", " - 32) // 32");
    assert_eq!(max_fixed, fixed, "KEY_MAX_PEERS and _key_body disagree on the fixed part");
    let py_max_peers = (REGION_SIZE - max_fixed - CHECKSUM) / PER_PEER;
    assert_eq!(py_max_peers, MAX_PEERS);
    for peers in [1usize, 2, 3, 8, 110, MAX_PEERS] {
        let mut r = [0u8; REGION_SIZE];
        let publics = std::vec![[7u8; 32]; peers];
        let used = write(&mut r, &[1; 32], &[2; 32], &publics).unwrap();
        assert_eq!(used - CHECKSUM, fixed + per_peer * peers, "{peers} peers");
        assert_eq!(body_len(peers), fixed + per_peer * peers, "{peers} peers");
    }
}
