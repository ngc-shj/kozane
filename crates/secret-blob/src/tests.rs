#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

fn sample() -> [u8; REGION_SIZE] {
    let mut out = [0u8; REGION_SIZE];
    assert_eq!(write(&mut out, &[1; 32], &[2; 32]), Some(USED_LEN));
    out
}

#[test]
fn round_trip_exposes_fields() {
    let r = sample();
    let b = Blob::parse(&r).unwrap();
    assert_eq!(b.gateway_private(), &[1; 32]);
    assert_eq!(b.boot_seed(), &[2; 32]);
}

#[test]
fn offsets_are_the_documented_layout() {
    // Pinned numerically: tests/integration/run.py slices blob files by them.
    assert_eq!([GATEWAY_PRIVATE_AT, BOOT_SEED_AT, CHECKSUM_AT, USED_LEN], [16, 48, 80, 112]);
    let r = sample();
    assert_eq!(&r[8..12], &4u32.to_le_bytes());
    assert_eq!(&r[12..16], &[0; 4]);
    assert_eq!(&r[GATEWAY_PRIVATE_AT..BOOT_SEED_AT], &[1; 32]);
    assert_eq!(&r[BOOT_SEED_AT..CHECKSUM_AT], &[2; 32]);
    assert_eq!(&r[CHECKSUM_AT..USED_LEN], &blake2s(&[&r[..CHECKSUM_AT]]));
    assert!(r[USED_LEN..].iter().all(|b| *b == 0));
}

#[test]
fn each_validation_failure_has_its_own_error() {
    let mut r = sample();
    r[0] ^= 1;
    assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadMagic));
    let mut r = sample();
    r[8] = 2;
    assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadVersion));
    let mut r = sample();
    r[12] = 1;
    assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadVersion));
    let mut r = sample();
    r[20] ^= 1; // gateway private key byte
    assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadChecksum));
    let mut r = sample();
    r[REGION_SIZE - 1] = 1;
    assert_eq!(Blob::parse(&r).err(), Some(BlobError::NonZeroPadding));
    assert_eq!(Blob::parse(&r[..100]).err(), Some(BlobError::TooSmall));
}

/// A well-formed region of an older version: `version`, a peer count of
/// one, both fixed secrets, `extra` after them (a TLS scalar in version 3,
/// a peer hash in 2, a hash and a static PSK in 1), then the checksum.
fn old_region(version: u32, extra: &[&[u8]]) -> [u8; REGION_SIZE] {
    let mut r = [0u8; REGION_SIZE];
    let mut body = std::vec::Vec::new();
    body.extend_from_slice(&MAGIC);
    body.extend_from_slice(&version.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[2; 32]);
    for e in extra {
        body.extend_from_slice(e);
    }
    let sum = blake2s(&[&body]);
    body.extend_from_slice(&sum);
    r[..body.len()].copy_from_slice(&body);
    r
}

/// M8 plan C7: version 2 bound the blob to the configured peers; the
/// peers come from the bundle now, so that binding is refused, not
/// ignored.
#[test]
fn version_2_region_with_peer_hashes_is_refused() {
    let hash = blake2s(&[&[3u8; 32]]);
    assert_eq!(Blob::parse(&old_region(2, &[&hash])).err(), Some(BlobError::BadVersion));
    // The same with this version's number, but its peer count in the
    // reserved word, is no version 4 either.
    assert_eq!(Blob::parse(&old_region(4, &[&hash])).err(), Some(BlobError::BadVersion));
}

#[test]
fn version_3_region_with_a_tls_scalar_is_refused() {
    // The TLS key has its own blob (M6 plan C12); `key` holds none.
    let hash = blake2s(&[&[3u8; 32]]);
    assert_eq!(Blob::parse(&old_region(3, &[&[6; 32], &hash])).err(), Some(BlobError::BadVersion));
}

#[test]
fn version_1_region_with_static_psks_is_refused() {
    let hash = blake2s(&[&[3u8; 32]]);
    assert_eq!(Blob::parse(&old_region(1, &[&hash, &[4; 32]])).err(), Some(BlobError::BadVersion));
}

#[test]
fn all_zero_region_is_rejected() {
    // The placeholder in the published image must never validate.
    assert_eq!(Blob::parse(&[0u8; REGION_SIZE]).err(), Some(BlobError::BadMagic));
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
        assert_eq!(super::super::Blob::parse(&r[..super::super::REGION_SIZE]).err(), Some(BlobError::BadMagic));
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
        assert_eq!(super::super::Blob::parse(&tls).err(), Some(BlobError::BadMagic));
        assert_eq!(Blob::parse(&super::sample()).err(), Some(BlobError::BadMagic));
    }
}

mod audit_blob {
    extern crate std;

    use super::super::audit::*;
    use super::super::{BlobError, blake2s};

    fn sample() -> [u8; REGION_SIZE] {
        let mut out = [0u8; REGION_SIZE];
        assert_eq!(write(&mut out, &[0x71; 32]), Some(USED_LEN));
        out
    }

    #[test]
    fn round_trip_exposes_the_seed() {
        let r = sample();
        assert_eq!(Blob::parse(&r).unwrap().seed(), &[0x71; 32]);
    }

    #[test]
    fn offsets_are_the_documented_layout() {
        // Pinned numerically: tools/package checks the checksum at
        // CHECKSUM_AT.
        assert_eq!([SEED_AT, CHECKSUM_AT, USED_LEN], [16, 48, 80]);
        let r = sample();
        assert_eq!(&r[..8], b"SOSAUDK1");
        assert_eq!(&r[8..12], &1u32.to_le_bytes());
        assert_eq!(&r[12..16], &[0; 4]);
        assert_eq!(&r[SEED_AT..CHECKSUM_AT], &[0x71; 32]);
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
        r[SEED_AT + 5] ^= 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::BadChecksum));
        let mut r = sample();
        r[REGION_SIZE - 1] = 1;
        assert_eq!(Blob::parse(&r).err(), Some(BlobError::NonZeroPadding));
        assert_eq!(Blob::parse(&r[..REGION_SIZE - 1]).err(), Some(BlobError::TooSmall));
        assert_eq!(Blob::parse(&[0u8; REGION_SIZE]).err(), Some(BlobError::BadMagic));
    }

    #[test]
    fn magics_keep_the_audit_and_other_4k_blobs_apart() {
        // The key, TLS and audit regions are all 4096 bytes: only the magic
        // tells them apart.
        let audit = sample();
        assert_eq!(super::super::Blob::parse(&audit).err(), Some(BlobError::BadMagic));
        assert_eq!(super::super::tls::Blob::parse(&audit).err(), Some(BlobError::BadMagic));
        assert_eq!(Blob::parse(&super::sample()).err(), Some(BlobError::BadMagic));
    }
}

extern crate std;

/// tools/package re-implements the four layouts in Python; it is checked
/// here so either side drifting fails `unit`, not only a packaged boot.
#[test]
fn tools_package_mirrors_the_blob_layouts() {
    let package = include_str!("../../../tools/package");
    let ascii = |m: &[u8; 8]| std::string::String::from_utf8(m.to_vec()).unwrap();
    // The key blob's checksum covers a fixed body too (M8 plan C7).
    let key = std::format!(
        "KEY = BlobKind(\"secrets\", b\"{}\", {}, {}, lambda _blob: {})",
        ascii(&crate::MAGIC),
        crate::VERSION,
        crate::REGION_SIZE,
        crate::CHECKSUM_AT
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
    let audit = std::format!(
        "AUDIT = BlobKind(\"audit_secrets\", b\"{}\", {}, {}, lambda _blob: {})",
        ascii(&crate::audit::MAGIC),
        crate::audit::VERSION,
        crate::audit::REGION_SIZE,
        crate::audit::CHECKSUM_AT
    );
    assert!(package.contains(&key), "tools/package does not declare: {key}");
    assert!(package.contains(&audit), "tools/package does not declare: {audit}");
    assert!(package.contains(&pq), "tools/package does not declare: {pq}");
    assert!(package.contains(&tls), "tools/package does not declare: {tls}");
}
