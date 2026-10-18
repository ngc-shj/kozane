#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]

use super::*;

fn sample() -> [u8; REGION_SIZE] {
    let mut out = [0u8; REGION_SIZE];
    write(&mut out, &[1; 32], &[2; 32], &[([3; 32], [4; 32]), ([5; 32], [6; 32])]).unwrap();
    out
}

#[test]
fn round_trip_exposes_fields() {
    let r = sample();
    let b = Blob::parse(&r, 2).unwrap();
    assert_eq!(b.gateway_private(), &[1; 32]);
    assert_eq!(b.boot_seed(), &[2; 32]);
    assert_eq!(b.peer(1), Some((&blake2s(&[&[5u8; 32]]), &[6u8; 32])));
    assert_eq!(b.peer(2), None);
}

#[test]
fn each_validation_failure_has_its_own_error() {
    let mut r = sample();
    r[0] ^= 1;
    assert_eq!(Blob::parse(&r, 2).err(), Some(BlobError::BadMagic));
    let mut r = sample();
    r[8] = 2;
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

extern crate std;
