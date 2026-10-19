//! `pqkey`'s secrets blob (M3 plan C2, law L6): the gateway's Classic
//! McEliece 460896 (round 3) secret key and the data that binds it to the
//! configured public key.
//!
//! Layout, version 1 (little-endian), at the offsets named below:
//!   magic[8] = "SOSPQKY1" | version u32 = 1
//!   secret_key[13608]      cmr layout (classic-mceliece-rust 2.0.2)
//!   spkm_hash[32]          BLAKE2s-256(gateway McEliece public key)
//!   kat_ct[188]            a ciphertext encapsulated to that public key
//!   kat_shk_hash[32]       BLAKE2s-256(its shared key)
//!   blob_seed[32]          independent of `key`'s boot seed
//!   checksum[32]           BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are
//! zero.

use crate::{BlobError, Writer, check_sealed, field, u32_at};

pub const MAGIC: [u8; 8] = *b"SOSPQKY1";
pub const VERSION: u32 = 1;
pub const REGION_SIZE: usize = 16384;

/// Classic McEliece 460896 round 3 sizes (the review's feasibility facts;
/// pqkey-core asserts them against the crate).
pub const PK_LEN: usize = 524_160;
pub const SK_LEN: usize = 13_608;
pub const CT_LEN: usize = 188;
pub const SHK_LEN: usize = 32;
/// The secret key as liboqs 0.8 (upstream rosenpass's `pqsk`) stores it.
pub const LIBOQS_SK_LEN: usize = 13_568;

/// cmr's leading bytes, which liboqs omits and decapsulation never reads.
const CMR_PREFIX_LEN: usize = SK_LEN - LIBOQS_SK_LEN;
/// The trailing part of a cmr key, which liboqs stores first:
/// `cmr = [0; 40] ‖ oqs[576..] ‖ oqs[..576]` (verified both ways against
/// liboqs in the feasibility study).
const MOVED_LEN: usize = 576;

pub const SK_OFFSET: usize = 8 + 4;
pub const SPKM_HASH_OFFSET: usize = SK_OFFSET + SK_LEN;
pub const KAT_CT_OFFSET: usize = SPKM_HASH_OFFSET + 32;
pub const KAT_SHK_HASH_OFFSET: usize = KAT_CT_OFFSET + CT_LEN;
pub const BLOB_SEED_OFFSET: usize = KAT_SHK_HASH_OFFSET + 32;
pub const CHECKSUM_OFFSET: usize = BLOB_SEED_OFFSET + 32;
/// Bytes in use; the rest of the region is zero.
pub const USED_LEN: usize = CHECKSUM_OFFSET + 32;

const _: () = assert!(USED_LEN <= REGION_SIZE);

/// A validated view of the region. Borrowed; the secret key is not copied.
pub struct Blob<'a> {
    bytes: &'a [u8],
}

impl<'a> Blob<'a> {
    /// Validates magic, version, checksum and zero padding.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BlobError> {
        if bytes.len() < REGION_SIZE {
            return Err(BlobError::TooSmall);
        }
        if field::<8>(bytes, 0) != Some(&MAGIC) {
            return Err(BlobError::BadMagic);
        }
        if u32_at(bytes, 8) != Some(VERSION) {
            return Err(BlobError::BadVersion);
        }
        check_sealed(bytes, CHECKSUM_OFFSET)?;
        Ok(Self { bytes })
    }

    /// The McEliece secret key, cmr layout. Callers copy it per use: cmr
    /// zeroizes the buffer it wraps on drop.
    pub fn secret_key(&self) -> &[u8; SK_LEN] {
        field::<SK_LEN>(self.bytes, SK_OFFSET).unwrap_or(&[0; SK_LEN])
    }

    pub fn spkm_hash(&self) -> &[u8; 32] {
        field::<32>(self.bytes, SPKM_HASH_OFFSET).unwrap_or(&[0; 32])
    }

    pub fn kat_ct(&self) -> &[u8; CT_LEN] {
        field::<CT_LEN>(self.bytes, KAT_CT_OFFSET).unwrap_or(&[0; CT_LEN])
    }

    pub fn kat_shk_hash(&self) -> &[u8; 32] {
        field::<32>(self.bytes, KAT_SHK_HASH_OFFSET).unwrap_or(&[0; 32])
    }

    pub fn blob_seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, BLOB_SEED_OFFSET).unwrap_or(&[0; 32])
    }
}

/// The fields of a `pqkey` blob, in layout order.
pub struct Fields<'f> {
    pub secret_key: &'f [u8; SK_LEN],
    pub spkm_hash: &'f [u8; 32],
    pub kat_ct: &'f [u8; CT_LEN],
    pub kat_shk_hash: &'f [u8; 32],
    pub blob_seed: &'f [u8; 32],
}

/// Writes a region. Returns the number of bytes used before zero padding.
pub fn write(out: &mut [u8; REGION_SIZE], f: &Fields<'_>) -> Option<usize> {
    out.fill(0);
    let mut w = Writer { out, at: 0 };
    w.put(&MAGIC)?;
    w.put(&VERSION.to_le_bytes())?;
    w.put(f.secret_key)?;
    w.put(f.spkm_hash)?;
    w.put(f.kat_ct)?;
    w.put(f.kat_shk_hash)?;
    w.put(f.blob_seed)?;
    w.seal()
}

/// Converts a liboqs-layout secret key (upstream `rp genkey`'s `pqsk`) to
/// the cmr layout. The 40-byte prefix is left zero.
pub fn cmr_sk_from_liboqs(out: &mut [u8; SK_LEN], oqs: &[u8; LIBOQS_SK_LEN]) {
    let (moved, rest) = oqs.split_at(MOVED_LEN);
    let (prefix, body) = out.split_at_mut(CMR_PREFIX_LEN);
    let (head, tail) = body.split_at_mut(rest.len());
    prefix.fill(0);
    head.copy_from_slice(rest);
    tail.copy_from_slice(moved);
}

/// Converts a cmr-layout secret key to the liboqs layout that upstream
/// rosenpass reads (M3 plan F19). The cmr prefix is dropped.
pub fn liboqs_sk_from_cmr(out: &mut [u8; LIBOQS_SK_LEN], cmr: &[u8; SK_LEN]) {
    let (_, body) = cmr.split_at(CMR_PREFIX_LEN);
    let (rest, moved) = body.split_at(body.len().saturating_sub(MOVED_LEN));
    let (head, tail) = out.split_at_mut(MOVED_LEN);
    head.copy_from_slice(moved);
    tail.copy_from_slice(rest);
}
