//! `auditkey`'s secrets blob (M8 plan C10, D7): the Ed25519 seed that signs
//! the audit stream's checkpoints. Its own region and envelope (kind
//! `audit`), apart from every other key PD's.
//!
//! Layout, version 1 (little-endian), at the offsets named below:
//!   magic[8] = "SOSAUDK1" | version u32 = 1 | reserved u32 = 0
//!   seed[32]          the Ed25519 private key (RFC 8032 §5.1.5's seed)
//!   checksum[32]      BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are
//! zero. No public key is stored: `auditkey` derives it, and `tools/package`
//! exports it for the verifier.

use crate::{BlobError, Writer, check_sealed, field, u32_at};

pub const MAGIC: [u8; 8] = *b"SOSAUDK1";
pub const VERSION: u32 = 1;
pub const REGION_SIZE: usize = 4096;

pub const SEED_AT: usize = 8 + 4 + 4;
pub const CHECKSUM_AT: usize = SEED_AT + 32;
/// Bytes in use; the rest of the region is zero.
pub const USED_LEN: usize = CHECKSUM_AT + 32;

const _: () = assert!(USED_LEN <= REGION_SIZE);

/// A validated view of the region. Borrowed; the seed is not copied.
pub struct Blob<'a> {
    bytes: &'a [u8],
}

impl<'a> Blob<'a> {
    /// Validates magic, version and reserved word (a reserved word other
    /// than zero is a version this parser does not know), checksum and zero
    /// padding.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BlobError> {
        if bytes.len() < REGION_SIZE {
            return Err(BlobError::TooSmall);
        }
        if field::<8>(bytes, 0) != Some(&MAGIC) {
            return Err(BlobError::BadMagic);
        }
        if u32_at(bytes, 8) != Some(VERSION) || u32_at(bytes, 12) != Some(0) {
            return Err(BlobError::BadVersion);
        }
        check_sealed(bytes, CHECKSUM_AT)?;
        Ok(Self { bytes })
    }

    /// The Ed25519 seed.
    pub fn seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, SEED_AT).unwrap_or(&[0; 32])
    }
}

/// Writes a region. Returns the number of bytes used before zero padding.
pub fn write(out: &mut [u8; REGION_SIZE], seed: &[u8; 32]) -> Option<usize> {
    out.fill(0);
    let mut w = Writer { out, at: 0 };
    w.put(&MAGIC)?;
    w.put(&VERSION.to_le_bytes())?;
    w.put(&0u32.to_le_bytes())?;
    w.put(seed)?;
    w.seal()
}
