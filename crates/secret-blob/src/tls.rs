//! `tlskey`'s secrets blob (M6 plan C12, law L6): the HTTPS server's P-256
//! signing key and its own boot seed, drawn independently of `key`'s.
//!
//! Layout, version 1 (little-endian), at the offsets named below:
//!   magic[8] = "SOSTLSK1" | version u32 = 1 | reserved u32 = 0
//!   tls_private[32]   P-256 scalar, big-endian
//!   boot_seed[32]
//!   checksum[32]      BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are
//! zero. The scalar's validity and its match with the certificate are
//! `tlskey-core`'s checks, not the format's.

use crate::{BlobError, Writer, check_sealed, field, u32_at};

pub const MAGIC: [u8; 8] = *b"SOSTLSK1";
pub const VERSION: u32 = 1;
pub const REGION_SIZE: usize = 4096;

pub const TLS_PRIVATE_AT: usize = 8 + 4 + 4;
pub const BOOT_SEED_AT: usize = TLS_PRIVATE_AT + 32;
pub const CHECKSUM_AT: usize = BOOT_SEED_AT + 32;
/// Bytes in use; the rest of the region is zero.
pub const USED_LEN: usize = CHECKSUM_AT + 32;

const _: () = assert!(USED_LEN <= REGION_SIZE);

/// A validated view of the region. Borrowed; the scalar is not copied.
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

    /// The signing scalar, big-endian.
    pub fn tls_private(&self) -> &[u8; 32] {
        field::<32>(self.bytes, TLS_PRIVATE_AT).unwrap_or(&[0; 32])
    }

    pub fn boot_seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, BOOT_SEED_AT).unwrap_or(&[0; 32])
    }
}

/// Writes a region. Returns the number of bytes used before zero padding.
pub fn write(out: &mut [u8; REGION_SIZE], tls_private: &[u8; 32], boot_seed: &[u8; 32]) -> Option<usize> {
    out.fill(0);
    let mut w = Writer { out, at: 0 };
    w.put(&MAGIC)?;
    w.put(&VERSION.to_le_bytes())?;
    w.put(&0u32.to_le_bytes())?;
    w.put(tls_private)?;
    w.put(boot_seed)?;
    w.seal()
}
