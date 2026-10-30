//! Formats of the secrets memory regions (law L6): the only place static
//! secrets exist at run time. There are three blobs with distinct magics,
//! each mapped into its own key PD alone (law L2): `key`'s WireGuard blob
//! (this module), `pqkey`'s McEliece blob ([`pq`]) and `tlskey`'s TLS
//! signing key ([`tls`], M6 plan C12). Shared by the key PDs (validation),
//! `mksecrets` (writing) and the config checks, so each layout is defined
//! once.
//!
//! `key` layout, version 4 (little-endian; M8 plan C7's "v3"):
//!   magic[8] = "SOSSECR1" | version u32 = 4 | reserved u32 = 0
//!   gateway_private[32] | boot_seed[32]
//!   checksum[32] = BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are
//! zero. Version 1 carried a static PSK per peer; it is refused (M3 plan C2,
//! L8: WireGuard PSKs come only from Rosenpass). Version 3 (M6 slice 2)
//! carried the TLS scalar, which now has its own blob; it is refused too,
//! and its number is not reused. Version 2 bound the blob to the peers'
//! keys (a hash each); the peers now come from the signed bundle (M8 plan
//! D4, C7), so a policy update never needs a re-seal, and it is refused.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod pq;
pub mod tls;

pub const MAGIC: [u8; 8] = *b"SOSSECR1";
pub const VERSION: u32 = 4;
pub const REGION_SIZE: usize = 4096;
const HEADER: usize = 8 + 4 + 4;
/// Byte offsets of the fixed secrets, pinned numerically by the tests (the
/// integration harness reads them from a blob file).
pub const GATEWAY_PRIVATE_AT: usize = HEADER;
pub const BOOT_SEED_AT: usize = GATEWAY_PRIVATE_AT + 32;
pub const CHECKSUM_AT: usize = BOOT_SEED_AT + 32;
const CHECKSUM: usize = 32;
/// Bytes in use; the rest of the region is zero.
pub const USED_LEN: usize = CHECKSUM_AT + CHECKSUM;

const _: () = assert!(USED_LEN <= REGION_SIZE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    BadMagic,
    BadVersion,
    BadChecksum,
    NonZeroPadding,
    TooSmall,
}

impl BlobError {
    /// Stable text for the boot log, one per failure (plan C10).
    pub const fn message(self) -> &'static str {
        match self {
            BlobError::BadMagic => "secrets: bad magic",
            BlobError::BadVersion => "secrets: unsupported version",
            BlobError::BadChecksum => "secrets: checksum mismatch",
            BlobError::NonZeroPadding => "secrets: non-zero padding",
            BlobError::TooSmall => "secrets: region too small",
        }
    }
}

pub fn blake2s(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = libcrux_blake2::Blake2sBuilder::new_unkeyed().build_const_digest_len::<32>();
    for p in parts {
        // Inputs here are bounded by a McEliece public key (512 KiB), far
        // below the 4 GiB chunk limit, the only error `update` reports.
        let _ = h.update(p);
    }
    h.finalize(&mut out);
    out
}

/// A validated view of the region. Borrowed; secrets are not copied.
pub struct Blob<'a> {
    bytes: &'a [u8],
}

fn field<const N: usize>(b: &[u8], at: usize) -> Option<&[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    field::<4>(b, at).map(|f| u32::from_le_bytes(*f))
}

/// Checksum over `bytes[..body]`, stored right after it, then zero padding.
fn check_sealed(bytes: &[u8], body: usize) -> Result<(), BlobError> {
    let data = bytes.get(..body).ok_or(BlobError::TooSmall)?;
    let stored = field::<32>(bytes, body).ok_or(BlobError::TooSmall)?;
    if blake2s(&[data]) != *stored {
        return Err(BlobError::BadChecksum);
    }
    let rest = bytes.get(body.saturating_add(CHECKSUM)..).ok_or(BlobError::TooSmall)?;
    if rest.iter().any(|b| *b != 0) {
        return Err(BlobError::NonZeroPadding);
    }
    Ok(())
}

/// Sequential writer over a zeroed region; every step is bounds-checked.
struct Writer<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, data: &[u8]) -> Option<()> {
        let end = self.at.checked_add(data.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(data);
        self.at = end;
        Some(())
    }

    /// Appends the checksum of everything written so far; returns the bytes used.
    fn seal(mut self) -> Option<usize> {
        let sum = blake2s(&[self.out.get(..self.at)?]);
        self.put(&sum)?;
        Some(self.at)
    }
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

    pub fn gateway_private(&self) -> &[u8; 32] {
        field::<32>(self.bytes, GATEWAY_PRIVATE_AT).unwrap_or(&[0; 32])
    }

    pub fn boot_seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, BOOT_SEED_AT).unwrap_or(&[0; 32])
    }
}

/// Writes a region. Returns the number of bytes used before zero padding.
pub fn write(out: &mut [u8; REGION_SIZE], gateway_private: &[u8; 32], boot_seed: &[u8; 32]) -> Option<usize> {
    out.fill(0);
    let mut w = Writer { out, at: 0 };
    w.put(&MAGIC)?;
    w.put(&VERSION.to_le_bytes())?;
    w.put(&0u32.to_le_bytes())?;
    w.put(gateway_private)?;
    w.put(boot_seed)?;
    w.seal()
}

#[cfg(test)]
mod tests;
