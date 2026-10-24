//! Formats of the secrets memory regions (law L6): the only place static
//! secrets exist at run time. There are three blobs with distinct magics,
//! each mapped into its own key PD alone (law L2): `key`'s WireGuard blob
//! (this module), `pqkey`'s McEliece blob ([`pq`]) and `tlskey`'s TLS
//! signing key ([`tls`], M6 plan C12). Shared by the key PDs (validation),
//! `mksecrets` (writing) and the config checks, so each layout is defined
//! once.
//!
//! `key` layout, version 2 (little-endian):
//!   magic[8] = "SOSSECR1" | version u32 = 2 | peer_count u32
//!   gateway_private[32] | boot_seed[32]
//!   peer_count × peer_public_hash[32] = BLAKE2s-256(peer public key)
//!   checksum[32] = BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are
//! zero. Version 1 carried a static PSK per peer; it is refused (M3 plan C2,
//! L8: WireGuard PSKs come only from Rosenpass). Version 3 (M6 slice 2)
//! carried the TLS scalar, which now has its own blob; it is refused too.

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
pub const VERSION: u32 = 2;
pub const REGION_SIZE: usize = 4096;
const HEADER: usize = 8 + 4 + 4;
/// Byte offsets of the fixed secrets, pinned numerically by the tests (the
/// integration harness reads them from a blob file).
pub const GATEWAY_PRIVATE_AT: usize = HEADER;
pub const BOOT_SEED_AT: usize = GATEWAY_PRIVATE_AT + 32;
const FIXED: usize = BOOT_SEED_AT + 32;
const PER_PEER: usize = 32;
const CHECKSUM: usize = 32;
pub const MAX_PEERS: usize = (REGION_SIZE - FIXED - CHECKSUM) / PER_PEER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    BadMagic,
    BadVersion,
    BadPeerCount,
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
            BlobError::BadPeerCount => "secrets: peer count out of range",
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
    peers: usize,
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

/// Callers bound `peers` by MAX_PEERS, so this cannot overflow.
const fn body_len(peers: usize) -> usize {
    FIXED.saturating_add(peers.saturating_mul(PER_PEER))
}

impl<'a> Blob<'a> {
    /// Validates magic, version, peer count (must equal `expected_peers`),
    /// checksum and zero padding.
    pub fn parse(bytes: &'a [u8], expected_peers: usize) -> Result<Self, BlobError> {
        if bytes.len() < REGION_SIZE {
            return Err(BlobError::TooSmall);
        }
        if field::<8>(bytes, 0) != Some(&MAGIC) {
            return Err(BlobError::BadMagic);
        }
        if u32_at(bytes, 8) != Some(VERSION) {
            return Err(BlobError::BadVersion);
        }
        let peers = u32_at(bytes, 12).and_then(|n| usize::try_from(n).ok()).ok_or(BlobError::BadPeerCount)?;
        if peers == 0 || peers > MAX_PEERS || peers != expected_peers {
            return Err(BlobError::BadPeerCount);
        }
        check_sealed(bytes, body_len(peers))?;
        Ok(Self { bytes, peers })
    }

    pub fn peer_count(&self) -> usize {
        self.peers
    }

    pub fn gateway_private(&self) -> &[u8; 32] {
        field::<32>(self.bytes, GATEWAY_PRIVATE_AT).unwrap_or(&[0; 32])
    }

    pub fn boot_seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, BOOT_SEED_AT).unwrap_or(&[0; 32])
    }

    /// Hash of peer `i`'s public key.
    pub fn peer(&self, i: usize) -> Option<&[u8; 32]> {
        if i >= self.peers {
            return None;
        }
        field::<32>(self.bytes, FIXED.checked_add(i.checked_mul(PER_PEER)?)?)
    }
}

/// Writes a region. `peers` are the peers' public keys. Returns the number
/// of bytes used before zero padding, or None if it does not fit.
pub fn write(out: &mut [u8; REGION_SIZE], gateway_private: &[u8; 32], boot_seed: &[u8; 32], peers: &[[u8; 32]]) -> Option<usize> {
    if peers.is_empty() || peers.len() > MAX_PEERS {
        return None;
    }
    out.fill(0);
    let mut w = Writer { out, at: 0 };
    w.put(&MAGIC)?;
    w.put(&VERSION.to_le_bytes())?;
    w.put(&u32::try_from(peers.len()).ok()?.to_le_bytes())?;
    w.put(gateway_private)?;
    w.put(boot_seed)?;
    for public in peers {
        w.put(&blake2s(&[public]))?;
    }
    w.seal()
}

#[cfg(test)]
mod tests;
