//! Format of the secrets memory region (law L6): the only place static
//! secrets exist at run time, mapped into `key` alone. Shared by `key`
//! (validation), `mksecrets` (writing) and the config checks, so the layout
//! is defined once.
//!
//! Layout (little-endian):
//!   magic[8] = "SOSSECR1" | version u32 = 1 | peer_count u32
//!   gateway_private[32] | boot_seed[32]
//!   peer_count × { peer_public_hash[32] = BLAKE2s-256(peer public key), psk[32] }
//!   checksum[32] = BLAKE2s-256(all preceding bytes)
//! The region has a fixed size (`REGION_SIZE`); bytes after the checksum are zero.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub const MAGIC: [u8; 8] = *b"SOSSECR1";
pub const VERSION: u32 = 1;
pub const REGION_SIZE: usize = 4096;
const HEADER: usize = 8 + 4 + 4;
const FIXED: usize = HEADER + 32 + 32;
const PER_PEER: usize = 64;
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
        // Inputs here are small and bounded by REGION_SIZE.
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
        let body = bytes.get(..body_len(peers)).ok_or(BlobError::TooSmall)?;
        let stored = field::<32>(bytes, body_len(peers)).ok_or(BlobError::TooSmall)?;
        if blake2s(&[body]) != *stored {
            return Err(BlobError::BadChecksum);
        }
        let rest = bytes.get(body_len(peers).saturating_add(CHECKSUM)..).ok_or(BlobError::TooSmall)?;
        if rest.iter().any(|b| *b != 0) {
            return Err(BlobError::NonZeroPadding);
        }
        Ok(Self { bytes, peers })
    }

    pub fn peer_count(&self) -> usize {
        self.peers
    }

    pub fn gateway_private(&self) -> &[u8; 32] {
        field::<32>(self.bytes, HEADER).unwrap_or(&[0; 32])
    }

    pub fn boot_seed(&self) -> &[u8; 32] {
        field::<32>(self.bytes, HEADER + 32).unwrap_or(&[0; 32])
    }

    /// (hash of the peer's public key, PSK) for peer `i`.
    pub fn peer(&self, i: usize) -> Option<(&[u8; 32], &[u8; 32])> {
        if i >= self.peers {
            return None;
        }
        let at = FIXED.checked_add(i.checked_mul(PER_PEER)?)?;
        Some((field::<32>(self.bytes, at)?, field::<32>(self.bytes, at.checked_add(32)?)?))
    }
}

/// Writes a region. `peers` are (peer public key, PSK). Returns the number of
/// bytes used before zero padding, or None if it does not fit.
pub fn write(
    out: &mut [u8; REGION_SIZE],
    gateway_private: &[u8; 32],
    boot_seed: &[u8; 32],
    peers: &[([u8; 32], [u8; 32])],
) -> Option<usize> {
    if peers.is_empty() || peers.len() > MAX_PEERS {
        return None;
    }
    out.fill(0);
    let mut w = 0usize;
    let mut put = |out: &mut [u8; REGION_SIZE], data: &[u8]| -> Option<()> {
        let end = w.checked_add(data.len())?;
        out.get_mut(w..end)?.copy_from_slice(data);
        w = end;
        Some(())
    };
    put(out, &MAGIC)?;
    put(out, &VERSION.to_le_bytes())?;
    put(out, &u32::try_from(peers.len()).ok()?.to_le_bytes())?;
    put(out, gateway_private)?;
    put(out, boot_seed)?;
    for (public, psk) in peers {
        put(out, &blake2s(&[public]))?;
        put(out, psk)?;
    }
    let body = body_len(peers.len());
    let sum = blake2s(&[out.get(..body)?]);
    put(out, &sum)?;
    body.checked_add(CHECKSUM)
}

#[cfg(test)]
mod tests;
