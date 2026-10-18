//! WireGuard message codecs and the transport replay window, free of any
//! cryptography so that Kani can check them without compiling libcrux.
//!
//! Every parser is total: any input yields a value or a `WireError`, never a
//! panic (proved by the harnesses in `proofs`). Reserved bytes must be zero.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod replay;

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const TRANSPORT_HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
/// Header plus an empty (keepalive) payload's tag.
pub const TRANSPORT_MIN_LEN: usize = TRANSPORT_HEADER_LEN + TAG_LEN;

/// Bytes of an initiation covered by mac1 (everything before it).
pub const INITIATION_MAC1_OFFSET: usize = 116;
/// Bytes of a response covered by mac1 (everything before it).
pub const RESPONSE_MAC1_OFFSET: usize = 60;

/// 2^64 - 2^13 - 1 (whitepaper section 6.1).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    WrongLength,
    WrongType,
    ReservedNonZero,
    TooShort,
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInitiation {
    pub sender: u32,
    pub ephemeral: [u8; 32],
    pub enc_static: [u8; 48],
    pub enc_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageResponse {
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral: [u8; 32],
    pub enc_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transport<'a> {
    pub receiver: u32,
    pub counter: u64,
    /// Encrypted payload followed by its 16-byte tag (at least 16 bytes).
    pub ciphertext: &'a [u8],
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(WireError::TooShort)?;
        self.0 = rest;
        Ok(*head)
    }

    fn header(&mut self, ty: u8) -> Result<(), WireError> {
        let [t, r0, r1, r2] = self.take::<4>()?;
        if t != ty {
            return Err(WireError::WrongType);
        }
        if (r0 | r1 | r2) != 0 {
            return Err(WireError::ReservedNonZero);
        }
        Ok(())
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        self.take::<4>().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        self.take::<8>().map(u64::from_le_bytes)
    }
}

struct Writer<'a>(&'a mut [u8]);

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let buf = core::mem::take(&mut self.0);
        let (head, rest) = buf
            .split_at_mut_checked(bytes.len())
            .ok_or(WireError::BufferTooSmall)?;
        head.copy_from_slice(bytes);
        self.0 = rest;
        Ok(())
    }

    fn header(&mut self, ty: u8) -> Result<(), WireError> {
        self.put(&[ty, 0, 0, 0])
    }
}

impl MessageInitiation {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != INITIATION_LEN {
            return Err(WireError::WrongLength);
        }
        let mut r = Reader(bytes);
        r.header(MSG_INITIATION)?;
        Ok(Self {
            sender: r.u32()?,
            ephemeral: r.take()?,
            enc_static: r.take()?,
            enc_timestamp: r.take()?,
            mac1: r.take()?,
            mac2: r.take()?,
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_INITIATION)?;
        w.put(&self.sender.to_le_bytes())?;
        w.put(&self.ephemeral)?;
        w.put(&self.enc_static)?;
        w.put(&self.enc_timestamp)?;
        w.put(&self.mac1)?;
        w.put(&self.mac2)?;
        Ok(INITIATION_LEN)
    }
}

impl MessageResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != RESPONSE_LEN {
            return Err(WireError::WrongLength);
        }
        let mut r = Reader(bytes);
        r.header(MSG_RESPONSE)?;
        Ok(Self {
            sender: r.u32()?,
            receiver: r.u32()?,
            ephemeral: r.take()?,
            enc_nothing: r.take()?,
            mac1: r.take()?,
            mac2: r.take()?,
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_RESPONSE)?;
        w.put(&self.sender.to_le_bytes())?;
        w.put(&self.receiver.to_le_bytes())?;
        w.put(&self.ephemeral)?;
        w.put(&self.enc_nothing)?;
        w.put(&self.mac1)?;
        w.put(&self.mac2)?;
        Ok(RESPONSE_LEN)
    }
}

impl<'a> Transport<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() < TRANSPORT_MIN_LEN {
            return Err(WireError::TooShort);
        }
        let mut r = Reader(bytes);
        r.header(MSG_TRANSPORT)?;
        let receiver = r.u32()?;
        let counter = r.u64()?;
        Ok(Self { receiver, counter, ciphertext: r.0 })
    }
}

/// Writes the 16-byte transport header; the caller appends the ciphertext.
pub fn emit_transport_header(receiver: u32, counter: u64, out: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer(out);
    w.header(MSG_TRANSPORT)?;
    w.put(&receiver.to_le_bytes())?;
    w.put(&counter.to_le_bytes())?;
    Ok(TRANSPORT_HEADER_LEN)
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
