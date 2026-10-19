//! Rosenpass V02 message codecs, free of any cryptography so that Kani can
//! check them without compiling libcrux (M3 plan C1).
//!
//! Every message is an envelope `type ‖ reserved[3] ‖ payload ‖ mac[16] ‖
//! cookie[16]` (upstream `msgs.rs`). Every parser is total: any input yields
//! a value or a `WireError`, never a panic (proved by the harnesses in
//! `proofs`). Reserved bytes must be zero; upstream always sends zeros there.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub const MSG_INIT_HELLO: u8 = 0x81;
pub const MSG_RESP_HELLO: u8 = 0x82;
pub const MSG_INIT_CONF: u8 = 0x83;
pub const MSG_EMPTY_DATA: u8 = 0x84;
pub const MSG_COOKIE_REPLY: u8 = 0x86;

pub const SID_LEN: usize = 4;
pub const TAG_LEN: usize = 16;
pub const MAC_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;
/// Kyber-512 (round 3) public key and ciphertext.
pub const EPK_LEN: usize = 800;
pub const ECT_LEN: usize = 768;
/// Classic McEliece 460896 (round 3) ciphertext.
pub const SCT_LEN: usize = 188;
/// The initiator's peer id (32 bytes) sealed under ChaCha20-Poly1305.
pub const PIDI_CT_LEN: usize = 32 + TAG_LEN;
/// `pidi[32] ‖ biscuit_no[12] ‖ ck[32]`.
pub const BISCUIT_PT_LEN: usize = 76;
/// XChaCha20-Poly1305 nonce, the sealed plaintext and its tag.
pub const BISCUIT_CT_LEN: usize = 24 + BISCUIT_PT_LEN + TAG_LEN;
pub const EMPTY_DATA_CTR_LEN: usize = 8;

pub const INIT_HELLO_LEN: usize = 1092;
pub const RESP_HELLO_LEN: usize = 1132;
pub const INIT_CONF_LEN: usize = 176;
pub const EMPTY_DATA_LEN: usize = 64;

const ENVELOPE_LEN: usize = 4 + MAC_LEN + COOKIE_LEN;
const _: () = assert!(INIT_HELLO_LEN == ENVELOPE_LEN + SID_LEN + EPK_LEN + SCT_LEN + PIDI_CT_LEN + TAG_LEN);
const _: () = assert!(RESP_HELLO_LEN == ENVELOPE_LEN + 2 * SID_LEN + ECT_LEN + SCT_LEN + TAG_LEN + BISCUIT_CT_LEN);
const _: () = assert!(INIT_CONF_LEN == ENVELOPE_LEN + 2 * SID_LEN + BISCUIT_CT_LEN + TAG_LEN);
const _: () = assert!(EMPTY_DATA_LEN == ENVELOPE_LEN + SID_LEN + EMPTY_DATA_CTR_LEN + TAG_LEN);

/// The mac covers every byte before it, the cookie every byte before it.
pub const fn mac_offset(len: usize) -> usize {
    len.saturating_sub(MAC_LEN + COOKIE_LEN)
}

pub const fn cookie_offset(len: usize) -> usize {
    len.saturating_sub(COOKIE_LEN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    WrongLength,
    WrongType,
    ReservedNonZero,
    TooShort,
    BufferTooSmall,
}

/// InitHello (0x81, 1092 bytes), sent by the initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitHello {
    pub sidi: [u8; SID_LEN],
    pub epki: [u8; EPK_LEN],
    pub sctr: [u8; SCT_LEN],
    pub pidi_ct: [u8; PIDI_CT_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// RespHello (0x82, 1132 bytes), sent by the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespHello {
    pub sidr: [u8; SID_LEN],
    pub sidi: [u8; SID_LEN],
    pub ecti: [u8; ECT_LEN],
    pub scti: [u8; SCT_LEN],
    pub auth: [u8; TAG_LEN],
    pub biscuit_ct: [u8; BISCUIT_CT_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// InitConf (0x83, 176 bytes), sent by the initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitConf {
    pub sidi: [u8; SID_LEN],
    pub sidr: [u8; SID_LEN],
    pub biscuit_ct: [u8; BISCUIT_CT_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// EmptyData (0x84, 64 bytes): the responder's acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyData {
    pub sid: [u8; SID_LEN],
    pub ctr: [u8; EMPTY_DATA_CTR_LEN],
    pub auth: [u8; TAG_LEN],
    pub mac: [u8; MAC_LEN],
    pub cookie: [u8; COOKIE_LEN],
}

/// The message type of a datagram, without validating anything else.
pub fn peek_type(bytes: &[u8]) -> Result<u8, WireError> {
    bytes.first().copied().ok_or(WireError::TooShort)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
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
}

/// Exact-length check first, so a parse never reads past a short buffer and
/// never accepts trailing bytes.
fn reader(bytes: &[u8], len: usize, ty: u8) -> Result<Reader<'_>, WireError> {
    if bytes.len() != len {
        return Err(WireError::WrongLength);
    }
    let mut r = Reader(bytes);
    r.header(ty)?;
    Ok(r)
}

struct Writer<'a>(&'a mut [u8]);

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let buf = core::mem::take(&mut self.0);
        let (head, rest) = buf.split_at_mut_checked(bytes.len()).ok_or(WireError::BufferTooSmall)?;
        head.copy_from_slice(bytes);
        self.0 = rest;
        Ok(())
    }

    fn header(&mut self, ty: u8) -> Result<(), WireError> {
        self.put(&[ty, 0, 0, 0])
    }
}

impl InitHello {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = reader(bytes, INIT_HELLO_LEN, MSG_INIT_HELLO)?;
        Ok(Self {
            sidi: r.take()?,
            epki: r.take()?,
            sctr: r.take()?,
            pidi_ct: r.take()?,
            auth: r.take()?,
            mac: r.take()?,
            cookie: r.take()?,
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_INIT_HELLO)?;
        w.put(&self.sidi)?;
        w.put(&self.epki)?;
        w.put(&self.sctr)?;
        w.put(&self.pidi_ct)?;
        w.put(&self.auth)?;
        w.put(&self.mac)?;
        w.put(&self.cookie)?;
        Ok(INIT_HELLO_LEN)
    }
}

impl RespHello {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = reader(bytes, RESP_HELLO_LEN, MSG_RESP_HELLO)?;
        Ok(Self {
            sidr: r.take()?,
            sidi: r.take()?,
            ecti: r.take()?,
            scti: r.take()?,
            auth: r.take()?,
            biscuit_ct: r.take()?,
            mac: r.take()?,
            cookie: r.take()?,
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_RESP_HELLO)?;
        w.put(&self.sidr)?;
        w.put(&self.sidi)?;
        w.put(&self.ecti)?;
        w.put(&self.scti)?;
        w.put(&self.auth)?;
        w.put(&self.biscuit_ct)?;
        w.put(&self.mac)?;
        w.put(&self.cookie)?;
        Ok(RESP_HELLO_LEN)
    }
}

impl InitConf {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = reader(bytes, INIT_CONF_LEN, MSG_INIT_CONF)?;
        Ok(Self {
            sidi: r.take()?,
            sidr: r.take()?,
            biscuit_ct: r.take()?,
            auth: r.take()?,
            mac: r.take()?,
            cookie: r.take()?,
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_INIT_CONF)?;
        w.put(&self.sidi)?;
        w.put(&self.sidr)?;
        w.put(&self.biscuit_ct)?;
        w.put(&self.auth)?;
        w.put(&self.mac)?;
        w.put(&self.cookie)?;
        Ok(INIT_CONF_LEN)
    }
}

impl EmptyData {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = reader(bytes, EMPTY_DATA_LEN, MSG_EMPTY_DATA)?;
        Ok(Self { sid: r.take()?, ctr: r.take()?, auth: r.take()?, mac: r.take()?, cookie: r.take()? })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut w = Writer(out);
        w.header(MSG_EMPTY_DATA)?;
        w.put(&self.sid)?;
        w.put(&self.ctr)?;
        w.put(&self.auth)?;
        w.put(&self.mac)?;
        w.put(&self.cookie)?;
        Ok(EMPTY_DATA_LEN)
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
