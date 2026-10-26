//! TPM 2.0 marshalling for the one flow kozane runs (M5 plan C9, C10):
//! the commands of an offline-sealed unseal (CreatePrimary →
//! StartAuthSession → PolicyPCR → PolicyAuthValue → Import → Load → Unseal
//! → FlushContext), PCR_Read and the cap's PCR_Extend, their response
//! parsers, the two public areas the flow uses, and the `tpm` PD's gate
//! ([`gate`]). Free of cryptography, so that Kani checks it without
//! compiling libcrux; the session crypto is the `tpm2` crate's.
//!
//! Every parser is total and checks every length: the TPM bus is A7's.
//! Every command and every response a parser accepts fits one seL4 IPC
//! message (C9's message-size rule, asserted below).
//!
//! Integers are big-endian, as TPM 2.0 Part 2 marshals them.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod gate;

pub const ST_NO_SESSIONS: u16 = 0x8001;
pub const ST_SESSIONS: u16 = 0x8002;

pub const CC_CREATE_PRIMARY: u32 = 0x131;
pub const CC_POLICY_AUTH_VALUE: u32 = 0x16B;
pub const CC_IMPORT: u32 = 0x156;
pub const CC_LOAD: u32 = 0x157;
pub const CC_UNSEAL: u32 = 0x15E;
pub const CC_FLUSH_CONTEXT: u32 = 0x165;
pub const CC_START_AUTH_SESSION: u32 = 0x176;
pub const CC_PCR_READ: u32 = 0x17E;
pub const CC_POLICY_PCR: u32 = 0x17F;
pub const CC_PCR_EXTEND: u32 = 0x182;

pub const RH_OWNER: u32 = 0x4000_0001;
pub const RH_NULL: u32 = 0x4000_0007;
pub const RS_PW: u32 = 0x4000_0009;

pub const ALG_AES: u16 = 0x0006;
pub const ALG_KEYEDHASH: u16 = 0x0008;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_CFB: u16 = 0x0043;
pub const ECC_NIST_P256: u16 = 0x0003;
pub const SE_POLICY: u8 = 0x01;

/// TPMA_SESSION bits.
pub const SESSION_CONTINUE: u8 = 0x01;
pub const SESSION_DECRYPT: u8 = 0x20;
pub const SESSION_ENCRYPT: u8 = 0x40;

/// The one PCR the seal policy names (M5 plan C8) and the cap extends.
pub const PCR_INDEX: u32 = 8;
/// TPML_PCR_SELECTION {sha256: {8}}.
pub const PCR_SELECTION: [u8; 10] = [0, 0, 0, 1, 0x00, 0x0B, 3, 0x00, 0x01, 0x00];

pub const HEADER_LEN: usize = 10;
pub const DIGEST_LEN: usize = 32;
/// The longest digest a TPM produces (SHA-512): the creation ticket's HMAC
/// uses the TPM's own context algorithm, not the key's nameAlg.
pub const MAX_DIGEST: usize = 64;
/// nameAlg ‖ digest.
pub const NAME_LEN: usize = 2 + DIGEST_LEN;
pub const NONCE_LEN: usize = 32;
/// The shortest nonce the TPM accepts or returns for a SHA-256 session.
pub const NONCE_MIN: usize = 16;
pub const COORD_LEN: usize = 32;
/// TPMS_ECC_POINT with P-256 coordinates: the salt's and the seed's
/// TPM2B_ENCRYPTED_SECRET contents.
pub const POINT_LEN: usize = 2 + COORD_LEN + 2 + COORD_LEN;

/// seL4's IPC buffer carries 120 message words (C9).
pub const IPC_MSG_BYTES: usize = 120 * 8;
/// No parser accepts a longer response.
pub const MAX_RESPONSE: usize = IPC_MSG_BYTES;

/// A password session with an empty password: handle, nonce, attributes, hmac.
const PW_SESSION_LEN: usize = 4 + 2 + 1 + 2;
/// The command auth area holding one password session.
const PW_AUTH_LEN: usize = 4 + PW_SESSION_LEN;

/// TPMT_PUBLIC of the SRK: the TCG storage key template, ECC NIST P-256 with
/// AES-128-CFB, attributes fixedTPM | fixedParent | sensitiveDataOrigin |
/// userWithAuth | noDA | restricted | decrypt, as `tpm2_createprimary -C o
/// -G ecc256:aes128cfb -g sha256 -a ...` builds it. The template's unique
/// point is empty; the TPM's public carries the point at the same place.
pub const SRK_PUBLIC_PREFIX: [u8; 22] = [
    0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00,
    0x03, 0x00, 0x10,
];
pub const SRK_TEMPLATE_LEN: usize = SRK_PUBLIC_PREFIX.len() + 4;
/// The SRK's TPMT_PUBLIC as the TPM returns it.
pub const SRK_PUBLIC_LEN: usize = SRK_PUBLIC_PREFIX.len() + POINT_LEN;

/// objectAttributes of the sealed KEK object: noDA only. userWithAuth is
/// clear (only the policy authorizes), fixedTPM and fixedParent are clear
/// (TPM2_Import requires it), encryptedDuplication is clear (no inner
/// wrapper), sign and decrypt are clear (a sealed data object).
pub const SEALED_ATTRIBUTES: u32 = 0x0000_0400;
/// TPMT_PUBLIC of the sealed object: keyedhash, sha256, the attributes,
/// authPolicy (32), scheme NULL, unique (32).
pub const SEALED_PUBLIC_LEN: usize = 2 + 2 + 4 + 2 + DIGEST_LEN + 2 + 2 + DIGEST_LEN;
/// TPMT_SENSITIVE of the sealed object: type, empty authValue, the
/// obfuscation seed (32) and the KEK (32).
pub const SENSITIVE_LEN: usize = 2 + 2 + 2 + DIGEST_LEN + 2 + 32;
/// The duplicate's contents: outerHMAC as a TPM2B, then the encrypted
/// TPM2B_SENSITIVE.
pub const DUPLICATE_LEN: usize = 2 + DIGEST_LEN + 2 + SENSITIVE_LEN;
/// The longest TPM2B_PRIVATE contents accepted from Import and sent to Load.
pub const MAX_PRIVATE: usize = 256;

pub const CREATE_PRIMARY_CMD_LEN: usize = HEADER_LEN + 4 + PW_AUTH_LEN + 6 + 2 + SRK_TEMPLATE_LEN + 2 + 4;
pub const START_AUTH_SESSION_CMD_LEN: usize = HEADER_LEN + 8 + 2 + NONCE_LEN + 2 + POINT_LEN + 1 + 6 + 2;
pub const POLICY_PCR_CMD_LEN: usize = HEADER_LEN + 4 + 2 + PCR_SELECTION.len();
pub const POLICY_AUTH_VALUE_CMD_LEN: usize = HEADER_LEN + 4;
pub const IMPORT_CMD_LEN: usize =
    HEADER_LEN + 4 + PW_AUTH_LEN + 2 + 2 + SEALED_PUBLIC_LEN + 2 + DUPLICATE_LEN + 2 + POINT_LEN + 2;
pub const MAX_LOAD_CMD_LEN: usize = HEADER_LEN + 4 + PW_AUTH_LEN + 2 + MAX_PRIVATE + 2 + SEALED_PUBLIC_LEN;
/// The policy session in Unseal's auth area: handle, nonce (32),
/// attributes, hmac (32).
const POLICY_SESSION_LEN: usize = 4 + 2 + NONCE_LEN + 1 + 2 + DIGEST_LEN;
pub const UNSEAL_CMD_LEN: usize = HEADER_LEN + 4 + 4 + POLICY_SESSION_LEN;
pub const FLUSH_CONTEXT_CMD_LEN: usize = HEADER_LEN + 4;
pub const PCR_READ_CMD_LEN: usize = HEADER_LEN + PCR_SELECTION.len();
pub const PCR_EXTEND_CMD_LEN: usize = HEADER_LEN + 4 + PW_AUTH_LEN + 4 + 2 + DIGEST_LEN;

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// The longest command of the flow.
pub const MAX_COMMAND: usize = max(
    max(max(CREATE_PRIMARY_CMD_LEN, START_AUTH_SESSION_CMD_LEN), max(POLICY_PCR_CMD_LEN, POLICY_AUTH_VALUE_CMD_LEN)),
    max(
        max(max(IMPORT_CMD_LEN, MAX_LOAD_CMD_LEN), max(UNSEAL_CMD_LEN, FLUSH_CONTEXT_CMD_LEN)),
        max(PCR_READ_CMD_LEN, PCR_EXTEND_CMD_LEN),
    ),
);

// C9: every command and every accepted response fits one IPC message.
const _: () = assert!(MAX_COMMAND <= IPC_MSG_BYTES);
const _: () = assert!(MAX_RESPONSE <= IPC_MSG_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RspError {
    /// Shorter than its fields, or a length field past the end.
    Short,
    /// The header's size differs from the bytes received, or a response is
    /// longer than `MAX_RESPONSE`.
    Size,
    /// The tag is not the one this command's response carries.
    Tag,
    /// The TPM refused the command with this response code.
    Tpm(u32),
    /// A field has a value the flow never produces (a length, a count, an
    /// algorithm, or bytes left over).
    Malformed,
}

/// Sequential writer; every step is bounds-checked.
pub struct Writer<'o> {
    out: &'o mut [u8],
    at: usize,
}

impl<'o> Writer<'o> {
    pub fn new(out: &'o mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    pub fn len(&self) -> usize {
        self.at
    }

    pub fn is_empty(&self) -> bool {
        self.at == 0
    }

    pub fn bytes(&mut self, data: &[u8]) -> Option<()> {
        let end = self.at.checked_add(data.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(data);
        self.at = end;
        Some(())
    }

    pub fn u8(&mut self, v: u8) -> Option<()> {
        self.bytes(&[v])
    }

    pub fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_be_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_be_bytes())
    }

    /// A TPM2B: u16 size, then the bytes.
    pub fn tpm2b(&mut self, data: &[u8]) -> Option<()> {
        self.u16(u16::try_from(data.len()).ok()?)?;
        self.bytes(data)
    }

    /// Writes a u32 at `at`, inside what is already written.
    fn patch_u32(&mut self, at: usize, v: u32) -> Option<()> {
        let end = at.checked_add(4)?;
        if end > self.at {
            return None;
        }
        self.out.get_mut(at..end)?.copy_from_slice(&v.to_be_bytes());
        Some(())
    }

    /// Fills in the header's size field; returns the command length.
    pub fn finish(mut self) -> Option<usize> {
        let len = self.at;
        self.patch_u32(2, u32::try_from(len).ok()?)?;
        Some(len)
    }
}

/// Sequential reader over A7's bytes; every step is bounds-checked.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], RspError> {
        let end = self.at.checked_add(n).ok_or(RspError::Short)?;
        let s = self.bytes.get(self.at..end).ok_or(RspError::Short)?;
        self.at = end;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], RspError> {
        self.take(N)?.try_into().map_err(|_| RspError::Short)
    }

    pub fn u8(&mut self) -> Result<u8, RspError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, RspError> {
        Ok(u16::from_be_bytes(*self.array::<2>()?))
    }

    pub fn u32(&mut self) -> Result<u32, RspError> {
        Ok(u32::from_be_bytes(*self.array::<4>()?))
    }

    /// A TPM2B's contents, at most `max` bytes.
    pub fn tpm2b(&mut self, max: usize) -> Result<&'a [u8], RspError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(RspError::Malformed);
        }
        self.take(n)
    }

    /// Nothing may follow the last field.
    pub fn end(&self) -> Result<(), RspError> {
        if self.remaining() == 0 { Ok(()) } else { Err(RspError::Malformed) }
    }
}

fn header(w: &mut Writer<'_>, tag: u16, cc: u32) -> Option<()> {
    w.u16(tag)?;
    w.u32(0)?;
    w.u32(cc)
}

/// The command auth area for one password session with an empty password.
fn pw_auth(w: &mut Writer<'_>) -> Option<()> {
    w.u32(u32::try_from(PW_SESSION_LEN).ok()?)?;
    w.u32(RS_PW)?;
    w.tpm2b(&[])?;
    w.u8(SESSION_CONTINUE)?;
    w.tpm2b(&[])
}

/// TPM2_CreatePrimary of the SRK under the owner hierarchy.
pub fn create_primary(out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_SESSIONS, CC_CREATE_PRIMARY)?;
    w.u32(RH_OWNER)?;
    pw_auth(&mut w)?;
    // inSensitive: empty userAuth and data.
    w.u16(4)?;
    w.tpm2b(&[])?;
    w.tpm2b(&[])?;
    w.u16(u16::try_from(SRK_TEMPLATE_LEN).ok()?)?;
    w.bytes(&SRK_PUBLIC_PREFIX)?;
    w.tpm2b(&[])?;
    w.tpm2b(&[])?;
    // outsideInfo, creationPCR (no PCRs).
    w.tpm2b(&[])?;
    w.u32(0)?;
    w.finish()
}

/// TPM2_StartAuthSession: a policy session salted to `tpm_key` (the SRK),
/// unbound, AES-128-CFB parameter encryption, SHA-256.
pub fn start_auth_session(
    out: &mut [u8],
    tpm_key: u32,
    nonce_caller: &[u8; NONCE_LEN],
    encrypted_salt: &[u8; POINT_LEN],
) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_NO_SESSIONS, CC_START_AUTH_SESSION)?;
    w.u32(tpm_key)?;
    w.u32(RH_NULL)?;
    w.tpm2b(nonce_caller)?;
    w.tpm2b(encrypted_salt)?;
    w.u8(SE_POLICY)?;
    w.u16(ALG_AES)?;
    w.u16(128)?;
    w.u16(ALG_CFB)?;
    w.u16(ALG_SHA256)?;
    w.finish()
}

/// TPM2_PolicyPCR over PCR 8 (sha256); an empty pcrDigest makes the TPM use
/// the current value.
pub fn policy_pcr(out: &mut [u8], session: u32) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_NO_SESSIONS, CC_POLICY_PCR)?;
    w.u32(session)?;
    w.tpm2b(&[])?;
    w.bytes(&PCR_SELECTION)?;
    w.finish()
}

pub fn policy_auth_value(out: &mut [u8], session: u32) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_NO_SESSIONS, CC_POLICY_AUTH_VALUE)?;
    w.u32(session)?;
    w.finish()
}

/// TPM2_Import under `parent` with an outer wrapper only (no inner
/// symmetric key). The three areas are TPM2B contents.
pub fn import(
    out: &mut [u8],
    parent: u32,
    object_public: &[u8],
    duplicate: &[u8],
    in_sym_seed: &[u8],
) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_SESSIONS, CC_IMPORT)?;
    w.u32(parent)?;
    pw_auth(&mut w)?;
    w.tpm2b(&[])?;
    w.tpm2b(object_public)?;
    w.tpm2b(duplicate)?;
    w.tpm2b(in_sym_seed)?;
    w.u16(ALG_NULL)?;
    w.finish()
}

pub fn load(out: &mut [u8], parent: u32, private: &[u8], public: &[u8]) -> Option<usize> {
    if private.len() > MAX_PRIVATE {
        return None;
    }
    let mut w = Writer::new(out);
    header(&mut w, ST_SESSIONS, CC_LOAD)?;
    w.u32(parent)?;
    pw_auth(&mut w)?;
    w.tpm2b(private)?;
    w.tpm2b(public)?;
    w.finish()
}

/// TPM2_Unseal of `item`, authorized by the policy `session`.
pub fn unseal(
    out: &mut [u8],
    item: u32,
    session: u32,
    nonce_caller: &[u8; NONCE_LEN],
    attributes: u8,
    hmac: &[u8; DIGEST_LEN],
) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_SESSIONS, CC_UNSEAL)?;
    w.u32(item)?;
    w.u32(u32::try_from(POLICY_SESSION_LEN).ok()?)?;
    w.u32(session)?;
    w.tpm2b(nonce_caller)?;
    w.u8(attributes)?;
    w.tpm2b(hmac)?;
    w.finish()
}

pub fn flush_context(out: &mut [u8], handle: u32) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_NO_SESSIONS, CC_FLUSH_CONTEXT)?;
    w.u32(handle)?;
    w.finish()
}

pub fn pcr_read(out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_NO_SESSIONS, CC_PCR_READ)?;
    w.bytes(&PCR_SELECTION)?;
    w.finish()
}

/// TPM2_PCR_Extend of PCR 8's sha256 bank with `digest`.
pub fn pcr_extend(out: &mut [u8], digest: &[u8; DIGEST_LEN]) -> Option<usize> {
    let mut w = Writer::new(out);
    header(&mut w, ST_SESSIONS, CC_PCR_EXTEND)?;
    w.u32(PCR_INDEX)?;
    pw_auth(&mut w)?;
    w.u32(1)?;
    w.u16(ALG_SHA256)?;
    w.bytes(digest)?;
    w.finish()
}

/// Checks the header against the bytes received and returns the reader
/// past it. A nonzero response code is returned as `Tpm`, with nothing
/// after the header (TPM 2.0 Part 1: an error response is the header alone).
fn response_header(bytes: &[u8], tag: u16) -> Result<Reader<'_>, RspError> {
    if bytes.len() > MAX_RESPONSE {
        return Err(RspError::Size);
    }
    let mut r = Reader::new(bytes);
    let got_tag = r.u16()?;
    let size = r.u32()?;
    let rc = r.u32()?;
    if usize::try_from(size).ok() != Some(bytes.len()) {
        return Err(RspError::Size);
    }
    if rc != 0 {
        return if got_tag == ST_NO_SESSIONS && r.remaining() == 0 { Err(RspError::Tpm(rc)) } else { Err(RspError::Malformed) };
    }
    if got_tag != tag {
        return Err(RspError::Tag);
    }
    Ok(r)
}

/// A response to a command without sessions that returns no parameters
/// (PolicyPCR, PolicyAuthValue, FlushContext).
pub fn parse_empty(bytes: &[u8]) -> Result<(), RspError> {
    response_header(bytes, ST_NO_SESSIONS)?.end()
}

/// The response auth area of one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRsp<'a> {
    pub nonce: &'a [u8],
    pub attributes: u8,
    pub hmac: &'a [u8],
}

/// A response with one session: the output handle, if the command has one,
/// the parameter area and the session's auth area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRsp<'a> {
    pub handle: u32,
    pub params: &'a [u8],
    pub auth: AuthRsp<'a>,
}

fn session_response(bytes: &[u8], has_handle: bool) -> Result<SessionRsp<'_>, RspError> {
    let mut r = response_header(bytes, ST_SESSIONS)?;
    let handle = if has_handle { r.u32()? } else { 0 };
    let param_len = usize::try_from(r.u32()?).map_err(|_| RspError::Size)?;
    let params = r.take(param_len)?;
    let nonce = r.tpm2b(NONCE_LEN)?;
    let attributes = r.u8()?;
    let hmac = r.tpm2b(DIGEST_LEN)?;
    r.end()?;
    Ok(SessionRsp { handle, params, auth: AuthRsp { nonce, attributes, hmac } })
}

/// A password session's response: empty nonce and hmac.
fn password_response(bytes: &[u8], has_handle: bool) -> Result<SessionRsp<'_>, RspError> {
    let s = session_response(bytes, has_handle)?;
    if !s.auth.nonce.is_empty() || !s.auth.hmac.is_empty() {
        return Err(RspError::Malformed);
    }
    Ok(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatePrimaryRsp<'a> {
    pub handle: u32,
    /// TPMT_PUBLIC.
    pub public: &'a [u8],
    pub name: &'a [u8],
}

/// The fields after outPublic are read for their lengths only; the caller
/// compares the name with the one it pinned.
pub fn parse_create_primary(bytes: &[u8]) -> Result<CreatePrimaryRsp<'_>, RspError> {
    let s = password_response(bytes, true)?;
    let mut r = Reader::new(s.params);
    let public = r.tpm2b(SRK_PUBLIC_LEN)?;
    r.tpm2b(MAX_RESPONSE)?; // creationData
    r.tpm2b(MAX_DIGEST)?; // creationHash
    r.u16()?; // creationTicket: tag, hierarchy, digest
    r.u32()?;
    r.tpm2b(MAX_DIGEST)?;
    let name = r.tpm2b(NAME_LEN)?;
    r.end()?;
    Ok(CreatePrimaryRsp { handle: s.handle, public, name })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartAuthSessionRsp<'a> {
    pub handle: u32,
    pub nonce_tpm: &'a [u8],
}

pub fn parse_start_auth_session(bytes: &[u8]) -> Result<StartAuthSessionRsp<'_>, RspError> {
    let mut r = response_header(bytes, ST_NO_SESSIONS)?;
    let handle = r.u32()?;
    let nonce_tpm = r.tpm2b(NONCE_LEN)?;
    if nonce_tpm.len() < NONCE_MIN {
        return Err(RspError::Malformed);
    }
    r.end()?;
    Ok(StartAuthSessionRsp { handle, nonce_tpm })
}

/// Import's outPrivate (TPM2B_PRIVATE contents).
pub fn parse_import(bytes: &[u8]) -> Result<&[u8], RspError> {
    let s = password_response(bytes, false)?;
    let mut r = Reader::new(s.params);
    let private = r.tpm2b(MAX_PRIVATE)?;
    r.end()?;
    Ok(private)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadRsp<'a> {
    pub handle: u32,
    pub name: &'a [u8],
}

pub fn parse_load(bytes: &[u8]) -> Result<LoadRsp<'_>, RspError> {
    let s = password_response(bytes, true)?;
    let mut r = Reader::new(s.params);
    let name = r.tpm2b(NAME_LEN)?;
    r.end()?;
    Ok(LoadRsp { handle: s.handle, name })
}

/// Unseal's response. `params` is what the response HMAC covers; `out_data`
/// lies inside it and is still encrypted. Nothing here is trusted until the
/// caller has verified `auth.hmac` (I10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsealRsp<'a> {
    pub params: &'a [u8],
    pub out_data: &'a [u8],
    pub auth: AuthRsp<'a>,
}

pub fn parse_unseal(bytes: &[u8]) -> Result<UnsealRsp<'_>, RspError> {
    let s = session_response(bytes, false)?;
    if s.auth.nonce.len() < NONCE_MIN || s.auth.hmac.len() != DIGEST_LEN {
        return Err(RspError::Malformed);
    }
    let mut r = Reader::new(s.params);
    let out_data = r.tpm2b(MAX_RESPONSE)?;
    r.end()?;
    Ok(UnsealRsp { params: s.params, out_data, auth: s.auth })
}

/// PCR_Read of PCR 8 (sha256): the selection must come back as asked, with
/// one digest.
pub fn parse_pcr_read(bytes: &[u8]) -> Result<&[u8; DIGEST_LEN], RspError> {
    let mut r = response_header(bytes, ST_NO_SESSIONS)?;
    r.u32()?; // pcrUpdateCounter
    if r.array::<10>()? != &PCR_SELECTION {
        return Err(RspError::Malformed);
    }
    if r.u32()? != 1 {
        return Err(RspError::Malformed);
    }
    if usize::from(r.u16()?) != DIGEST_LEN {
        return Err(RspError::Malformed);
    }
    let digest = r.array::<DIGEST_LEN>()?;
    r.end()?;
    Ok(digest)
}

/// PCR_Extend's response (a password session, no parameters).
pub fn parse_pcr_extend(bytes: &[u8]) -> Result<(), RspError> {
    let s = password_response(bytes, false)?;
    if s.params.is_empty() { Ok(()) } else { Err(RspError::Malformed) }
}

/// The SRK's public point, if `public` is the SRK template's public area
/// with 32-byte coordinates (the curve check is the ECDH's).
pub fn srk_point(public: &[u8]) -> Option<(&[u8; COORD_LEN], &[u8; COORD_LEN])> {
    let mut r = Reader::new(public);
    if r.take(SRK_PUBLIC_PREFIX.len()).ok()? != SRK_PUBLIC_PREFIX {
        return None;
    }
    if usize::from(r.u16().ok()?) != COORD_LEN {
        return None;
    }
    let x = r.array::<COORD_LEN>().ok()?;
    if usize::from(r.u16().ok()?) != COORD_LEN {
        return None;
    }
    let y = r.array::<COORD_LEN>().ok()?;
    r.end().ok()?;
    Some((x, y))
}

/// Writes the sealed object's TPMT_PUBLIC.
pub fn sealed_public(out: &mut [u8; SEALED_PUBLIC_LEN], auth_policy: &[u8; DIGEST_LEN], unique: &[u8; DIGEST_LEN]) -> Option<()> {
    let mut w = Writer::new(out);
    w.u16(ALG_KEYEDHASH)?;
    w.u16(ALG_SHA256)?;
    w.u32(SEALED_ATTRIBUTES)?;
    w.tpm2b(auth_policy)?;
    w.u16(ALG_NULL)?;
    w.tpm2b(unique)?;
    (w.len() == SEALED_PUBLIC_LEN).then_some(())
}

/// The authPolicy of `public`, if it is a sealed object's public area as
/// `sealed_public` writes it.
pub fn sealed_policy(public: &[u8]) -> Option<&[u8; DIGEST_LEN]> {
    let mut r = Reader::new(public);
    if r.u16().ok()? != ALG_KEYEDHASH || r.u16().ok()? != ALG_SHA256 || r.u32().ok()? != SEALED_ATTRIBUTES {
        return None;
    }
    if usize::from(r.u16().ok()?) != DIGEST_LEN {
        return None;
    }
    let policy = r.array::<DIGEST_LEN>().ok()?;
    if r.u16().ok()? != ALG_NULL || usize::from(r.u16().ok()?) != DIGEST_LEN {
        return None;
    }
    r.take(DIGEST_LEN).ok()?;
    r.end().ok()?;
    Some(policy)
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
