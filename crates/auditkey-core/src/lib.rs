//! `auditkey` signer logic (M8 plan C10, D7; laws L1/L2 as amended by C11):
//! the only code that touches the audit checkpoint key. The PD maps the
//! `audit_secrets` region read-only; it holds the blob sealed, which the PD
//! unseals through `tpm` into its own memory at boot (`tpm2::boot`, which
//! also reads the TPM's resetCount and restartCount before the PD's Done).
//! The PD draws the boot ID from `rng` and takes the SRK Name its envelope
//! pins; from then on it answers one fixed-size PPC from `audit`, its only
//! caller (`layout::auditkey`):
//!
//! | label  | request (words)                     | reply                    |
//! |--------|-------------------------------------|--------------------------|
//! | `SIGN` | seq, chain (4, little-endian), lost | `SIGN_REPLY_LEN` bytes   |
//!
//! The reply is `signature [64] ‖ boot_id [16] ‖ reset u32 ‖ restart u32 ‖
//! srk_name [34]` (counts little-endian), packed into words as `tpm::pack`
//! does. Any other label, caller or size is `BAD_REQUEST`; a request the
//! seq rule refuses is `REFUSED`; both carry no data.
//!
//! The signer fixes everything but `seq`, `chain` and `lost` itself, so a
//! compromised `audit` cannot sign for another boot or TPM (S6, S11, S26).
//! It signs only the fixed-width message
//! `DOMAIN ‖ srk_name ‖ boot_id ‖ reset ‖ restart ‖ seq ‖ chain ‖ lost`
//! (counts big-endian), and only when the seq rule admits `seq` (S25):
//! at least `CHECKPOINT_EVERY` past the last signed one, except for one
//! "ready" checkpoint per boot, which still needs a larger `seq`. A boot
//! starts as if seq 0, the boot's first line, had been signed. A `seq`
//! whose distance check overflows is refused. So no two signatures of one
//! boot share a `seq` or go backwards, and `audit` gets at most one per
//! `CHECKPOINT_EVERY` lines plus one (RM8-9 bounds what a compromised
//! `audit` can still obtain).
//!
//! A boot that fails (`BootError`) leaves the PD up but Unavailable (M5 plan
//! C6): it holds no secret and answers every call from `audit` with
//! `UNAVAILABLE | code` and no data; `audit` prints the code. `auditkey`
//! has no audit ring and no console (L1).

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use layout::audit::CHECKPOINT_EVERY;
use layout::auditkey::{BAD_REQUEST, OK, REFUSED, SIGN, SIGN_REPLY_LEN, SIGN_REQ_WORDS, UNAVAILABLE};
use secret_blob::BlobError;
use secret_blob::audit::Blob;
use zeroize::Zeroize;

/// The signature's domain (M8 plan D7).
pub const DOMAIN: &[u8; 27] = b"kozane-audit-checkpoint-v1\0";
/// A TPM Name: nameAlg ‖ SHA-256 (`tpm2_wire::NAME_LEN`; the PD asserts it).
pub const SRK_NAME_LEN: usize = 2 + 32;
pub const BOOT_ID_LEN: usize = 16;
pub const CHAIN_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// The signed message's fixed length.
pub const MESSAGE_LEN: usize = DOMAIN.len() + SRK_NAME_LEN + BOOT_ID_LEN + 4 + 4 + 8 + CHAIN_LEN + 8;

const _: () = assert!(SIGN_REPLY_LEN == SIGNATURE_LEN + BOOT_ID_LEN + 4 + 4 + SRK_NAME_LEN);
const _: () = assert!(SIGN_REQ_WORDS == 1 + CHAIN_LEN / 8 + 1);
const _: () = assert!(MESSAGE_LEN == 133);

/// One `SIGN` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub seq: u64,
    pub chain: [u8; CHAIN_LEN],
    pub lost: u64,
}

/// The request in `words`: exactly `SIGN_REQ_WORDS` of them, `seq`, the
/// chain's bytes as four little-endian words, `lost`. Anything else is None.
pub fn parse(words: &[u64]) -> Option<Request> {
    let [seq, c0, c1, c2, c3, lost] = <[u64; SIGN_REQ_WORDS]>::try_from(words).ok()?;
    let mut chain = [0u8; CHAIN_LEN];
    for (out, w) in chain.as_chunks_mut::<8>().0.iter_mut().zip([c0, c1, c2, c3]) {
        *out = w.to_le_bytes();
    }
    Some(Request { seq, chain, lost })
}

/// The words `parse` reads back as `req` (`audit`'s side).
pub fn encode(req: &Request) -> [u64; SIGN_REQ_WORDS] {
    let mut words = [0u64; SIGN_REQ_WORDS];
    let (seq, rest) = words.split_at_mut(1);
    let (chain, lost) = rest.split_at_mut(CHAIN_LEN / 8);
    seq.fill(req.seq);
    lost.fill(req.lost);
    for (w, c) in chain.iter_mut().zip(req.chain.as_chunks::<8>().0) {
        *w = u64::from_le_bytes(*c);
    }
    words
}

/// What the signer, not `audit`, fixes for the boot (S6, S11, S26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// The SRK Name the envelope pins (and the unseal checked).
    pub srk_name: [u8; SRK_NAME_LEN],
    /// Drawn from `rng` at boot.
    pub boot_id: [u8; BOOT_ID_LEN],
    /// TPM resetCount and restartCount (ReadClock, before the Done).
    pub reset: u32,
    pub restart: u32,
}

/// The signed message for `req` under `id`.
pub fn message(id: &Identity, req: &Request) -> [u8; MESSAGE_LEN] {
    let mut out = [0u8; MESSAGE_LEN];
    let parts: [&[u8]; 8] = [
        DOMAIN,
        &id.srk_name,
        &id.boot_id,
        &id.reset.to_be_bytes(),
        &id.restart.to_be_bytes(),
        &req.seq.to_be_bytes(),
        &req.chain,
        &req.lost.to_be_bytes(),
    ];
    let mut at = 0usize;
    for p in parts {
        let end = at.saturating_add(p.len());
        if let Some(dst) = out.get_mut(at..end) {
            dst.copy_from_slice(p);
        }
        at = end;
    }
    out
}

/// One successful `SIGN`'s reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub signature: [u8; SIGNATURE_LEN],
    pub identity: Identity,
}

pub fn encode_reply(r: &Reply) -> [u8; SIGN_REPLY_LEN] {
    let mut out = [0u8; SIGN_REPLY_LEN];
    let parts: [&[u8]; 5] = [
        &r.signature,
        &r.identity.boot_id,
        &r.identity.reset.to_le_bytes(),
        &r.identity.restart.to_le_bytes(),
        &r.identity.srk_name,
    ];
    let mut at = 0usize;
    for p in parts {
        let end = at.saturating_add(p.len());
        if let Some(dst) = out.get_mut(at..end) {
            dst.copy_from_slice(p);
        }
        at = end;
    }
    out
}

/// The reply in `bytes`, if it is exactly one (`audit`'s side).
pub fn decode_reply(bytes: &[u8]) -> Option<Reply> {
    let b: &[u8; SIGN_REPLY_LEN] = bytes.try_into().ok()?;
    let (signature, rest) = b.split_first_chunk::<SIGNATURE_LEN>()?;
    let (boot_id, rest) = rest.split_first_chunk::<BOOT_ID_LEN>()?;
    let (reset, rest) = rest.split_first_chunk::<4>()?;
    let (restart, srk_name) = rest.split_first_chunk::<4>()?;
    Some(Reply {
        signature: *signature,
        identity: Identity {
            srk_name: srk_name.try_into().ok()?,
            boot_id: *boot_id,
            reset: u32::from_le_bytes(*reset),
            restart: u32::from_le_bytes(*restart),
        },
    })
}

/// Why the seq rule refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not `CHECKPOINT_EVERY` past the last signed seq, and the one
    /// exemption is spent or `seq` is not above it.
    TooSoon,
    /// `last + CHECKPOINT_EVERY` does not fit a u64, and the exemption
    /// does not apply.
    Overflow,
}

/// The seq rule's state for one boot (S25): the last signed seq, and
/// whether the one "ready" exemption is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqRule {
    last: u64,
    exempt_spent: bool,
}

impl Default for SeqRule {
    fn default() -> Self {
        Self::new()
    }
}

impl SeqRule {
    /// A boot's start: as if seq 0 had been signed.
    pub const fn new() -> Self {
        Self { last: 0, exempt_spent: false }
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    pub fn exempt_spent(&self) -> bool {
        self.exempt_spent
    }

    /// The state after signing `seq`, if the rule admits it: `seq` at least
    /// `CHECKPOINT_EVERY` past the last, or else the one exemption, which
    /// still needs `seq` above the last. Pure: the caller keeps the result
    /// only once the signature exists.
    pub fn next(&self, seq: u64) -> Result<SeqRule, Refusal> {
        let due = self.last.checked_add(CHECKPOINT_EVERY);
        match due {
            Some(due) if seq >= due => return Ok(SeqRule { last: seq, exempt_spent: self.exempt_spent }),
            _ => {}
        }
        if !self.exempt_spent && seq > self.last {
            return Ok(SeqRule { last: seq, exempt_spent: true });
        }
        Err(if due.is_none() { Refusal::Overflow } else { Refusal::TooSoon })
    }
}

/// Where `auditkey`'s codes start: `key`'s lie below 0x40 and `tlskey`'s
/// in 0x40..0x80, so one code names the key PD that failed.
pub const CODE_BASE: u32 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    Blob(BlobError),
    /// `rng` gave no boot ID (or no salt for the unseal).
    RngUnavailable,
    /// The region is not a sealed envelope of `auditkey`'s kind.
    EnvelopeInvalid,
    /// `tpm` refused, failed or stayed busy, the ReadClock included.
    TpmUnavailable,
    /// The TPM's SRK is not the envelope's pinned one: another TPM (I10.2).
    SrkMismatch,
    /// The TPM refused the Unseal: PCR 8 is not the value sealed to.
    UnsealRefused,
    /// A TPM response failed the client's checks (A7).
    TpmResponseInvalid,
    /// The unsealed KEK did not open the envelope.
    EnvelopeOpen,
    /// `tpm` could not confirm the cap of PCR 8: the key was not released.
    TpmCapFailed,
}

impl BootError {
    /// Stable code, one per failure, carried by the Unavailable reply
    /// label: `tlskey`'s numbers for the failures both have, above
    /// `CODE_BASE` (3, 7, 8 and 10 stay unused).
    pub const fn code(self) -> u32 {
        CODE_BASE
            | match self {
                BootError::Blob(BlobError::BadMagic) => 1,
                BootError::Blob(BlobError::BadVersion) => 2,
                BootError::Blob(BlobError::BadChecksum) => 4,
                BootError::Blob(BlobError::NonZeroPadding) => 5,
                BootError::Blob(BlobError::TooSmall) => 6,
                BootError::RngUnavailable => 9,
                BootError::EnvelopeInvalid => 11,
                BootError::TpmUnavailable => 12,
                BootError::SrkMismatch => 13,
                BootError::UnsealRefused => 14,
                BootError::TpmResponseInvalid => 15,
                BootError::EnvelopeOpen => 16,
                BootError::TpmCapFailed => 17,
            }
    }

    /// Stable text, one per failure (`audit` prints the code's).
    pub const fn message(self) -> &'static str {
        match self {
            BootError::Blob(BlobError::BadMagic) => "audit secrets: bad magic",
            BootError::Blob(BlobError::BadVersion) => "audit secrets: unsupported version",
            BootError::Blob(BlobError::BadChecksum) => "audit secrets: checksum mismatch",
            BootError::Blob(BlobError::NonZeroPadding) => "audit secrets: non-zero padding",
            BootError::Blob(BlobError::TooSmall) => "audit secrets: region too small",
            BootError::RngUnavailable => "rng unavailable",
            BootError::EnvelopeInvalid => "audit secrets: not a sealed envelope for auditkey",
            BootError::TpmUnavailable => "audit secrets: tpm unavailable",
            BootError::SrkMismatch => "audit secrets: sealed to another TPM",
            BootError::UnsealRefused => "audit secrets: the TPM refused to unseal (PCR 8)",
            BootError::TpmResponseInvalid => "audit secrets: a TPM response failed its checks",
            BootError::EnvelopeOpen => "audit secrets: the unsealed KEK does not open the envelope",
            BootError::TpmCapFailed => "audit secrets: the TPM did not confirm the PCR 8 cap",
        }
    }
}

/// The reply label of an Unavailable `auditkey` whose boot failed with
/// `code`.
pub const fn unavailable_label(code: u32) -> u64 {
    UNAVAILABLE | (code as u64 & 0xff)
}

/// The boot error code an Unavailable reply label carries, if it is one.
pub const fn unavailable_code(label: u64) -> Option<u32> {
    if label & !0xff == UNAVAILABLE { Some((label & 0xff) as u32) } else { None }
}

/// The PDs allowed to call `auditkey`: `audit` alone (law L2: a key PD has
/// at most one caller). The PD maps its channel to a caller; a channel with
/// no caller is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Audit,
}

/// The answer of an Unavailable `auditkey` (no oracle, no secret): every
/// call from `audit` gets `unavailable_label(code)`, an unknown caller
/// `BAD_REQUEST`; never any data, and `reply` is zeroed.
pub fn unavailable(caller: Option<Caller>, code: u32, reply: &mut [u64]) -> (u64, usize) {
    reply.fill(0);
    match caller {
        Some(Caller::Audit) => (unavailable_label(code), 0),
        None => (BAD_REQUEST, 0),
    }
}

/// The Ed25519 sign function: (signature, message, seed) → false if it
/// failed. A seam for the tests.
pub type SignFn = fn(&mut [u8; SIGNATURE_LEN], &[u8], &[u8; 32]) -> bool;

/// libcrux's Ed25519 (HACL*, constant time in the key). Its expanded key
/// stays in dead frames: the PD scrubs `SCRUB_DEPTH` after each call.
pub fn libcrux_sign(sig: &mut [u8; SIGNATURE_LEN], msg: &[u8], seed: &[u8; 32]) -> bool {
    match libcrux_ed25519::sign(msg, seed) {
        Ok(s) => {
            *sig = s;
            true
        }
        Err(_) => false,
    }
}

/// The public key of `seed` (`mksecrets` and the tests).
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    libcrux_ed25519::secret_to_public(&mut pk, seed);
    pk
}

/// How deep the PD scrubs its stack after each `SIGN` (Ed25519's expanded
/// key and nonce in HACL*'s dead frames). Not measured: `tlskey`'s depth,
/// far above Ed25519's frames and well inside the 128 KiB stack.
pub const SCRUB_DEPTH: usize = 32 * 1024;

pub struct Oracle<'a> {
    blob: Blob<'a>,
    identity: Identity,
    rule: SeqRule,
}

impl<'a> Oracle<'a> {
    /// The unsealed region checked as an audit blob; any failure wipes the
    /// whole region before it returns (M5 plan C6: an Unavailable key PD
    /// holds no secret). On success the oracle borrows it read-only for the
    /// life of the system.
    pub fn boot(region: &'a mut [u8], identity: Identity) -> Result<Self, BootError> {
        if let Err(e) = Blob::parse(region) {
            region.zeroize();
            return Err(BootError::Blob(e));
        }
        let region: &'a [u8] = region;
        let blob = Blob::parse(region).map_err(BootError::Blob)?;
        Ok(Self { blob, identity, rule: SeqRule::new() })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn rule(&self) -> &SeqRule {
        &self.rule
    }

    /// Answers one request from `caller` (None: a channel with no caller).
    /// Returns (reply label, reply word count); on any error the count is 0
    /// and `reply` is zeroed.
    pub fn handle(&mut self, caller: Option<Caller>, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        self.handle_with(libcrux_sign, caller, label, req, reply)
    }

    /// `handle` with the sign function as a seam (tests).
    pub fn handle_with(
        &mut self,
        sign: SignFn,
        caller: Option<Caller>,
        label: u64,
        req: &[u64],
        reply: &mut [u64],
    ) -> (u64, usize) {
        let r = match (caller, label, parse(req)) {
            (Some(Caller::Audit), SIGN, Some(req)) => self.sign(sign, &req, reply),
            _ => Err(BAD_REQUEST),
        };
        match r {
            Ok(n) => (OK, n),
            Err(e) => {
                reply.fill(0);
                (e, 0)
            }
        }
    }

    fn sign(&mut self, sign: SignFn, req: &Request, reply: &mut [u64]) -> Result<usize, u64> {
        let next = self.rule.next(req.seq).map_err(|_| REFUSED)?;
        let msg = message(&self.identity, req);
        let mut signature = [0u8; SIGNATURE_LEN];
        if !sign(&mut signature, &msg, self.blob.seed()) {
            return Err(BAD_REQUEST);
        }
        let bytes = encode_reply(&Reply { signature, identity: self.identity });
        let n = layout::tpm::pack(&bytes, reply).ok_or(BAD_REQUEST)?;
        self.rule = next;
        Ok(n)
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
