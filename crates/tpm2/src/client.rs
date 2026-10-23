//! The client side of one unseal flow (M5 plan C10), pure: it produces each
//! command and consumes each response, so `key`/`pqkey` only move bytes to
//! and from `tpm`.
//!
//! CreatePrimary → StartAuthSession → PolicyPCR → PolicyAuthValue → Import
//! → Load → Unseal → FlushContext × 3 (object, session, SRK), then the
//! caller sends `tpm` its explicit Done or Failed.
//!
//! - I10.2: the CreatePrimary result's Name must equal the envelope's
//!   pinned SRK Name, and the session is salted by ECDH to the pinned SRK
//!   point, not to anything a response carries: a foreign TPM fails here.
//! - S17: the client computes the object Name from its own envelope,
//!   refuses a Load whose Name differs, and binds its own Name into
//!   Unseal's cpHash.
//! - I10.1: Unseal's response HMAC is verified, in constant time
//!   (`wg_core::crypto::ct_eq`), before any response parameter is used;
//!   only then is outData decrypted (the session's `encrypt` attribute,
//!   AES-128-CFB).
//! - I10.3: the KEK exists only here, decrypted, and is wiped right after
//!   the envelope opens (`finish`), on every path; so are the salt and the
//!   session key.
//!
//! After any failure the client still flushes every handle it holds, so
//! the TPM's object slots are free for the other client, then reports the
//! failure. The PolicyPCR, PolicyAuthValue, Import, Load and FlushContext
//! responses are not authenticated: a lie there can only make Unseal fail
//! (the TPM checks the policy and the command HMAC), never yield a KEK the
//! client accepts.

use tpm2_wire::{
    CC_UNSEAL, COORD_LEN, DIGEST_LEN, MAX_PRIVATE, NAME_LEN, NONCE_LEN, NONCE_MIN, POINT_LEN, RspError,
    SESSION_CONTINUE, SESSION_ENCRYPT,
};
use wg_core::crypto::{Key32, ct_eq};

use crate::Secret;
use crate::crypto::{self, AES_BLOCK_LEN, AES_KEY_LEN};
use crate::envelope::{EnvError, Envelope, Kind};

/// Client entropy: ephemeral ECDH scalar ‖ StartAuthSession's nonceCaller ‖
/// Unseal's nonceCaller.
pub const CLIENT_ENTROPY_LEN: usize = 3 * 32;

/// Unseal's session attributes: keep the session (the client flushes it)
/// and encrypt the response parameter.
pub const UNSEAL_ATTRIBUTES: u8 = SESSION_CONTINUE | SESSION_ENCRYPT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    CreatePrimary,
    StartAuthSession,
    PolicyPcr,
    PolicyAuthValue,
    Import,
    Load,
    Unseal,
    FlushObject,
    FlushSession,
    FlushPrimary,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Envelope(EnvError),
    /// The ephemeral scalar is zero or not below the group order.
    Entropy,
    /// A command did not fit the caller's buffer.
    Buffer,
    /// A response without a command, a command before the last response,
    /// or `finish` before the flow ended.
    Order,
    /// The response does not parse, or the TPM refused (`RspError::Tpm`).
    Response(RspError),
    /// CreatePrimary's Name is not the pinned SRK's (I10.2).
    SrkName,
    /// Load's Name is not the envelope object's (S17).
    LoadName,
    /// Unseal's response HMAC does not verify (I10.1).
    ResponseHmac,
    /// Unseal's response attributes are not the ones sent.
    ResponseAttributes,
    /// outData is not a 32-byte KEK.
    OutData,
    /// The KEK does not open the envelope.
    Open(EnvError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub step: Step,
    pub cause: Cause,
}

pub struct Client<'e> {
    envelope: Envelope<'e>,
    object_name: [u8; NAME_LEN],
    step: Step,
    awaiting: bool,
    failure: Option<Failure>,
    srk: Option<u32>,
    session: Option<u32>,
    object: Option<u32>,
    /// The encrypted salt: the ephemeral point as a TPMS_ECC_POINT.
    salt_point: [u8; POINT_LEN],
    salt: Secret<DIGEST_LEN>,
    nonce_start: [u8; NONCE_LEN],
    nonce_unseal: [u8; NONCE_LEN],
    nonce_tpm: [u8; NONCE_LEN],
    nonce_tpm_len: usize,
    session_key: Secret<DIGEST_LEN>,
    private: [u8; MAX_PRIVATE],
    private_len: usize,
    kek: Secret<32>,
    unsealed: bool,
}

impl<'e> Client<'e> {
    /// Parses the envelope and salts the session-to-be: Z by ECDH of the
    /// ephemeral scalar with the pinned SRK point, salt = KDFe(Z, "SECRET",
    /// ephemeral x, SRK x). The scalar is not kept. A failure here needs no
    /// flow (no handle exists yet).
    pub fn new(envelope: &'e [u8], kind: Kind, entropy: &Secret<CLIENT_ENTROPY_LEN>) -> Result<Self, Failure> {
        let fail = |cause| Failure { step: Step::CreatePrimary, cause };
        let envelope = Envelope::parse(envelope, kind).map_err(|e| fail(Cause::Envelope(e)))?;
        let (scalar_bytes, nonces) = entropy.as_bytes().split_at(32);
        let (nonce_start, nonce_unseal) = nonces.split_at(NONCE_LEN);
        let mut scalar = Secret::<COORD_LEN>::zero();
        scalar.as_mut_bytes().copy_from_slice(scalar_bytes);
        let ephemeral = crypto::public_point(&scalar).ok_or(fail(Cause::Entropy))?;
        let srk_xy = envelope.srk_xy();
        let mut z = Secret::<COORD_LEN>::zero();
        crypto::ecdh(&mut z, &scalar, &srk_xy).ok_or(fail(Cause::Envelope(EnvError::SrkPublic)))?;
        scalar.wipe();
        let mut salt = Secret::<DIGEST_LEN>::zero();
        let (ex, _) = ephemeral.split_at(COORD_LEN);
        let (sx, _) = srk_xy.split_at(COORD_LEN);
        crypto::kdfe(&mut salt, z.as_bytes(), b"SECRET", ex, sx);
        z.wipe();
        let mut client = Self {
            object_name: envelope.object_name(),
            envelope,
            step: Step::CreatePrimary,
            awaiting: false,
            failure: None,
            srk: None,
            session: None,
            object: None,
            salt_point: crypto::ecc_point(&ephemeral),
            salt,
            nonce_start: [0; NONCE_LEN],
            nonce_unseal: [0; NONCE_LEN],
            nonce_tpm: [0; NONCE_LEN],
            nonce_tpm_len: 0,
            session_key: Secret::zero(),
            private: [0; MAX_PRIVATE],
            private_len: 0,
            kek: Secret::zero(),
            unsealed: false,
        };
        client.nonce_start.copy_from_slice(nonce_start);
        client.nonce_unseal.copy_from_slice(nonce_unseal);
        Ok(client)
    }

    pub fn step(&self) -> Step {
        self.step
    }

    pub fn failure(&self) -> Option<Failure> {
        self.failure
    }

    /// Records the first failure, wipes the session secrets and the KEK, and
    /// moves on to the flushes.
    fn fail(&mut self, cause: Cause) {
        if self.failure.is_none() {
            self.failure = Some(Failure { step: self.step, cause });
        }
        self.salt.wipe();
        self.session_key.wipe();
        self.kek.wipe();
        self.unsealed = false;
        if matches!(
            self.step,
            Step::CreatePrimary
                | Step::StartAuthSession
                | Step::PolicyPcr
                | Step::PolicyAuthValue
                | Step::Import
                | Step::Load
                | Step::Unseal
        ) {
            self.step = Step::FlushObject;
        }
    }

    fn nonce_tpm(&self) -> &[u8] {
        self.nonce_tpm.get(..self.nonce_tpm_len).unwrap_or(&[])
    }

    /// Skips flushes of handles the client never got.
    fn skip_unheld(&mut self) {
        loop {
            self.step = match self.step {
                Step::FlushObject if self.object.is_none() => Step::FlushSession,
                Step::FlushSession if self.session.is_none() => Step::FlushPrimary,
                Step::FlushPrimary if self.srk.is_none() => Step::Finished,
                _ => return,
            };
        }
    }

    /// Writes the next command into `out` and returns its length; None once
    /// the flow is over (then `finish`).
    pub fn command(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.awaiting {
            self.awaiting = false;
            self.fail(Cause::Order);
        }
        self.skip_unheld();
        let written = match self.step {
            Step::CreatePrimary => tpm2_wire::create_primary(out),
            Step::StartAuthSession => {
                let srk = self.srk?;
                tpm2_wire::start_auth_session(out, srk, &self.nonce_start, &self.salt_point)
            }
            Step::PolicyPcr => tpm2_wire::policy_pcr(out, self.session?),
            Step::PolicyAuthValue => tpm2_wire::policy_auth_value(out, self.session?),
            Step::Import => tpm2_wire::import(
                out,
                self.srk?,
                self.envelope.object_public(),
                self.envelope.duplicate(),
                self.envelope.in_sym_seed(),
            ),
            Step::Load => tpm2_wire::load(
                out,
                self.srk?,
                self.private.get(..self.private_len)?,
                self.envelope.object_public(),
            ),
            Step::Unseal => self.unseal_command(out),
            Step::FlushObject => tpm2_wire::flush_context(out, self.object?),
            Step::FlushSession => tpm2_wire::flush_context(out, self.session?),
            Step::FlushPrimary => tpm2_wire::flush_context(out, self.srk?),
            Step::Finished => return None,
        };
        match written {
            Some(n) => {
                self.awaiting = true;
                Some(n)
            }
            None => {
                self.fail(Cause::Buffer);
                self.step = Step::Finished;
                None
            }
        }
    }

    /// cpHash = H(CC_Unseal ‖ Name(object)), with the client's own Name;
    /// HMAC(sessionKey ‖ authValue (empty), cpHash ‖ nonceCaller ‖
    /// nonceTPM ‖ attributes).
    fn unseal_command(&mut self, out: &mut [u8]) -> Option<usize> {
        let cp_hash = crypto::sha256(&[&CC_UNSEAL.to_be_bytes(), &self.object_name]);
        let mut hmac = [0u8; DIGEST_LEN];
        crypto::hmac(
            &mut hmac,
            self.session_key.as_bytes(),
            &[&cp_hash, &self.nonce_unseal, self.nonce_tpm(), &[UNSEAL_ATTRIBUTES]],
        )?;
        tpm2_wire::unseal(out, self.object?, self.session?, &self.nonce_unseal, UNSEAL_ATTRIBUTES, &hmac)
    }

    /// Consumes the response to the last command.
    pub fn response(&mut self, rsp: &[u8]) {
        if !self.awaiting {
            self.fail(Cause::Order);
            return;
        }
        self.awaiting = false;
        let next = match self.step {
            Step::CreatePrimary => self.on_create_primary(rsp).map(|()| Step::StartAuthSession),
            Step::StartAuthSession => self.on_start_auth_session(rsp).map(|()| Step::PolicyPcr),
            Step::PolicyPcr => tpm2_wire::parse_empty(rsp).map_err(Cause::Response).map(|()| Step::PolicyAuthValue),
            Step::PolicyAuthValue => tpm2_wire::parse_empty(rsp).map_err(Cause::Response).map(|()| Step::Import),
            Step::Import => self.on_import(rsp).map(|()| Step::Load),
            Step::Load => self.on_load(rsp).map(|()| Step::Unseal),
            Step::Unseal => self.on_unseal(rsp).map(|()| Step::FlushObject),
            // A failed flush leaves the handle to the TPM's next reset; the
            // flow's outcome does not depend on it.
            Step::FlushObject => Ok(Step::FlushSession),
            Step::FlushSession => Ok(Step::FlushPrimary),
            Step::FlushPrimary => Ok(Step::Finished),
            Step::Finished => Err(Cause::Order),
        };
        match next {
            Ok(step) => self.step = step,
            Err(cause) => self.fail(cause),
        }
    }

    fn on_create_primary(&mut self, rsp: &[u8]) -> Result<(), Cause> {
        let r = tpm2_wire::parse_create_primary(rsp).map_err(Cause::Response)?;
        // The handle is the client's to flush even if the Name is wrong.
        self.srk = Some(r.handle);
        if r.name != self.envelope.srk_name() {
            return Err(Cause::SrkName);
        }
        Ok(())
    }

    /// sessionKey = KDFa(salt, "ATH", nonceTPM, nonceCaller, 256): the
    /// session is unbound, so the salt is the whole key input.
    fn on_start_auth_session(&mut self, rsp: &[u8]) -> Result<(), Cause> {
        let r = tpm2_wire::parse_start_auth_session(rsp).map_err(Cause::Response)?;
        self.session = Some(r.handle);
        let nonce = self.nonce_tpm.get_mut(..r.nonce_tpm.len()).ok_or(Cause::Response(RspError::Malformed))?;
        nonce.copy_from_slice(r.nonce_tpm);
        self.nonce_tpm_len = r.nonce_tpm.len();
        crypto::kdfa(
            self.salt.as_bytes(),
            b"ATH",
            r.nonce_tpm,
            &self.nonce_start,
            self.session_key.as_mut_bytes(),
        )
        .ok_or(Cause::Buffer)?;
        self.salt.wipe();
        Ok(())
    }

    fn on_import(&mut self, rsp: &[u8]) -> Result<(), Cause> {
        let private = tpm2_wire::parse_import(rsp).map_err(Cause::Response)?;
        self.private.get_mut(..private.len()).ok_or(Cause::Response(RspError::Malformed))?.copy_from_slice(private);
        self.private_len = private.len();
        Ok(())
    }

    fn on_load(&mut self, rsp: &[u8]) -> Result<(), Cause> {
        let r = tpm2_wire::parse_load(rsp).map_err(Cause::Response)?;
        self.object = Some(r.handle);
        if r.name != self.object_name {
            return Err(Cause::LoadName);
        }
        Ok(())
    }

    /// rpHash = H(rc (0) ‖ CC_Unseal ‖ parameters as received);
    /// HMAC(sessionKey, rpHash ‖ nonceTPM (new) ‖ nonceCaller ‖ attributes)
    /// must match before outData is touched. Then the CFB key and IV are
    /// KDFa(sessionKey, "CFB", nonceTPM, nonceCaller, 256).
    fn on_unseal(&mut self, rsp: &[u8]) -> Result<(), Cause> {
        let r = tpm2_wire::parse_unseal(rsp).map_err(Cause::Response)?;
        let rp_hash = crypto::sha256(&[&0u32.to_be_bytes(), &CC_UNSEAL.to_be_bytes(), r.params]);
        let mut expected = [0u8; DIGEST_LEN];
        crypto::hmac(
            &mut expected,
            self.session_key.as_bytes(),
            &[&rp_hash, r.auth.nonce, &self.nonce_unseal, &[r.auth.attributes]],
        )
        .ok_or(Cause::Buffer)?;
        if !ct_eq(&expected, r.auth.hmac) {
            return Err(Cause::ResponseHmac);
        }
        // Authenticated from here on.
        if r.auth.attributes != UNSEAL_ATTRIBUTES {
            return Err(Cause::ResponseAttributes);
        }
        if r.out_data.len() != 32 || r.auth.nonce.len() < NONCE_MIN {
            return Err(Cause::OutData);
        }
        let mut key_iv = Secret::<{ AES_KEY_LEN + AES_BLOCK_LEN }>::zero();
        crypto::kdfa(self.session_key.as_bytes(), b"CFB", r.auth.nonce, &self.nonce_unseal, key_iv.as_mut_bytes())
            .ok_or(Cause::Buffer)?;
        let (key, iv) = key_iv.as_bytes().split_at(AES_KEY_LEN);
        let key: &[u8; AES_KEY_LEN] = key.try_into().map_err(|_| Cause::Buffer)?;
        let iv: &[u8; AES_BLOCK_LEN] = iv.try_into().map_err(|_| Cause::Buffer)?;
        self.kek.as_mut_bytes().copy_from_slice(r.out_data);
        crypto::cfb(key, iv, self.kek.as_mut_bytes(), true);
        self.session_key.wipe();
        self.unsealed = true;
        Ok(())
    }

    /// After `command` returned None: opens the envelope with the unsealed
    /// KEK into `out` (the region's size) and wipes the KEK, on every path.
    /// On failure `out` is all zero (I11.1).
    pub fn finish(mut self, out: &mut [u8]) -> Result<(), Failure> {
        out.fill(0);
        if self.step != Step::Finished || self.awaiting {
            self.fail(Cause::Order);
        }
        if let Some(f) = self.failure {
            return Err(f);
        }
        if !self.unsealed {
            return Err(Failure { step: Step::Finished, cause: Cause::Order });
        }
        let kek = Key32::copy_from(self.kek.as_bytes());
        self.kek.wipe();
        self.envelope.open(&kek, out).map_err(|e| Failure { step: Step::Finished, cause: Cause::Open(e) })
    }
}
