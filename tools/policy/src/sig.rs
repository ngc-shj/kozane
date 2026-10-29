//! Signatures (M8 plan C2, D1, D11): the hybrid Ed25519+ML-DSA-65 pair over
//! a bundle body (same construction as `tools/release`, under
//! `policy_wire::DOMAIN`), and the plain Ed25519 approver signatures over
//! approval and restore-approval records, each under its own domain so a
//! signature from one role can never be replayed as another's.

use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey};
use zeroize::Zeroize;

/// Approval records (C2): `approver_id, body_sha256, version, fleet_id,
/// prev_sha256, diff_sha256, roster_sha256, ts`.
pub const APPROVAL_DOMAIN: &[u8] = b"kozane-policy-approval-v1\0";
/// Restore-approval records (D11): `approver_id, fleet_id, head_version,
/// head_body_sha256, ts`.
pub const RESTORE_DOMAIN: &[u8] = b"kozane-ledger-restore-v1\0";

#[derive(Debug, PartialEq, Eq)]
pub enum SigError {
    Randomness,
    Ed25519Sign,
    MlDsaSign,
    Ed25519Invalid,
    MlDsaInvalid,
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Randomness => write!(f, "no randomness"),
            Self::Ed25519Sign => write!(f, "Ed25519 signing failed"),
            Self::MlDsaSign => write!(f, "ML-DSA-65 signing failed"),
            Self::Ed25519Invalid => write!(f, "the Ed25519 signature does not verify"),
            Self::MlDsaInvalid => write!(f, "the ML-DSA-65 signature does not verify"),
        }
    }
}

pub fn urandom(buf: &mut [u8]) -> bool {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex only, even length.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

// --- Bundle signing (Ed25519 + ML-DSA-65, D1) ---------------------------

pub struct BundleSigningKeys {
    pub ed25519: [u8; 32],
    pub ml_dsa: MLDSA65SigningKey,
}

impl Drop for BundleSigningKeys {
    fn drop(&mut self) {
        // zeroize, not fill: a plain store nothing reads again is a dead
        // store the optimiser may remove (L12).
        self.ed25519.zeroize();
        self.ml_dsa.as_ref_mut().zeroize();
    }
}

pub struct BundleVerifyingKeys {
    pub ed25519: [u8; 32],
    pub ml_dsa: MLDSA65VerificationKey,
}

pub fn bundle_keygen(random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<(BundleSigningKeys, BundleVerifyingKeys), SigError> {
    let mut ed = [0u8; 32];
    let mut seed = [0u8; 32];
    if !random(&mut ed) || !random(&mut seed) || ed.iter().all(|&b| b == 0) {
        ed.zeroize();
        seed.zeroize();
        return Err(SigError::Randomness);
    }
    let mut ed_pub = [0u8; 32];
    libcrux_ed25519::secret_to_public(&mut ed_pub, &ed);
    let pair = ml_dsa_65::generate_key_pair(seed);
    seed.zeroize();
    Ok((BundleSigningKeys { ed25519: ed, ml_dsa: pair.signing_key }, BundleVerifyingKeys { ed25519: ed_pub, ml_dsa: pair.verification_key }))
}

/// Signs `domain ‖ body` (`body` is `policy_wire::split`'s body, i.e. the
/// slot up to but excluding both signature fields), returning the raw
/// fixed-size signatures in wire order.
pub fn bundle_sign(keys: &BundleSigningKeys, domain: &[u8], body: &[u8], random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<([u8; 64], [u8; 3309]), SigError> {
    let msg = [domain, body].concat();
    let ed = libcrux_ed25519::sign(&msg, &keys.ed25519).map_err(|_| SigError::Ed25519Sign)?;
    let mut r = [0u8; 32];
    if !random(&mut r) {
        return Err(SigError::Randomness);
    }
    let ml = ml_dsa_65::sign(&keys.ml_dsa, &msg, b"", r).map_err(|_| SigError::MlDsaSign)?;
    let mut ml_bytes = [0u8; 3309];
    ml_bytes.copy_from_slice(ml.as_ref());
    Ok((ed, ml_bytes))
}

/// Both signatures must verify (AND), matching the device's check (D1).
pub fn bundle_verify(keys: &BundleVerifyingKeys, domain: &[u8], body: &[u8], sig_ed25519: &[u8; 64], sig_mldsa65: &[u8; 3309]) -> Result<(), SigError> {
    let msg = [domain, body].concat();
    let ed_ok = libcrux_ed25519::verify(&msg, &keys.ed25519, sig_ed25519).is_ok();
    let mut ml = MLDSA65Signature::zero();
    ml.as_ref_mut().copy_from_slice(sig_mldsa65);
    let ml_ok = ml_dsa_65::verify(&keys.ml_dsa, &msg, b"", &ml).is_ok();
    match (ed_ok, ml_ok) {
        (true, true) => Ok(()),
        (false, _) => Err(SigError::Ed25519Invalid),
        (true, false) => Err(SigError::MlDsaInvalid),
    }
}

// --- Approver signing (Ed25519 only) ------------------------------------

pub struct ApproverSigningKey(pub [u8; 32]);

impl Drop for ApproverSigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn approver_keygen(random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<([u8; 32], [u8; 32]), SigError> {
    let mut sk = [0u8; 32];
    if !random(&mut sk) || sk.iter().all(|&b| b == 0) {
        sk.zeroize();
        return Err(SigError::Randomness);
    }
    let mut pk = [0u8; 32];
    libcrux_ed25519::secret_to_public(&mut pk, &sk);
    Ok((sk, pk))
}

/// Signs `domain ‖ fields` (`fields` the canonical record bytes, never
/// including the trailing `sig_ed25519=` line).
pub fn approver_sign(sk: &ApproverSigningKey, domain: &[u8], fields: &[u8], random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<[u8; 64], SigError> {
    let _ = random; // Ed25519 here is deterministic (RFC 8032); kept for a uniform call shape.
    let msg = [domain, fields].concat();
    libcrux_ed25519::sign(&msg, &sk.0).map_err(|_| SigError::Ed25519Sign)
}

pub fn approver_verify(pk: &[u8; 32], domain: &[u8], fields: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
    let msg = [domain, fields].concat();
    libcrux_ed25519::verify(&msg, pk, sig).map_err(|_| SigError::Ed25519Invalid)
}
