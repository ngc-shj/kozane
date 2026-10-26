//! Hybrid release signatures (M5 plan C13): Ed25519 and ML-DSA-65 over the
//! same domain-separated message; a release verifies only when both do.

use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey};
use zeroize::Zeroize;

/// Prefixed to the manifest before signing, so these signatures cannot be
/// replayed as signatures over anything else either key signs.
pub const DOMAIN: &[u8] = b"kozane-release-v1\0";

pub struct SigningKeys {
    pub ed25519: [u8; 32],
    pub ml_dsa: MLDSA65SigningKey,
}

impl Drop for SigningKeys {
    fn drop(&mut self) {
        // zeroize, not fill: a plain store to memory nothing reads again is
        // a dead store the optimiser may remove (L12).
        self.ed25519.zeroize();
        self.ml_dsa.as_ref_mut().zeroize();
    }
}

pub struct VerifyingKeys {
    pub ed25519: [u8; 32],
    pub ml_dsa: MLDSA65VerificationKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SigError {
    Randomness,
    Ed25519Sign,
    MlDsaSign,
    Format(&'static str),
    Ed25519Invalid,
    MlDsaInvalid,
}

impl core::fmt::Display for SigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Randomness => write!(f, "no randomness"),
            Self::Ed25519Sign => write!(f, "Ed25519 signing failed"),
            Self::MlDsaSign => write!(f, "ML-DSA-65 signing failed"),
            Self::Format(what) => write!(f, "signature file: {what}"),
            Self::Ed25519Invalid => write!(f, "the Ed25519 signature does not verify"),
            Self::MlDsaInvalid => write!(f, "the ML-DSA-65 signature does not verify"),
        }
    }
}

fn message(manifest: &[u8]) -> Vec<u8> {
    [DOMAIN, manifest].concat()
}

pub fn keygen(random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<(SigningKeys, VerifyingKeys), SigError> {
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
    Ok((SigningKeys { ed25519: ed, ml_dsa: pair.signing_key }, VerifyingKeys { ed25519: ed_pub, ml_dsa: pair.verification_key }))
}

/// The signature file: `ed25519=<hex>` then `ml-dsa-65=<hex>`, LF each.
pub fn sign(keys: &SigningKeys, manifest: &[u8], random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<Vec<u8>, SigError> {
    let msg = message(manifest);
    let ed = libcrux_ed25519::sign(&msg, &keys.ed25519).map_err(|_| SigError::Ed25519Sign)?;
    let mut r = [0u8; 32];
    if !random(&mut r) {
        return Err(SigError::Randomness);
    }
    let ml = ml_dsa_65::sign(&keys.ml_dsa, &msg, b"", r).map_err(|_| SigError::MlDsaSign)?;
    Ok(format!("ed25519={}\nml-dsa-65={}\n", hex(&ed), hex(ml.as_ref())).into_bytes())
}

/// Both signatures must verify (AND); a malformed file is refused before
/// either is checked.
pub fn verify(keys: &VerifyingKeys, manifest: &[u8], sig_file: &[u8]) -> Result<(), SigError> {
    let text = core::str::from_utf8(sig_file).map_err(|_| SigError::Format("not UTF-8"))?;
    let lines: Vec<&str> = text.strip_suffix('\n').ok_or(SigError::Format("no final LF"))?.split('\n').collect();
    let [ed_line, ml_line] = lines.as_slice() else {
        return Err(SigError::Format("expected exactly two lines"));
    };
    let ed_hex = ed_line.strip_prefix("ed25519=").ok_or(SigError::Format("first line is not ed25519="))?;
    let ml_hex = ml_line.strip_prefix("ml-dsa-65=").ok_or(SigError::Format("second line is not ml-dsa-65="))?;
    let ed: [u8; 64] = unhex(ed_hex).and_then(|v| v.try_into().ok()).ok_or(SigError::Format("bad Ed25519 signature"))?;
    let ml_bytes = unhex(ml_hex).ok_or(SigError::Format("bad ML-DSA-65 signature"))?;
    let mut ml = MLDSA65Signature::zero();
    if ml_bytes.len() != MLDSA65Signature::len() {
        return Err(SigError::Format("bad ML-DSA-65 signature length"));
    }
    ml.as_ref_mut().copy_from_slice(&ml_bytes);
    let msg = message(manifest);
    let ed_ok = libcrux_ed25519::verify(&msg, &keys.ed25519, &ed).is_ok();
    let ml_ok = ml_dsa_65::verify(&keys.ml_dsa, &msg, b"", &ml).is_ok();
    match (ed_ok, ml_ok) {
        (true, true) => Ok(()),
        (false, _) => Err(SigError::Ed25519Invalid),
        (true, false) => Err(SigError::MlDsaInvalid),
    }
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
