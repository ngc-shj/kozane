//! The release verifier as a library (M9 plan C4): the `release` tool and
//! the host launcher `kozane-vm` link the same manifest parser and the same
//! signature check, so `pin-firmware` accepts exactly what `release verify`
//! accepts.

pub mod manifest;
pub mod sig;
#[cfg(test)]
mod tests;

use std::fs;
use std::path::Path;

use libcrux_ml_dsa::ml_dsa_65::MLDSA65VerificationKey;
use zeroize::Zeroizing;

/// The decoded file. Both the text and the bytes are wiped on drop: the
/// signing keys pass through here (L12).
pub fn read_hex(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?);
    sig::unhex(text.trim_end_matches('\n'))
        .map(Zeroizing::new)
        .ok_or(format!("{}: not lowercase hex", path.display()))
}

fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| format!("{what}: wrong length"))
}

/// The public halves `keygen` writes into `dir`.
pub fn load_verifying(dir: &Path) -> Result<sig::VerifyingKeys, String> {
    let text = |name: &str| fs::read_to_string(dir.join(name)).map_err(|e| format!("{}: {e}", dir.join(name).display()));
    verifying_from_hex(&text("ed25519.pub")?, &text("ml-dsa-65.pub")?)
}

/// The public halves from their files' text (lowercase hex and a newline),
/// for a caller that read them from descriptors it checked.
pub fn verifying_from_hex(ed25519: &str, ml_dsa: &str) -> Result<sig::VerifyingKeys, String> {
    let ed = sig::unhex(ed25519.trim_end_matches('\n')).ok_or("ed25519.pub: not lowercase hex")?;
    let ed = fixed::<32>(&ed, "ed25519.pub")?;
    let bytes = sig::unhex(ml_dsa.trim_end_matches('\n')).ok_or("ml-dsa-65.pub: not lowercase hex")?;
    if bytes.len() != MLDSA65VerificationKey::len() {
        return Err("ml-dsa-65.pub: wrong length".into());
    }
    let mut ml = MLDSA65VerificationKey::zero();
    ml.as_ref_mut().copy_from_slice(&bytes);
    Ok(sig::VerifyingKeys { ed25519: ed, ml_dsa: ml })
}

/// The fields of a canonical manifest whose two signatures both verify
/// under `keys`; anything else is refused.
pub fn verify_release(keys: &sig::VerifyingKeys, manifest: &[u8], sig_file: &[u8]) -> Result<Vec<(String, String)>, String> {
    let fields = manifest::parse(manifest).map_err(|e| e.to_string())?;
    sig::verify(keys, manifest, sig_file).map_err(|e| e.to_string())?;
    Ok(fields)
}
