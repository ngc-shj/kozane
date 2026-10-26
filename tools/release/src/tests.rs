//! M5 plan C13's allow and deny fixtures.

use crate::manifest::{self, ManifestError};
use crate::sig::{self, SigError};

fn counter_rng() -> impl FnMut(&mut [u8]) -> bool {
    let mut n = 1u8;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            *b = n;
            n = n.wrapping_add(7);
        }
        true
    }
}

fn good_manifest() -> Vec<u8> {
    manifest::render(&[
        ("version", "m5-dev"),
        ("commit", "0123456789abcdef0123456789abcdef01234567"),
        ("dev_image", "sha256:aa"),
        ("loader_img_sha256", "bb"),
        ("boot_desc_sha256", "cc"),
        ("pcr8", "dd"),
        ("cargo_lock_sha256", "ee"),
        ("verus", "0.2026.10.04.426d8b0"),
        ("kani", "0.68.0"),
    ])
    .unwrap()
}

fn signed() -> (sig::VerifyingKeys, Vec<u8>, Vec<u8>) {
    let mut rng = counter_rng();
    let (sk, pk) = sig::keygen(&mut rng).unwrap();
    let m = good_manifest();
    let s = sig::sign(&sk, &m, &mut rng).unwrap();
    (pk, m, s)
}

#[test]
fn a_valid_dual_signed_manifest_verifies() {
    let (pk, m, s) = signed();
    assert_eq!(sig::verify(&pk, &m, &s), Ok(()));
    assert_eq!(manifest::parse(&m).unwrap().len(), manifest::KEYS.len());
}

#[test]
fn a_flipped_manifest_byte_fails_both() {
    let (pk, mut m, s) = signed();
    m[3] ^= 1;
    assert_eq!(sig::verify(&pk, &m, &s), Err(SigError::Ed25519Invalid));
}

#[test]
fn a_bad_ed25519_signature_alone_fails() {
    let (pk, m, s) = signed();
    let mut t = String::from_utf8(s).unwrap();
    let flip = if t.as_bytes()[8] == b'0' { "1" } else { "0" };
    t.replace_range(8..9, flip);
    assert_eq!(sig::verify(&pk, &m, t.as_bytes()), Err(SigError::Ed25519Invalid));
}

#[test]
fn a_bad_ml_dsa_signature_alone_fails() {
    let (pk, m, s) = signed();
    let mut t = String::from_utf8(s).unwrap();
    let at = t.find("ml-dsa-65=").unwrap() + "ml-dsa-65=".len() + 10;
    let flip = if t.as_bytes()[at] == b'0' { "1" } else { "0" };
    t.replace_range(at..at + 1, flip);
    assert_eq!(sig::verify(&pk, &m, t.as_bytes()), Err(SigError::MlDsaInvalid));
}

#[test]
fn a_missing_ml_dsa_line_is_refused() {
    let (pk, m, s) = signed();
    let t = String::from_utf8(s).unwrap();
    let first = t.split_inclusive('\n').next().unwrap();
    assert_eq!(sig::verify(&pk, &m, first.as_bytes()), Err(SigError::Format("expected exactly two lines")));
}

#[test]
fn another_keys_signatures_are_refused() {
    let (_, m, s) = signed();
    let mut rng = |buf: &mut [u8]| {
        buf.fill(0x5a);
        true
    };
    let (_, other) = sig::keygen(&mut rng).unwrap();
    assert_eq!(sig::verify(&other, &m, &s), Err(SigError::Ed25519Invalid));
}

#[test]
fn the_domain_prefix_is_part_of_what_is_signed() {
    let (pk, m, s) = signed();
    let mut unprefixed = m.clone();
    unprefixed.splice(0..0, b"x".iter().copied());
    assert!(sig::verify(&pk, &unprefixed, &s).is_err());
    assert_eq!(sig::DOMAIN, b"kozane-release-v1\0");
}

/// The pre-rename domain is refused even under the right keys: the
/// verifier knows only `DOMAIN`, never both (post-M6 plan P7).
#[test]
fn a_signature_over_the_old_domain_is_refused() {
    let mut rng = counter_rng();
    let (sk, pk) = sig::keygen(&mut rng).unwrap();
    let m = good_manifest();
    let old = [b"secureos-release-v1\0".as_slice(), &m].concat();
    let ed = libcrux_ed25519::sign(&old, &sk.ed25519).unwrap();
    let ml = libcrux_ml_dsa::ml_dsa_65::sign(&sk.ml_dsa, &old, b"", [9; 32]).unwrap();
    let file = format!("ed25519={}\nml-dsa-65={}\n", sig::hex(&ed), sig::hex(ml.as_ref()));
    assert_eq!(sig::verify(&pk, &m, file.as_bytes()), Err(SigError::Ed25519Invalid));
    // The same construction over the current domain verifies, so the refusal
    // above is the domain's doing.
    let new = [sig::DOMAIN, &m].concat();
    let ed = libcrux_ed25519::sign(&new, &sk.ed25519).unwrap();
    let ml = libcrux_ml_dsa::ml_dsa_65::sign(&sk.ml_dsa, &new, b"", [9; 32]).unwrap();
    let file = format!("ed25519={}\nml-dsa-65={}\n", sig::hex(&ed), sig::hex(ml.as_ref()));
    assert_eq!(sig::verify(&pk, &m, file.as_bytes()), Ok(()));
}

#[test]
fn a_duplicate_key_is_refused() {
    let mut m = good_manifest();
    m.extend_from_slice(b"version=again\n");
    assert_eq!(manifest::parse(&m), Err(ManifestError::Duplicate("version".into())));
}

#[test]
fn an_unknown_key_is_refused() {
    let m = [good_manifest(), b"zzz=1\n".to_vec()].concat();
    assert_eq!(manifest::parse(&m), Err(ManifestError::Unknown("zzz".into())));
}

#[test]
fn a_missing_key_is_refused() {
    let m: Vec<u8> = good_manifest().split_inclusive(|&b| b == b'\n').filter(|l| !l.starts_with(b"pcr8=")).flatten().copied().collect();
    assert_eq!(manifest::parse(&m), Err(ManifestError::Missing("pcr8".into())));
}

#[test]
fn unsorted_keys_are_refused() {
    let lines: Vec<&[u8]> = good_manifest().leak().split_inclusive(|&b| b == b'\n').collect();
    let mut swapped = lines.clone();
    swapped.swap(0, 1);
    assert_eq!(manifest::parse(&swapped.concat()), Err(ManifestError::Unsorted("boot_desc_sha256".into())));
}

#[test]
fn a_crlf_line_end_is_refused() {
    let m = String::from_utf8(good_manifest()).unwrap().replacen('\n', "\r\n", 1);
    assert_eq!(manifest::parse(m.as_bytes()), Err(ManifestError::BadValue(1)));
}

#[test]
fn a_missing_final_newline_is_refused() {
    let mut m = good_manifest();
    m.pop();
    assert_eq!(manifest::parse(&m), Err(ManifestError::NoFinalNewline));
}

#[test]
fn uppercase_hex_in_a_signature_file_is_refused() {
    let (pk, m, s) = signed();
    let t = String::from_utf8(s).unwrap().to_uppercase().replace("ED25519=", "ed25519=").replace("ML-DSA-65=", "ml-dsa-65=");
    assert_eq!(sig::verify(&pk, &m, t.as_bytes()), Err(SigError::Format("bad Ed25519 signature")));
}
