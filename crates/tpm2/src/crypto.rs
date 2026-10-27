//! The TPM 2.0 Part 1 primitives of the flow, over libcrux (SHA-256,
//! HMAC-SHA256, P-256 ECDH) and RustCrypto's `aes` (the block cipher; CFB
//! is the few lines below): KDFa (SP 800-108 counter mode, §11.4.10.2),
//! KDFe (SP 800-56A concatenation KDF, §11.4.10.3), CFB-128 (§11.4.6.3),
//! the policy digest and object Names.
//!
//! libcrux's and `aes`' internal stack state (hash states, HMAC pads) is
//! not zeroized by them; values owned here are. `aes` wipes its round keys
//! on drop (its `zeroize` feature).

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use libcrux_p256::P256;
use libcrux_p256::ecdh_api::EcdhArrayref;
use libcrux_sha2::{Digest, Sha256};
use tpm2_wire::{ALG_SHA256, CC_POLICY_AUTH_VALUE, CC_POLICY_PCR, COORD_LEN, DIGEST_LEN, NAME_LEN, POLICY_PCR_COUNT,
    POLICY_PCR_SELECTION};
use zeroize::Zeroize;

use crate::Secret;

pub const AES_KEY_LEN: usize = 16;
pub const AES_BLOCK_LEN: usize = 16;
/// An affine P-256 point, x ‖ y, big-endian.
pub const XY_LEN: usize = 2 * COORD_LEN;

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        // Inputs here are a few hundred bytes, far below the u32 limit
        // libcrux's update checks.
        h.update(p);
    }
    let mut out = [0u8; DIGEST_LEN];
    h.finish(&mut out);
    out
}

/// HMAC-SHA256(key, parts...). None only for inputs over 4 GiB.
pub fn hmac(out: &mut [u8; DIGEST_LEN], key: &[u8], parts: &[&[u8]]) -> Option<()> {
    libcrux_hmac::hmac_sha2_256_slices(out, key, parts).ok()
}

/// KDFa(SHA-256, key, label, contextU, contextV, 8·out.len()): HMAC over
/// counter ‖ label ‖ 0 ‖ contextU ‖ contextV ‖ bits, counter from 1.
/// `label` is given without its terminating zero.
pub fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], out: &mut [u8]) -> Option<()> {
    let bits = u32::try_from(out.len().checked_mul(8)?).ok()?;
    let mut counter = 0u32;
    let mut block = Secret::<DIGEST_LEN>::zero();
    for chunk in out.chunks_mut(DIGEST_LEN) {
        counter = counter.checked_add(1)?;
        hmac(
            block.as_mut_bytes(),
            key,
            &[&counter.to_be_bytes(), label, &[0], context_u, context_v, &bits.to_be_bytes()],
        )?;
        chunk.copy_from_slice(block.as_bytes().get(..chunk.len())?);
    }
    Some(())
}

/// KDFe(SHA-256, Z, label, partyUInfo, partyVInfo, 256): one block of
/// SHA-256(1 ‖ Z ‖ label ‖ 0 ‖ partyUInfo ‖ partyVInfo).
pub fn kdfe(out: &mut Secret<DIGEST_LEN>, z: &[u8; COORD_LEN], label: &[u8], party_u: &[u8], party_v: &[u8]) {
    *out.as_mut_bytes() = sha256(&[&1u32.to_be_bytes(), z, label, &[0], party_u, party_v]);
}

/// AES-128-CFB over `data` in place (full feedback; a short last block is
/// truncated).
pub fn cfb(key: &[u8; AES_KEY_LEN], iv: &[u8; AES_BLOCK_LEN], data: &mut [u8], decrypt: bool) {
    let cipher = Aes128::new(key.into());
    let mut feedback = *iv;
    let mut block = GenericArray::from([0u8; AES_BLOCK_LEN]);
    for chunk in data.chunks_mut(AES_BLOCK_LEN) {
        block.copy_from_slice(&feedback);
        cipher.encrypt_block(&mut block);
        for ((d, k), f) in chunk.iter_mut().zip(block.iter()).zip(feedback.iter_mut()) {
            let c = if decrypt { *d } else { *d ^ *k };
            *d ^= *k;
            *f = c;
        }
    }
    block.as_mut_slice().zeroize();
    feedback.zeroize();
}

/// [scalar]G as x ‖ y. None if the scalar is zero or not below the order.
pub fn public_point(scalar: &Secret<COORD_LEN>) -> Option<[u8; XY_LEN]> {
    <P256 as EcdhArrayref<COORD_LEN, COORD_LEN, XY_LEN>>::validate_secret(scalar.as_bytes()).ok()?;
    let mut public = [0u8; XY_LEN];
    <P256 as EcdhArrayref<COORD_LEN, COORD_LEN, XY_LEN>>::secret_to_public(&mut public, scalar.as_bytes()).ok()?;
    Some(public)
}

/// Z = x([scalar]peer). None if `peer` is not on the curve or the scalar
/// is invalid.
pub fn ecdh(z: &mut Secret<COORD_LEN>, scalar: &Secret<COORD_LEN>, peer: &[u8; XY_LEN]) -> Option<()> {
    let mut shared = Secret::<XY_LEN>::zero();
    <P256 as EcdhArrayref<COORD_LEN, COORD_LEN, XY_LEN>>::derive_ecdh(shared.as_mut_bytes(), peer, scalar.as_bytes())
        .ok()?;
    z.as_mut_bytes().copy_from_slice(shared.as_bytes().get(..COORD_LEN)?);
    Some(())
}

/// x ‖ y of a point from its two coordinates.
pub fn xy(x: &[u8; COORD_LEN], y: &[u8; COORD_LEN]) -> [u8; XY_LEN] {
    let mut out = [0u8; XY_LEN];
    let (ox, oy) = out.split_at_mut(COORD_LEN);
    ox.copy_from_slice(x);
    oy.copy_from_slice(y);
    out
}

/// The TPMS_ECC_POINT of x ‖ y: each coordinate as a TPM2B.
pub fn ecc_point(xy: &[u8; XY_LEN]) -> [u8; tpm2_wire::POINT_LEN] {
    let mut out = [0u8; tpm2_wire::POINT_LEN];
    let size = (COORD_LEN as u16).to_be_bytes();
    let (x, y) = xy.split_at(COORD_LEN);
    for (o, b) in out.iter_mut().zip(size.iter().chain(x).chain(size.iter()).chain(y)) {
        *o = *b;
    }
    out
}

/// A Name: nameAlg ‖ SHA-256(TPMT_PUBLIC).
pub fn name(public: &[u8]) -> [u8; NAME_LEN] {
    let mut out = [0u8; NAME_LEN];
    let (alg, digest) = out.split_at_mut(2);
    alg.copy_from_slice(&ALG_SHA256.to_be_bytes());
    digest.copy_from_slice(&sha256(&[public]));
    out
}

/// The values of PCRs 0-8, in index order: what the seal policy names.
pub type PolicyPcrs = [[u8; DIGEST_LEN]; POLICY_PCR_COUNT];

/// The policy digest of PolicyPCR(PCRs 0-8 = `pcrs`, sha256) alone: the
/// pcrDigest is the hash of the selected values concatenated in index order.
pub fn policy_pcr_digest(pcrs: &PolicyPcrs) -> [u8; DIGEST_LEN] {
    let values: [&[u8]; POLICY_PCR_COUNT] = pcrs.each_ref().map(|p| p.as_slice());
    sha256(&[&[0u8; DIGEST_LEN], &CC_POLICY_PCR.to_be_bytes(), &POLICY_PCR_SELECTION, &sha256(&values)])
}

/// The seal policy (M5 plan C11, M7 plan C4): PolicyPCR(0-8, sha256) ∧
/// PolicyAuthValue.
pub fn policy_digest(pcrs: &PolicyPcrs) -> [u8; DIGEST_LEN] {
    sha256(&[&policy_pcr_digest(pcrs), &CC_POLICY_AUTH_VALUE.to_be_bytes()])
}
