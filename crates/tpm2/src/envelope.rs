//! The sealed secrets envelope (M5 plan C11): what the boot media carries in
//! place of a plaintext secrets blob. It fills its memory region exactly
//! (`Kind::region_size`) and holds:
//!
//! | offset | field                                                        |
//! |--------|--------------------------------------------------------------|
//! | 0      | magic "SOSSEAL1"                                             |
//! | 8      | version u32 = 1 (little-endian, as the other blobs)          |
//! | 12     | kind u32: 1 = `key`'s blob, 2 = `pqkey`'s                    |
//! | 16     | payload_len u32: plaintext bytes                             |
//! | 20     | pinned SRK Name (34)                                         |
//! | 54     | pinned SRK public, TPM2B_PUBLIC (2 + 90)                     |
//! | 146    | PCR selection, TPML_PCR_SELECTION {sha256: {8}} (10)         |
//! | 156    | policy digest (32)                                           |
//! | 188    | object public, TPM2B_PUBLIC (2 + 78)                         |
//! | 268    | duplicate, TPM2B_PRIVATE (2 + 108)                           |
//! | 378    | inSymSeed, TPM2B_ENCRYPTED_SECRET (2 + 68)                   |
//! | 448    | ChaCha20-Poly1305(KEK, nonce 0, aad = bytes [0, 448)) of the |
//! |        | blob without its trailing zeros: payload_len + 16 bytes      |
//! | …      | zero to the end of the region                                |
//!
//! TPM structures are in their TPM marshalling (big-endian) so the client
//! forwards them as they are. The sealed object is a keyedhash data object
//! holding the 32-byte KEK, with userWithAuth clear and authPolicy =
//! PolicyPCR(8, sha256) ∧ PolicyAuthValue under an empty authValue, so the
//! TPM checks the command HMAC under the salted session key (S9). Its
//! duplicate has an outer wrapper only (TPM 2.0 Part 1 §23.3.2), seeded by
//! ECDH to the SRK. The KEK is fresh per envelope (S13), which makes the
//! fixed AEAD nonce safe.
//!
//! The parser checks every length and every fixed field; the decision on
//! the contents is the AEAD tag's (and, for the KEK, the TPM's policy). The
//! header's policy copy must equal the object public's: the object public
//! is the one the TPM enforces (C12 reads it from there).

use secret_blob::pq;
use tpm2_wire::{
    COORD_LEN, DIGEST_LEN, DUPLICATE_LEN, NAME_LEN, PCR_SELECTION, POINT_LEN, SEALED_PUBLIC_LEN, SENSITIVE_LEN,
    SRK_PUBLIC_LEN, Writer,
};
use wg_core::crypto::{Key32, TAG_LEN, aead_open, aead_seal};

use crate::Secret;
use crate::crypto::{self, AES_KEY_LEN};

pub const MAGIC: [u8; 8] = *b"SOSSEAL1";
pub const VERSION: u32 = 1;

const KIND_AT: usize = 12;
const PAYLOAD_LEN_AT: usize = 16;
const SRK_NAME_AT: usize = 20;
const SRK_PUBLIC_AT: usize = SRK_NAME_AT + NAME_LEN;
const PCR_SELECTION_AT: usize = SRK_PUBLIC_AT + 2 + SRK_PUBLIC_LEN;
const POLICY_AT: usize = PCR_SELECTION_AT + PCR_SELECTION.len();
const OBJECT_PUBLIC_AT: usize = POLICY_AT + DIGEST_LEN;
const DUPLICATE_AT: usize = OBJECT_PUBLIC_AT + 2 + SEALED_PUBLIC_LEN;
const SEED_AT: usize = DUPLICATE_AT + 2 + DUPLICATE_LEN;
/// Everything before the ciphertext: the AEAD's associated data.
pub const HEADER_LEN: usize = SEED_AT + 2 + POINT_LEN;

const _: () = assert!(SRK_PUBLIC_AT == 54 && OBJECT_PUBLIC_AT == 188 && SEED_AT == 378 && HEADER_LEN == 448);

/// `key`'s blob: header, gateway private key, boot seed, TLS scalar, then
/// 32 bytes per peer and the checksum (secret_blob's layout, version 3).
const KEY_BLOB_FIXED: usize = 16 + 32 + 32 + 32;
const KEY_BLOB_PER_PEER: usize = 32;
const KEY_BLOB_CHECKSUM: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `key`'s WireGuard blob, the `secrets` region.
    Key,
    /// `pqkey`'s McEliece blob, the `pq_secrets` region.
    Pq,
}

impl Kind {
    pub const fn code(self) -> u32 {
        match self {
            Kind::Key => 1,
            Kind::Pq => 2,
        }
    }

    /// The region the envelope fills, which is the plaintext blob's too.
    pub const fn region_size(self) -> usize {
        match self {
            Kind::Key => secret_blob::REGION_SIZE,
            Kind::Pq => pq::REGION_SIZE,
        }
    }

    /// The most plaintext bytes an envelope of this kind carries.
    pub const fn capacity(self) -> usize {
        self.region_size().saturating_sub(HEADER_LEN).saturating_sub(TAG_LEN)
    }
}

/// The pq blob fits whole.
const _: () = assert!(pq::USED_LEN <= Kind::Pq.capacity());
/// The most peers a sealed `key` blob can carry: fewer than the plaintext
/// format's `secret_blob::MAX_PEERS`, which fills the whole region.
pub const KEY_MAX_PEERS: usize = (Kind::Key.capacity() - KEY_BLOB_FIXED - KEY_BLOB_CHECKSUM) / KEY_BLOB_PER_PEER;
const _: () = assert!(KEY_MAX_PEERS == 109 && KEY_MAX_PEERS < secret_blob::MAX_PEERS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvError {
    /// The envelope or the output is not the region's size.
    Size,
    BadMagic,
    BadVersion,
    /// Not the kind the caller expects.
    BadKind,
    /// payload_len past the capacity.
    BadLength,
    /// The SRK public is not the SRK template's with a point.
    SrkPublic,
    /// The pinned Name is not the SRK public's.
    SrkName,
    PcrSelection,
    /// The object public is not a sealed object's.
    ObjectPublic,
    /// The header's policy differs from the object public's.
    Policy,
    Duplicate,
    Seed,
    NonZeroPadding,
    /// The AEAD tag did not verify.
    Auth,
    /// Sealing only: the SRK point is not on the curve, an entropy scalar is
    /// invalid, or the plaintext is too long or not the region's size.
    Seal,
}

fn field<const N: usize>(b: &[u8], at: usize) -> Option<&[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// The contents of the TPM2B at `at`, which must have exactly `len` bytes.
fn tpm2b(b: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    let size = field::<2>(b, at)?;
    if usize::from(u16::from_be_bytes(*size)) != len {
        return None;
    }
    let start = at.checked_add(2)?;
    b.get(start..start.checked_add(len)?)
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    field::<4>(b, at).map(|f| u32::from_le_bytes(*f))
}

/// A validated view of an envelope. Borrowed; everything in it is public
/// until the AEAD opens it.
#[derive(Clone, Copy)]
pub struct Envelope<'a> {
    bytes: &'a [u8],
    payload_len: usize,
}

impl<'a> Envelope<'a> {
    pub fn parse(bytes: &'a [u8], kind: Kind) -> Result<Self, EnvError> {
        if bytes.len() != kind.region_size() {
            return Err(EnvError::Size);
        }
        if field::<8>(bytes, 0) != Some(&MAGIC) {
            return Err(EnvError::BadMagic);
        }
        if u32_le(bytes, 8) != Some(VERSION) {
            return Err(EnvError::BadVersion);
        }
        if u32_le(bytes, KIND_AT) != Some(kind.code()) {
            return Err(EnvError::BadKind);
        }
        let payload_len =
            u32_le(bytes, PAYLOAD_LEN_AT).and_then(|n| usize::try_from(n).ok()).ok_or(EnvError::BadLength)?;
        if payload_len > kind.capacity() {
            return Err(EnvError::BadLength);
        }
        let srk_public = tpm2b(bytes, SRK_PUBLIC_AT, SRK_PUBLIC_LEN).ok_or(EnvError::SrkPublic)?;
        tpm2_wire::srk_point(srk_public).ok_or(EnvError::SrkPublic)?;
        if field::<NAME_LEN>(bytes, SRK_NAME_AT) != Some(&crypto::name(srk_public)) {
            return Err(EnvError::SrkName);
        }
        if field::<10>(bytes, PCR_SELECTION_AT) != Some(&PCR_SELECTION) {
            return Err(EnvError::PcrSelection);
        }
        let object_public = tpm2b(bytes, OBJECT_PUBLIC_AT, SEALED_PUBLIC_LEN).ok_or(EnvError::ObjectPublic)?;
        let object_policy = tpm2_wire::sealed_policy(object_public).ok_or(EnvError::ObjectPublic)?;
        if field::<DIGEST_LEN>(bytes, POLICY_AT) != Some(object_policy) {
            return Err(EnvError::Policy);
        }
        let duplicate = tpm2b(bytes, DUPLICATE_AT, DUPLICATE_LEN).ok_or(EnvError::Duplicate)?;
        if tpm2b(duplicate, 0, DIGEST_LEN).is_none() {
            return Err(EnvError::Duplicate);
        }
        let seed = tpm2b(bytes, SEED_AT, POINT_LEN).ok_or(EnvError::Seed)?;
        if tpm2b(seed, 0, COORD_LEN).is_none() || tpm2b(seed, 2 + COORD_LEN, COORD_LEN).is_none() {
            return Err(EnvError::Seed);
        }
        let end = HEADER_LEN.checked_add(payload_len).and_then(|n| n.checked_add(TAG_LEN)).ok_or(EnvError::BadLength)?;
        if bytes.get(end..).ok_or(EnvError::BadLength)?.iter().any(|b| *b != 0) {
            return Err(EnvError::NonZeroPadding);
        }
        Ok(Self { bytes, payload_len })
    }

    fn at(&self, at: usize, len: usize) -> &'a [u8] {
        tpm2b(self.bytes, at, len).unwrap_or(&[])
    }

    pub fn srk_name(&self) -> &'a [u8] {
        self.bytes.get(SRK_NAME_AT..SRK_PUBLIC_AT).unwrap_or(&[])
    }

    /// The pinned SRK's TPMT_PUBLIC.
    pub fn srk_public(&self) -> &'a [u8] {
        self.at(SRK_PUBLIC_AT, SRK_PUBLIC_LEN)
    }

    /// The pinned SRK's point, x ‖ y.
    pub fn srk_xy(&self) -> [u8; crypto::XY_LEN] {
        match tpm2_wire::srk_point(self.srk_public()) {
            Some((x, y)) => crypto::xy(x, y),
            None => [0; crypto::XY_LEN],
        }
    }

    /// The sealed object's TPMT_PUBLIC.
    pub fn object_public(&self) -> &'a [u8] {
        self.at(OBJECT_PUBLIC_AT, SEALED_PUBLIC_LEN)
    }

    /// The sealed object's Name, computed from this envelope (S17).
    pub fn object_name(&self) -> [u8; NAME_LEN] {
        crypto::name(self.object_public())
    }

    /// The policy the TPM enforces: the object public's authPolicy.
    pub fn object_policy(&self) -> &'a [u8; DIGEST_LEN] {
        tpm2_wire::sealed_policy(self.object_public()).unwrap_or(&[0; DIGEST_LEN])
    }

    pub fn duplicate(&self) -> &'a [u8] {
        self.at(DUPLICATE_AT, DUPLICATE_LEN)
    }

    pub fn in_sym_seed(&self) -> &'a [u8] {
        self.at(SEED_AT, POINT_LEN)
    }

    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// The ciphertext, tag included.
    pub fn ciphertext(&self) -> &'a [u8] {
        let end = HEADER_LEN.saturating_add(self.payload_len).saturating_add(TAG_LEN);
        self.bytes.get(HEADER_LEN..end).unwrap_or(&[])
    }

    /// Decrypts the blob into `out` (the region's size): the plaintext,
    /// then zeros. On any failure `out` is all zero (I11.1).
    pub(crate) fn open(&self, kek: &Key32, out: &mut [u8]) -> Result<(), EnvError> {
        out.fill(0);
        if out.len() != self.bytes.len() {
            return Err(EnvError::Size);
        }
        let aad = self.bytes.get(..HEADER_LEN).ok_or(EnvError::Size)?;
        match aead_open(kek, 0, self.ciphertext(), aad, out) {
            Ok(n) if n == self.payload_len => Ok(()),
            Ok(_) => {
                out.fill(0);
                Err(EnvError::BadLength)
            }
            Err(_) => {
                out.fill(0);
                Err(EnvError::Auth)
            }
        }
    }
}

/// Bytes of stack [`open_sealed`] zeroes after the open: libcrux's
/// ChaCha20 state, which holds the KEK, stays in the dead frames of the
/// AEAD otherwise. The open's peak on this build is far below this (the C9
/// residue harness requires the scrub to cover it: no KEK window survives).
pub const OPEN_SCRUB_DEPTH: usize = 8 * 1024;

/// The envelope-open closure (I10.3): the unsealed KEK becomes the AEAD
/// key and is wiped, the envelope is opened into `out` (zero on failure),
/// and the stack the AEAD used is scrubbed. The PDs ship this function and
/// the C9 residue harness runs the same compiled closure (C10 identity), so
/// it is never inlined.
#[inline(never)]
pub fn open_sealed(envelope: &Envelope<'_>, kek: &mut Secret<32>, out: &mut [u8]) -> Result<(), EnvError> {
    let r = open_core(envelope, kek, out);
    scrub_stack();
    r
}

#[inline(never)]
fn open_core(envelope: &Envelope<'_>, kek: &mut Secret<32>, out: &mut [u8]) -> Result<(), EnvError> {
    let key = Key32::copy_from(kek.as_bytes());
    kek.wipe();
    envelope.open(&key, out)
}

/// Zeroes, with volatile writes, `OPEN_SCRUB_DEPTH` bytes of stack below
/// the caller's frame: where `open_core` and the AEAD just ran.
#[inline(never)]
fn scrub_stack() {
    let mut area = [0u64; OPEN_SCRUB_DEPTH / 8];
    zeroize::Zeroize::zeroize(&mut area);
}

/// Seal entropy: KEK ‖ obfuscation seed ‖ ephemeral ECDH scalar.
pub const SEAL_ENTROPY_LEN: usize = 3 * 32;

/// Seals `region` (a plaintext blob of `kind`'s region size) into `out`
/// (the same size) for the TPM whose SRK public is `srk_public`
/// (TPMT_PUBLIC) and the PCR 8 value `pcr8`.
pub fn seal(
    out: &mut [u8],
    kind: Kind,
    region: &[u8],
    srk_public: &[u8],
    pcr8: &[u8; DIGEST_LEN],
    entropy: &Secret<SEAL_ENTROPY_LEN>,
) -> Result<(), EnvError> {
    seal_with_policy(out, kind, region, srk_public, &crypto::policy_digest(pcr8), entropy)
}

/// `seal` under any authPolicy. Only `seal`'s policy is one `key` and
/// `pqkey` can satisfy; the host relay tests use another to show what
/// PolicyAuthValue is for.
pub fn seal_with_policy(
    out: &mut [u8],
    kind: Kind,
    region: &[u8],
    srk_public: &[u8],
    auth_policy: &[u8; DIGEST_LEN],
    entropy: &Secret<SEAL_ENTROPY_LEN>,
) -> Result<(), EnvError> {
    out.fill(0);
    if out.len() != kind.region_size() || region.len() != kind.region_size() {
        return Err(EnvError::Seal);
    }
    let payload_len = region.iter().rposition(|b| *b != 0).map_or(0, |i| i.saturating_add(1));
    if payload_len > kind.capacity() {
        return Err(EnvError::Seal);
    }
    let (x, y) = tpm2_wire::srk_point(srk_public).ok_or(EnvError::SrkPublic)?;
    let srk_xy = crypto::xy(x, y);
    let (kek, rest) = entropy.as_bytes().split_at(32);
    let (obfuscation, ephemeral) = rest.split_at(32);

    // The sealed object: public area, Name, and TPM2B_SENSITIVE.
    let unique = crypto::sha256(&[obfuscation, kek]);
    let mut public = [0u8; SEALED_PUBLIC_LEN];
    tpm2_wire::sealed_public(&mut public, auth_policy, &unique).ok_or(EnvError::Seal)?;
    let name = crypto::name(&public);
    let mut sensitive = Secret::<{ 2 + SENSITIVE_LEN }>::zero();
    {
        let mut w = Writer::new(sensitive.as_mut_bytes());
        let ok = (|| {
            w.u16(u16::try_from(SENSITIVE_LEN).ok()?)?;
            w.u16(tpm2_wire::ALG_KEYEDHASH)?;
            w.tpm2b(&[])?;
            w.tpm2b(obfuscation)?;
            w.tpm2b(kek)
        })();
        ok.ok_or(EnvError::Seal)?;
    }

    // Outer wrapper: seed by ECDH to the SRK, symKey and HMAC key by KDFa.
    let mut scalar = Secret::<COORD_LEN>::zero();
    scalar.as_mut_bytes().copy_from_slice(ephemeral);
    let ephemeral_xy = crypto::public_point(&scalar).ok_or(EnvError::Seal)?;
    let mut z = Secret::<COORD_LEN>::zero();
    crypto::ecdh(&mut z, &scalar, &srk_xy).ok_or(EnvError::Seal)?;
    scalar.wipe();
    let mut seed = Secret::<DIGEST_LEN>::zero();
    crypto::kdfe(&mut seed, z.as_bytes(), b"DUPLICATE", ephemeral_xy.get(..COORD_LEN).ok_or(EnvError::Seal)?, x);
    z.wipe();
    let mut sym_key = Secret::<AES_KEY_LEN>::zero();
    crypto::kdfa(seed.as_bytes(), b"STORAGE", &name, &[], sym_key.as_mut_bytes()).ok_or(EnvError::Seal)?;
    let mut hmac_key = Secret::<DIGEST_LEN>::zero();
    crypto::kdfa(seed.as_bytes(), b"INTEGRITY", &[], &[], hmac_key.as_mut_bytes()).ok_or(EnvError::Seal)?;
    seed.wipe();
    crypto::cfb(sym_key.as_bytes(), &[0; 16], sensitive.as_mut_bytes(), false);
    sym_key.wipe();
    let mut outer_hmac = [0u8; DIGEST_LEN];
    crypto::hmac(&mut outer_hmac, hmac_key.as_bytes(), &[sensitive.as_bytes(), &name]).ok_or(EnvError::Seal)?;
    hmac_key.wipe();

    let srk_name = crypto::name(srk_public);
    let written = (|| {
        let mut w = Writer::new(&mut *out);
        w.bytes(&MAGIC)?;
        w.bytes(&VERSION.to_le_bytes())?;
        w.bytes(&kind.code().to_le_bytes())?;
        w.bytes(&u32::try_from(payload_len).ok()?.to_le_bytes())?;
        w.bytes(&srk_name)?;
        w.tpm2b(srk_public)?;
        w.bytes(&PCR_SELECTION)?;
        w.bytes(auth_policy)?;
        w.tpm2b(&public)?;
        w.u16(u16::try_from(DUPLICATE_LEN).ok()?)?;
        w.tpm2b(&outer_hmac)?;
        w.bytes(sensitive.as_bytes())?;
        w.u16(u16::try_from(POINT_LEN).ok()?)?;
        w.bytes(&crypto::ecc_point(&ephemeral_xy))?;
        (w.len() == HEADER_LEN).then_some(())
    })();
    if written.is_none() {
        out.fill(0);
        return Err(EnvError::Seal);
    }
    let key = Key32::copy_from(kek.try_into().map_err(|_| EnvError::Seal)?);
    let (aad, body) = out.split_at_mut(HEADER_LEN);
    let sealed = region.get(..payload_len).and_then(|p| aead_seal(&key, 0, p, aad, body).ok());
    if sealed.is_none() {
        out.fill(0);
        return Err(EnvError::Seal);
    }
    Ok(())
}
