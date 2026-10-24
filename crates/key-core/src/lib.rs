//! `key` oracle logic (plan C10, law L2): the only code that touches the
//! gateway's static WireGuard private key and, since M6, the HTTPS
//! server's P-256 signing key. The PD maps the secrets region read-only; it
//! holds the blob sealed (M5 plan C11), which the PD unseals through `tpm`
//! into its own memory at boot (`tpm2::boot`). The plaintext is validated
//! against the compiled configuration once; then the PD answers fixed-size
//! PPC requests:
//!
//! | label        | request (words)          | reply (words)          |
//! |--------------|--------------------------|------------------------|
//! | `STATIC_DH`  | peer point (4)           | DH(S_priv, point) (4)  |
//! | `BOOT_SEED`  | — (0)                    | per-caller seed (4)    |
//! | `TLS_SIGN`   | transcript hash (4)      | r ‖ s, big-endian (8)  |
//!
//! Each caller may use only the labels in its row of a closed caller →
//! label table (M3 plan C2, M6 plan C5): `Hs → {STATIC_DH, BOOT_SEED}`,
//! `Tls → {TLS_SIGN, BOOT_SEED}`. An unknown caller, a label outside the
//! caller's row, a wrong size, an all-zero DH or an exhausted caller budget
//! gets an error label and no data; the first three before any budget is
//! spent. Each caller has its own budget and its own boot seed. Words are
//! little-endian `u64`s, as in seL4 message registers. WireGuard PSKs come
//! only from Rosenpass (L8); `key` holds none.
//!
//! `TLS_SIGN` signs nothing but a TLS 1.3 server CertificateVerify (RFC 8446
//! §4.4.3): `key` builds the content around the caller's transcript hash,
//! so the key cannot sign any other message. Its nonce is RFC 6979's with
//! 32 bytes of RNDR as the §3.6 additional input (M6 plan C5).
//!
//! A boot that fails (`BootError`) leaves the PD up but Unavailable (M5 plan
//! C6): it holds no secret and answers every call from a known caller with
//! `unavailable_label(code)` and no data, so `hs` can report the failure
//! (`key` has no audit ring and no console, L1). A TLS scalar that is
//! invalid or does not match the compiled certificate (`TlsKeyError`) fails
//! only `TLS_SIGN`, answered `unavailable_label(code)`, while `hs`'s labels
//! keep working (M6 plan D5).

#![no_std]
#![cfg_attr(test, feature(variant_count))]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use secret_blob::{Blob, BlobError};
use tpm2::Secret;
use tpm2::boot::UnsealError;
use wg_core::crypto::{self, Key32};

pub const LABEL_STATIC_DH: u64 = 1;
pub const LABEL_BOOT_SEED: u64 = 3;
pub const LABEL_TLS_SIGN: u64 = 4;

/// Reply labels.
pub const OK: u64 = 0;
pub const ERR_BAD_REQUEST: u64 = 1;
pub const ERR_ZERO_DH: u64 = 2;
pub const ERR_RATE_LIMITED: u64 = 4;
pub const ERR_CRYPTO: u64 = 5;
/// `ERR_UNAVAILABLE | code`: the boot failed with `BootError::code` `code`,
/// or (`TLS_SIGN` only) the TLS key with `TlsKeyError::code` `code`.
pub const ERR_UNAVAILABLE: u64 = 0x100;

pub const STATIC_DH_REQ_WORDS: usize = 4;
pub const BOOT_SEED_REQ_WORDS: usize = 0;
pub const TLS_SIGN_REQ_WORDS: usize = 4;
pub const STATIC_DH_REPLY_WORDS: usize = 4;
pub const BOOT_SEED_REPLY_WORDS: usize = 4;
pub const TLS_SIGN_REPLY_WORDS: usize = 8;
/// Largest request or reply.
pub const MAX_WORDS: usize = TLS_SIGN_REPLY_WORDS;

/// The PDs allowed to call `key`. The PD maps its channel to a caller;
/// a channel with no caller is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Hs,
    Tls,
}

impl Caller {
    /// The closed caller → label table (M3 plan C2, M6 plan C5, law L2).
    pub const fn allows(self, label: u64) -> bool {
        match self {
            Caller::Hs => matches!(label, LABEL_STATIC_DH | LABEL_BOOT_SEED),
            Caller::Tls => matches!(label, LABEL_TLS_SIGN | LABEL_BOOT_SEED),
        }
    }

    /// Mixed into the caller's boot seed, so no caller learns another's.
    const fn tag(self) -> &'static [u8] {
        match self {
            Caller::Hs => b"hs",
            Caller::Tls => b"tls",
        }
    }
}

/// `hs`'s call budget: `KEY_BURST` calls, refilled at one per
/// `KEY_INTERVAL_NS` (2 000/s). Far beyond what `hs`'s CPU budget can drive,
/// while still bounding a runaway caller. The initiations `ingress` can
/// forward must never exhaust it (M2.5 plan C5).
pub const KEY_BURST: u64 = 256;
pub const KEY_INTERVAL_NS: u64 = 1_000_000_000 / 2_000;
/// Calls `hs` makes outside handshakes: the `BOOT_SEED` request at init
/// (crates/pds/hs/src/main.rs).
pub const KEY_BOOT_CALLS: u64 = 1;

/// `tls`'s call budget (M6 plan C5): one `TLS_SIGN` per handshake, so it is
/// sized at the handshakes `ingress` can forward (its global SYN bucket,
/// the abuse bound): the burst covers the SYN burst plus the boot calls,
/// and the refill is at least the SYN refill (both asserted in `hs-core`,
/// which sees `ingress-core`). What a sign costs `hs` is bounded per call
/// by the wait invariant there, not by this budget.
pub const TLS_SIGN_BURST: u64 = 32;
pub const TLS_SIGN_INTERVAL_NS: u64 = 1_000_000_000 / 20;
/// Calls `tls` makes outside handshakes: its `BOOT_SEED` request at init
/// (the hedged RNG's seed, M6 plan C7).
pub const TLS_BOOT_CALLS: u64 = 1;

/// The longest one `TLS_SIGN` runs, in ns of CPU time on `tls`'s scheduling
/// context, for the wait invariant in `hs-core`. PROVISIONAL (M6 slice 2):
/// a conservative estimate (HACL*'s P-256 signs in about 0.1–0.3 ms natively;
/// this allows a 60–200× QEMU TCG slowdown) until slice 3 measures the
/// maximum of 20 runs under TCG and records twice that here. It is bound to the
/// libcrux-p256 it was taken for: check-pins P17 fails when Cargo.lock's
/// entry differs from `SIGN_COST_LIBCRUX_P256` (the re-measure trigger).
pub const SIGN_COST_NS: u64 = 20_000_000;
/// Cargo.lock's libcrux-p256 entry `SIGN_COST_NS` belongs to: "version
/// checksum" (check-pins P17).
pub const SIGN_COST_LIBCRUX_P256: &str = "0.0.9 7489aa205be22524e2f6ddbe006c0c4ff5f1dfc7c17b783e3d02f1cb2a01c605";

/// Every caller's bucket, each refilled on its own (M6 plan C5): a caller
/// can exhaust only its own.
#[derive(Debug, Clone, Copy)]
pub struct Buckets {
    hs: Bucket,
    tls: Bucket,
}

impl Buckets {
    pub const fn new() -> Self {
        Self::with(Bucket::new(KEY_BURST, KEY_INTERVAL_NS), Bucket::new(TLS_SIGN_BURST, TLS_SIGN_INTERVAL_NS))
    }

    /// Buckets of other sizes (tests).
    pub const fn with(hs: Bucket, tls: Bucket) -> Self {
        Self { hs, tls }
    }

    fn of(&mut self, caller: Caller) -> &mut Bucket {
        match caller {
            Caller::Hs => &mut self.hs,
            Caller::Tls => &mut self.tls,
        }
    }
}

impl Default for Buckets {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    Blob(BlobError),
    GatewayKeyMismatch,
    PeerMismatch,
    /// RNDR failed while drawing the boot seed's samples.
    RndrUnavailable,
    /// Hashing the boot seed failed.
    SeedDerivation,
    /// The secrets region is not a sealed envelope of `key`'s kind (M5
    /// plan C11: a plaintext blob is refused here).
    EnvelopeInvalid,
    /// `tpm` refused, failed or stayed busy (M5 plan C9).
    TpmUnavailable,
    /// The TPM's SRK is not the envelope's pinned one: another TPM (I10.2).
    SrkMismatch,
    /// The TPM refused the Unseal: PCR 8 is not the value sealed to.
    UnsealRefused,
    /// A TPM response failed the client's checks (A7).
    TpmResponseInvalid,
    /// The unsealed KEK did not open the envelope.
    EnvelopeOpen,
}

impl From<UnsealError> for BootError {
    fn from(e: UnsealError) -> Self {
        match e {
            UnsealError::Rndr => BootError::RndrUnavailable,
            UnsealError::EnvelopeInvalid => BootError::EnvelopeInvalid,
            UnsealError::TpmUnavailable => BootError::TpmUnavailable,
            UnsealError::SrkMismatch => BootError::SrkMismatch,
            UnsealError::UnsealRefused => BootError::UnsealRefused,
            UnsealError::ResponseInvalid => BootError::TpmResponseInvalid,
            UnsealError::EnvelopeOpen => BootError::EnvelopeOpen,
        }
    }
}

impl BootError {
    /// Stable text, one per failure (plan C10).
    pub const fn message(self) -> &'static str {
        match self {
            BootError::Blob(e) => e.message(),
            BootError::GatewayKeyMismatch => "secrets: gateway key does not match the configuration",
            BootError::PeerMismatch => "secrets: peer keys do not match the configuration",
            BootError::RndrUnavailable => "RNDR unavailable",
            BootError::SeedDerivation => "boot seed derivation failed",
            BootError::EnvelopeInvalid => "secrets: not a sealed envelope for key",
            BootError::TpmUnavailable => "secrets: tpm unavailable",
            BootError::SrkMismatch => "secrets: sealed to another TPM",
            BootError::UnsealRefused => "secrets: the TPM refused to unseal (PCR 8)",
            BootError::TpmResponseInvalid => "secrets: a TPM response failed its checks",
            BootError::EnvelopeOpen => "secrets: the unsealed KEK does not open the envelope",
        }
    }

    /// Stable code, one per failure, carried by the Unavailable reply label
    /// and by `hs`'s `KeyUnavailable` audit record (M5 plan C6). Never 0.
    pub const fn code(self) -> u32 {
        match self {
            BootError::Blob(BlobError::BadMagic) => 1,
            BootError::Blob(BlobError::BadVersion) => 2,
            BootError::Blob(BlobError::BadPeerCount) => 3,
            BootError::Blob(BlobError::BadChecksum) => 4,
            BootError::Blob(BlobError::NonZeroPadding) => 5,
            BootError::Blob(BlobError::TooSmall) => 6,
            BootError::GatewayKeyMismatch => 7,
            BootError::PeerMismatch => 8,
            BootError::RndrUnavailable => 9,
            BootError::SeedDerivation => 10,
            BootError::EnvelopeInvalid => 11,
            BootError::TpmUnavailable => 12,
            BootError::SrkMismatch => 13,
            BootError::UnsealRefused => 14,
            BootError::TpmResponseInvalid => 15,
            BootError::EnvelopeOpen => 16,
        }
    }
}

/// Why the TLS scalar is unusable (M6 plan D5). Never a boot failure: `key`
/// stays Ready for `hs`, and only `TLS_SIGN` answers
/// `unavailable_label(code)`. The codes share `BootError`'s space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKeyError {
    /// Zero or not below the group order.
    Invalid,
    /// Its public point is not `config::TLS_PUBLIC`, the certificate's.
    Mismatch,
}

impl TlsKeyError {
    pub const fn message(self) -> &'static str {
        match self {
            TlsKeyError::Invalid => "secrets: TLS key is not a valid P-256 scalar",
            TlsKeyError::Mismatch => "secrets: TLS key does not match the certificate",
        }
    }

    /// Stable code, after `BootError`'s, carried by `TLS_SIGN`'s Unavailable
    /// reply label and by `tls`'s `KeyUnavailable` audit record.
    pub const fn code(self) -> u32 {
        match self {
            TlsKeyError::Invalid => 17,
            TlsKeyError::Mismatch => 18,
        }
    }
}

/// An uncompressed P-256 point: 0x04 ‖ x ‖ y.
pub const TLS_PUBLIC_LEN: usize = 65;

/// Whether `private` is a valid P-256 scalar whose public point is
/// `public`. The scalar's copy is wiped; libcrux's stack is the PD's to
/// scrub (M6 plan C5).
pub fn check_tls_key(private: &[u8; 32], public: &[u8; TLS_PUBLIC_LEN]) -> Result<(), TlsKeyError> {
    let mut scalar = Secret::<32>::zero();
    scalar.as_mut_bytes().copy_from_slice(private);
    let xy = tpm2::crypto::public_point(&scalar).ok_or(TlsKeyError::Invalid)?;
    let (prefix, point) = public.split_at(1);
    if prefix != [0x04] || !crypto::ct_eq(point, &xy) {
        return Err(TlsKeyError::Mismatch);
    }
    Ok(())
}

/// The reply label of an Unavailable `key` whose boot failed with `code`.
pub const fn unavailable_label(code: u32) -> u64 {
    ERR_UNAVAILABLE | (code as u64 & 0xff)
}

/// The boot error code an Unavailable reply label carries, if it is one.
pub const fn unavailable_code(label: u64) -> Option<u32> {
    if label & !0xff == ERR_UNAVAILABLE { Some((label & 0xff) as u32) } else { None }
}

/// The answer of an Unavailable `key` (no oracle, no secret): every call from
/// a known caller gets `unavailable_label(code)`, an unknown caller
/// `ERR_BAD_REQUEST`; never any data, and `reply` is zeroed.
pub fn unavailable(caller: Option<Caller>, code: u32, reply: &mut [u64]) -> (u64, usize) {
    reply.fill(0);
    match caller {
        Some(_) => (unavailable_label(code), 0),
        None => (ERR_BAD_REQUEST, 0),
    }
}

/// A validated region, and the TLS key's own verdict (M6 plan D5).
pub struct Validated<'a> {
    pub blob: Blob<'a>,
    pub tls: Result<(), TlsKeyError>,
}

/// Checks the region against the compiled configuration: format, the TLS
/// scalar against `tls_public` (a refused scalar is wiped from the region,
/// M6 plan C5), the public key derived from the private key, and each
/// peer's key hash in configuration order. Only the TLS check runs on the
/// mutable region, before the returned borrow; its failure is not a
/// `BootError`.
pub fn validate<'a, 'p>(
    region: &'a mut [u8],
    gateway_public: &[u8; 32],
    tls_public: &[u8; TLS_PUBLIC_LEN],
    peers: impl ExactSizeIterator<Item = &'p [u8; 32]>,
) -> Result<Validated<'a>, BootError> {
    let mut tls = Ok(());
    let (blob, _) = Blob::parse_checking_tls(region, peers.len(), |k| {
        tls = check_tls_key(k, tls_public);
        tls.is_ok()
    })
    .map_err(BootError::Blob)?;
    let private = Key32::copy_from(blob.gateway_private());
    if !crypto::ct_eq(&crypto::public_key(&private), gateway_public) {
        return Err(BootError::GatewayKeyMismatch);
    }
    for (i, public) in peers.enumerate() {
        let hash = blob.peer(i).ok_or(BootError::PeerMismatch)?;
        if !crypto::ct_eq(hash, &secret_blob::blake2s(&[public])) {
            return Err(BootError::PeerMismatch);
        }
    }
    Ok(Validated { blob, tls })
}

/// Per-caller CNTPCT token bucket: `burst` calls, refilled at one call per
/// `interval_ns`. Sized by the PD at or above what `hs`'s CPU budget can
/// drive, so it bounds a misbehaving caller without throttling real load.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    capacity_ns: u64,
    interval_ns: u64,
    budget_ns: u64,
    last_ns: u64,
}

impl Bucket {
    pub const fn new(burst: u64, interval_ns: u64) -> Self {
        let capacity_ns = burst.saturating_mul(interval_ns);
        Self { capacity_ns, interval_ns, budget_ns: capacity_ns, last_ns: 0 }
    }

    pub fn take(&mut self, now_ns: u64) -> bool {
        let elapsed = now_ns.saturating_sub(self.last_ns);
        self.budget_ns = self.budget_ns.saturating_add(elapsed).min(self.capacity_ns);
        self.last_ns = self.last_ns.max(now_ns);
        if self.budget_ns < self.interval_ns {
            return false;
        }
        self.budget_ns = self.budget_ns.saturating_sub(self.interval_ns);
        true
    }
}

/// RNDR samples mixed into the boot seed.
pub const SEED_SAMPLES: usize = 4;

/// The hardware entropy `key` uses: the boot seed's inputs and each
/// signature's RFC 6979 additional input. The PD implements it over `cpu`.
pub trait Entropy {
    /// Fills `out` from RNDR; false if the hardware failed.
    fn fill_random(&mut self, out: &mut [u8]) -> bool;
    fn cntpct(&mut self) -> u64;
}

pub struct Oracle<'a> {
    blob: Blob<'a>,
    tls: Result<(), TlsKeyError>,
    boot_seed: Key32,
}

/// P-256's group order n, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa,
    0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// RFC 6979 §2.3.4 bits2octets for qlen = hlen = 256: `h` mod n. One
/// conditional subtraction suffices (h < 2^256 < 2n); branch-free.
fn bits2octets(h: &[u8; 32]) -> [u8; 32] {
    let mut diff = [0u8; 32];
    let mut borrow = 0u16;
    for ((d, a), b) in diff.iter_mut().zip(h).zip(&P256_N).rev() {
        let t = u16::from(*a).wrapping_sub(u16::from(*b)).wrapping_sub(borrow);
        *d = t.to_le_bytes()[0];
        borrow = (t >> 8) & 1;
    }
    // borrow == 0: h ≥ n, take h − n.
    let take_diff = 0u8.wrapping_sub(u8::from(borrow == 0));
    let mut out = [0u8; 32];
    for ((o, d), a) in out.iter_mut().zip(&diff).zip(h) {
        *o = (d & take_diff) | (a & !take_diff);
    }
    out
}

/// RFC 6979 §3.2's HMAC-DRBG (HMAC-SHA256 through libcrux-hmac) with the
/// §3.6 additional input. K and V wipe themselves (`Secret`).
struct Drbg {
    k: Secret<32>,
    v: Secret<32>,
}

impl Drbg {
    /// Steps b–g: `x` the private key, `h1` = bits2octets(H(m)), `extra` k'.
    fn new(x: &[u8; 32], h1: &[u8; 32], extra: &[u8]) -> Option<Self> {
        let mut d = Self { k: Secret::zero(), v: Secret::zero() };
        d.v.as_mut_bytes().fill(0x01);
        d.update(&[&[0x00], x, h1, extra])?;
        d.update(&[&[0x01], x, h1, extra])?;
        Some(d)
    }

    /// K = HMAC_K(V ‖ `parts`), then V = HMAC_K(V).
    fn update(&mut self, parts: &[&[u8]]) -> Option<()> {
        let mut next = Secret::<32>::zero();
        let mut input: [&[u8]; 5] = [&[]; 5];
        let (first, rest) = input.split_first_mut()?;
        *first = self.v.as_bytes();
        for (slot, p) in rest.iter_mut().zip(parts) {
            *slot = p;
        }
        tpm2::crypto::hmac(next.as_mut_bytes(), self.k.as_bytes(), &input)?;
        self.k.as_mut_bytes().copy_from_slice(next.as_bytes());
        self.next_v()
    }

    fn next_v(&mut self) -> Option<()> {
        let mut next = Secret::<32>::zero();
        tpm2::crypto::hmac(next.as_mut_bytes(), self.k.as_bytes(), &[self.v.as_bytes()])?;
        self.v.as_mut_bytes().copy_from_slice(next.as_bytes());
        Some(())
    }

    /// Step h.1–h.2: one candidate (qlen = hlen, so one V; bits2int is the
    /// identity).
    fn candidate(&mut self, k: &mut Secret<32>) -> Option<()> {
        self.next_v()?;
        k.as_mut_bytes().copy_from_slice(self.v.as_bytes());
        Some(())
    }

    /// Step h.3, after a candidate the sign function refused.
    fn reject(&mut self) -> Option<()> {
        self.update(&[&[0x00]])
    }
}

/// Candidates tried before `TLS_SIGN` gives up with `ERR_CRYPTO`. A
/// candidate outside [1, n−1], or one giving r = 0 or s = 0, has
/// probability about 2^-128, so a second is already never expected.
pub const MAX_NONCE_CANDIDATES: usize = 8;

/// The ECDSA P-256/SHA-256 sign function: (signature r ‖ s, message,
/// private key, nonce) → false if the key or nonce is not in [1, n−1] or r
/// or s came out zero. A seam for the candidate tests.
pub type SignFn = fn(&mut [u8; 64], &[u8], &[u8; 32], &[u8; 32]) -> bool;

/// libcrux's sign (HACL*); it hashes `msg` with SHA-256 itself.
pub fn libcrux_sign(sig: &mut [u8; 64], msg: &[u8], private: &[u8; 32], nonce: &[u8; 32]) -> bool {
    let Ok(len) = u32::try_from(msg.len()) else { return false };
    libcrux_p256::ecdsa_sign_p256_sha2(sig, len, msg, private, nonce)
}

/// Signs `msg` with the RFC 6979 nonce for (`private`, SHA-256(`msg`)) and
/// the additional input `extra`, trying at most `MAX_NONCE_CANDIDATES`.
/// False (and `sig` zeroed) when every candidate was refused.
pub fn sign_rfc6979(sign: SignFn, sig: &mut Secret<64>, msg: &[u8], private: &[u8; 32], extra: &[u8]) -> bool {
    let h1 = bits2octets(&tpm2::crypto::sha256(&[msg]));
    let Some(mut drbg) = Drbg::new(private, &h1, extra) else { return false };
    let mut k = Secret::<32>::zero();
    for _ in 0..MAX_NONCE_CANDIDATES {
        if drbg.candidate(&mut k).is_none() {
            break;
        }
        if sign(sig.as_mut_bytes(), msg, private, k.as_bytes()) {
            return true;
        }
        if drbg.reject().is_none() {
            break;
        }
    }
    sig.wipe();
    false
}

/// RFC 8446 §4.4.3: 64 spaces, the server context string, a zero byte.
const CV_PREFIX_LEN: usize = 64 + CV_CONTEXT.len() + 1;
const CV_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
/// The content a server CertificateVerify signs over a SHA-256 transcript.
pub const CV_CONTENT_LEN: usize = CV_PREFIX_LEN + 32;

/// The server CertificateVerify content for `transcript_hash`.
pub fn certificate_verify_content(out: &mut Secret<CV_CONTENT_LEN>, transcript_hash: &[u8; 32]) {
    let (spaces, rest) = out.as_mut_bytes().split_at_mut(64);
    spaces.fill(0x20);
    let (context, rest) = rest.split_at_mut(CV_CONTEXT.len());
    context.copy_from_slice(CV_CONTEXT);
    let (zero, hash) = rest.split_at_mut(1);
    zero.fill(0);
    hash.copy_from_slice(transcript_hash);
}

/// How deep `key`'s PD scrubs its stack after the boot-time TLS check and
/// after each `TLS_SIGN` (M6 plan C5): libcrux's P-256, SHA-256 and HMAC
/// state (the scalar, nonce candidates, K and V) stays in their dead frames
/// otherwise. Not measured: chosen far above those frames' size and well
/// inside `key`'s 128 KiB stack; the scalar residue case (plan T8)
/// adjudicates it.
pub const SCRUB_DEPTH: usize = 32 * 1024;

fn words_to_bytes<const N: usize>(words: &[u64]) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let (chunks, rest) = out.as_chunks_mut::<8>();
    if !rest.is_empty() || chunks.len() != words.len() {
        return None;
    }
    for (c, w) in chunks.iter_mut().zip(words) {
        *c = w.to_le_bytes();
    }
    Some(out)
}

fn put_bytes(words: &mut [u64], bytes: &[u8]) -> Option<usize> {
    let (chunks, rest) = bytes.as_chunks::<8>();
    if !rest.is_empty() {
        return None;
    }
    let dst = words.get_mut(..chunks.len())?;
    for (w, c) in dst.iter_mut().zip(chunks) {
        *w = u64::from_le_bytes(*c);
    }
    Some(chunks.len())
}

impl<'a> Oracle<'a> {
    /// `boot_seed` is the per-boot value derived by the PD
    /// (BLAKE2s(blob seed ‖ RNDR ‖ CNTPCT)); the blob seed never leaves `key`.
    pub fn new(validated: Validated<'a>, boot_seed: Key32) -> Self {
        Self { blob: validated.blob, tls: validated.tls, boot_seed }
    }

    /// The TLS key's verdict from validation (M6 plan D5).
    pub fn tls_key(&self) -> Result<(), TlsKeyError> {
        self.tls
    }

    /// Everything `key` does with the unsealed region before it can answer:
    /// validation, then the per-boot seed (blob seed ‖ RNDR ‖ CNTPCT). One
    /// fallible call, so the PD wipes the region on any of its failures
    /// with a single guard, as `pqkey` does (M5 plan C6: an Unavailable
    /// `key` holds no secret).
    /// The TLS scalar's verdict never fails it (M6 plan D5).
    pub fn boot<'p>(
        region: &'a mut [u8],
        gateway_public: &[u8; 32],
        tls_public: &[u8; TLS_PUBLIC_LEN],
        peers: impl ExactSizeIterator<Item = &'p [u8; 32]>,
        entropy: &mut impl Entropy,
    ) -> Result<Self, BootError> {
        let validated = validate(region, gateway_public, tls_public, peers)?;
        // Both wipe themselves on drop (tpm2::Secret), on every return.
        let mut samples = tpm2::Secret::<{ SEED_SAMPLES * 8 }>::zero();
        if !entropy.fill_random(samples.as_mut_bytes()) {
            return Err(BootError::RndrUnavailable);
        }
        let mut seed = tpm2::Secret::<32>::zero();
        *seed.as_mut_bytes() =
            crypto::hash(&[validated.blob.boot_seed(), samples.as_bytes(), &entropy.cntpct().to_le_bytes()])
                .map_err(|_| BootError::SeedDerivation)?;
        Ok(Self::new(validated, Key32::copy_from(seed.as_bytes())))
    }

    /// Answers one request from `caller` (None: a channel with no caller),
    /// charged to that caller's bucket. Returns (reply label, reply word
    /// count); on any error the count is 0 and `reply` is zeroed, so no
    /// partial result leaks through a reused message register.
    #[allow(clippy::too_many_arguments)] // intentional: one PPC's whole context, as the PD holds it
    pub fn handle(
        &self,
        caller: Option<Caller>,
        buckets: &mut Buckets,
        now_ns: u64,
        entropy: &mut impl Entropy,
        label: u64,
        req: &[u64],
        reply: &mut [u64],
    ) -> (u64, usize) {
        let r = match caller {
            Some(c) if c.allows(label) => self.dispatch(c, buckets.of(c), now_ns, entropy, label, req, reply),
            _ => (ERR_BAD_REQUEST, 0),
        };
        if r.0 != OK {
            reply.fill(0);
            return (r.0, 0);
        }
        r
    }

    #[allow(clippy::too_many_arguments)] // intentional: `handle`'s context, its caller resolved
    fn dispatch(
        &self,
        caller: Caller,
        bucket: &mut Bucket,
        now_ns: u64,
        entropy: &mut impl Entropy,
        label: u64,
        req: &[u64],
        reply: &mut [u64],
    ) -> (u64, usize) {
        let expected = match label {
            LABEL_STATIC_DH => STATIC_DH_REQ_WORDS,
            LABEL_BOOT_SEED => BOOT_SEED_REQ_WORDS,
            LABEL_TLS_SIGN => TLS_SIGN_REQ_WORDS,
            _ => return (ERR_BAD_REQUEST, 0),
        };
        if req.len() != expected {
            return (ERR_BAD_REQUEST, 0);
        }
        // D5: a refused TLS key costs the caller nothing and does no work.
        if let (LABEL_TLS_SIGN, Err(e)) = (label, self.tls) {
            return (unavailable_label(e.code()), 0);
        }
        if !bucket.take(now_ns) {
            return (ERR_RATE_LIMITED, 0);
        }
        let written = match label {
            LABEL_STATIC_DH => self.static_dh(req, reply),
            LABEL_TLS_SIGN => self.tls_sign(libcrux_sign, entropy, req, reply),
            _ => self.boot_seed(caller, reply),
        };
        match written {
            Ok(n) => (OK, n),
            Err(e) => (e, 0),
        }
    }

    /// BLAKE2s(boot seed ‖ caller tag): the same value on every call, a
    /// different one per caller (M6 plan C5).
    fn boot_seed(&self, caller: Caller, reply: &mut [u64]) -> Result<usize, u64> {
        let mut seed = Secret::<32>::zero();
        *seed.as_mut_bytes() = secret_blob::blake2s(&[self.boot_seed.as_bytes(), caller.tag()]);
        put_bytes(reply, seed.as_bytes()).ok_or(ERR_BAD_REQUEST)
    }

    /// A server CertificateVerify signature over the 32-byte transcript hash
    /// in `req`: r ‖ s, 32 bytes each, big-endian, in 8 words. `sign` is
    /// `libcrux_sign` except in the candidate tests.
    fn tls_sign(&self, sign: SignFn, entropy: &mut impl Entropy, req: &[u64], reply: &mut [u64]) -> Result<usize, u64> {
        let hash: [u8; 32] = words_to_bytes(req).ok_or(ERR_BAD_REQUEST)?;
        let mut content = Secret::<CV_CONTENT_LEN>::zero();
        certificate_verify_content(&mut content, &hash);
        let mut extra = Secret::<32>::zero();
        if !entropy.fill_random(extra.as_mut_bytes()) {
            return Err(ERR_CRYPTO);
        }
        let mut sig = Secret::<64>::zero();
        if !sign_rfc6979(sign, &mut sig, content.as_bytes(), self.blob.tls_private(), extra.as_bytes()) {
            return Err(ERR_CRYPTO);
        }
        put_bytes(reply, sig.as_bytes()).ok_or(ERR_BAD_REQUEST)
    }

    fn static_dh(&self, req: &[u64], reply: &mut [u64]) -> Result<usize, u64> {
        let point: [u8; 32] = words_to_bytes(req).ok_or(ERR_BAD_REQUEST)?;
        let private = Key32::copy_from(self.blob.gateway_private());
        let shared = crypto::dh(&private, &point).map_err(|e| match e {
            crypto::CryptoError::ZeroDh => ERR_ZERO_DH,
            _ => ERR_CRYPTO,
        })?;
        put_bytes(reply, shared.as_bytes()).ok_or(ERR_BAD_REQUEST)
    }
}

/// Packs a 32-byte value into four words (used by callers and tests).
pub fn pack32(bytes: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    let _ = put_bytes(&mut w, bytes);
    w
}

/// Unpacks four words into 32 bytes.
pub fn unpack32(words: &[u64]) -> Option<[u8; 32]> {
    words_to_bytes(words)
}

#[cfg(test)]
mod tests;
