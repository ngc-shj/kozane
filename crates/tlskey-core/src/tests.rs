#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use core::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use secret_blob::tls::{REGION_SIZE, TLS_PRIVATE_AT};

const SEED: [u8; 32] = [0x5e; 32];
/// RFC 6979 A.2.5's P-256 private key, the TLS scalar throughout.
const TLS_PRIVATE: [u8; 32] = hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
/// Another valid scalar, with its own certificate point.
const OTHER_PRIVATE: [u8; 32] = [0x01; 32];

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not hex"),
    }
}

fn xy(private: &[u8; 32]) -> [u8; 64] {
    let mut s = Secret::<32>::zero();
    s.as_mut_bytes().copy_from_slice(private);
    tpm2::crypto::public_point(&s).unwrap()
}

fn public_of(private: &[u8; 32]) -> [u8; TLS_PUBLIC_LEN] {
    let mut p = [0x04; TLS_PUBLIC_LEN];
    p[1..].copy_from_slice(&xy(private));
    p
}

fn tls_public() -> [u8; TLS_PUBLIC_LEN] {
    public_of(&TLS_PRIVATE)
}

fn region_with(tls_private: &[u8; 32], seed: &[u8; 32]) -> [u8; REGION_SIZE] {
    let mut r = [0u8; REGION_SIZE];
    secret_blob::tls::write(&mut r, tls_private, seed).unwrap();
    r
}

fn region() -> [u8; REGION_SIZE] {
    region_with(&TLS_PRIVATE, &[0x99; 32])
}

/// RNDR (every byte `byte`, or a failure) and CNTPCT (`tick`), both fixed.
struct FakeHw {
    ok: bool,
    byte: u8,
    tick: u64,
}

fn hw() -> FakeHw {
    FakeHw { ok: true, byte: 0x42, tick: 7 }
}

impl Hw for FakeHw {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        out.fill(self.byte);
        self.ok
    }

    fn cntpct(&mut self) -> u64 {
        self.tick
    }
}

fn oracle(r: &mut [u8]) -> Oracle<'_> {
    Oracle::boot(r, &tls_public(), &mut hw()).unwrap()
}

fn bucket() -> Bucket {
    Bucket::new(100, 1)
}

const TLS: Option<Caller> = Some(Caller::Tls);

fn call(o: &Oracle<'_>, caller: Option<Caller>, b: &mut Bucket, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
    o.handle(caller, b, 0, &mut hw(), label, req, reply)
}

// ---------------------------------------------------------------- boot

#[test]
fn a_valid_region_boots_and_answers_both_labels() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut bucket(), LABEL_BOOT_SEED, &[], &mut reply), (OK, BOOT_SEED_REPLY_WORDS));
    assert_eq!(call(&o, TLS, &mut bucket(), LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (OK, TLS_SIGN_REPLY_WORDS));
}

/// A refused boot: its error, and the whole plaintext wiped (M5 plan C6).
fn refused_boot(r: &mut [u8; REGION_SIZE], public: &[u8; TLS_PUBLIC_LEN], hw: &mut FakeHw) -> BootError {
    let e = Oracle::boot(r, public, hw).err().expect("the boot is refused");
    assert!(r.iter().all(|b| *b == 0), "{e:?}: the plaintext is not wiped");
    e
}

#[test]
fn a_bad_blob_is_its_blob_code_and_the_plaintext_is_wiped() {
    let mut r = region();
    r[0] ^= 1;
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::Blob(BlobError::BadMagic));
    let mut r = region();
    r[8] = 2;
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::Blob(BlobError::BadVersion));
    let mut r = region();
    r[TLS_PRIVATE_AT] ^= 1;
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::Blob(BlobError::BadChecksum));
    let mut r = region();
    r[REGION_SIZE - 1] = 1;
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::Blob(BlobError::NonZeroPadding));
}

#[test]
fn a_zero_scalar_is_invalid_and_the_plaintext_is_wiped() {
    let mut r = region_with(&[0; 32], &SEED);
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::ScalarInvalid);
}

#[test]
fn a_scalar_not_below_the_order_is_invalid_and_the_plaintext_is_wiped() {
    for scalar in [P256_N, [0xff; 32]] {
        let mut r = region_with(&scalar, &SEED);
        assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::ScalarInvalid);
    }
}

/// M6 plan D5 as amended by C12: a scalar whose point is not the
/// certificate's fails the whole of `tlskey`.
#[test]
fn a_scalar_of_another_point_is_a_mismatch_and_the_plaintext_is_wiped() {
    let mut r = region_with(&OTHER_PRIVATE, &SEED);
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut hw()), BootError::Mismatch);
    // The certificate's point without the uncompressed prefix is no match.
    let mut p = tls_public();
    p[0] = 0x02;
    let mut r = region();
    assert_eq!(refused_boot(&mut r, &p, &mut hw()), BootError::Mismatch);
}

#[test]
fn rndr_failing_after_the_checks_is_its_own_code_and_the_plaintext_is_wiped() {
    let mut r = region();
    assert_eq!(refused_boot(&mut r, &tls_public(), &mut FakeHw { ok: false, byte: 0, tick: 0 }), BootError::RndrUnavailable);
}

#[test]
fn each_unseal_failure_has_its_own_boot_error() {
    use tpm2::boot::UnsealError;
    let all = [
        UnsealError::Rndr,
        UnsealError::EnvelopeInvalid,
        UnsealError::TpmUnavailable,
        UnsealError::SrkMismatch,
        UnsealError::UnsealRefused,
        UnsealError::ResponseInvalid,
        UnsealError::EnvelopeOpen,
        UnsealError::CapFailed,
    ];
    assert_eq!(all.len(), core::mem::variant_count::<UnsealError>());
    assert_eq!(BootError::from(UnsealError::Rndr), BootError::RndrUnavailable);
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(BootError::from(*a), BootError::from(*b), "{a:?} and {b:?}");
        }
    }
}

/// Every BootError: the ten plain kinds, then each BlobError by an
/// exhaustive successor match (a new variant fails to compile until it is
/// placed in the walk).
fn all_boot_errors() -> std::vec::Vec<BootError> {
    fn next(e: BlobError) -> Option<BlobError> {
        match e {
            BlobError::BadMagic => Some(BlobError::BadVersion),
            BlobError::BadVersion => Some(BlobError::BadPeerCount),
            BlobError::BadPeerCount => Some(BlobError::BadChecksum),
            BlobError::BadChecksum => Some(BlobError::NonZeroPadding),
            BlobError::NonZeroPadding => Some(BlobError::TooSmall),
            BlobError::TooSmall => None,
        }
    }
    let mut all = std::vec![
        BootError::ScalarInvalid,
        BootError::Mismatch,
        BootError::RndrUnavailable,
        BootError::EnvelopeInvalid,
        BootError::TpmUnavailable,
        BootError::SrkMismatch,
        BootError::UnsealRefused,
        BootError::TpmResponseInvalid,
        BootError::EnvelopeOpen,
        BootError::TpmCapFailed,
    ];
    let mut e = Some(BlobError::BadMagic);
    while let Some(v) = e {
        all.push(BootError::Blob(v));
        e = next(v);
    }
    assert_eq!(all.len() - 10, core::mem::variant_count::<BlobError>());
    assert_eq!(core::mem::variant_count::<BootError>(), 11);
    all
}

/// R1-S F6: `tlskey`'s codes are distinct, fit the Unavailable label and
/// lie in their own range above `CODE_BASE` (`key`'s are below it; run.py's
/// code-table mirror checks the two tables against each other).
#[test]
fn boot_error_codes_are_distinct_and_lie_in_tlskeys_own_range() {
    let all = all_boot_errors();
    assert_eq!(CODE_BASE, 0x40);
    for (i, a) in all.iter().enumerate() {
        assert!((CODE_BASE + 1..CODE_BASE + 0x40).contains(&a.code()), "{a:?}: {:#x}", a.code());
        assert_eq!(unavailable_code(unavailable_label(a.code())), Some(a.code()), "{a:?}");
        for b in &all[i + 1..] {
            assert_ne!(a.code(), b.code(), "{a:?} and {b:?}");
            assert_ne!(a.message(), b.message(), "{a:?} and {b:?}");
        }
    }
    assert_eq!((BootError::ScalarInvalid.code(), BootError::Mismatch.code()), (0x47, 0x48));
}

#[test]
fn no_other_reply_label_reads_as_unavailable() {
    for label in [OK, ERR_BAD_REQUEST, ERR_RATE_LIMITED, ERR_CRYPTO, ERR_UNAVAILABLE - 1, ERR_UNAVAILABLE + 0x100] {
        assert_eq!(unavailable_code(label), None, "{label:#x}");
    }
}

#[test]
fn unavailable_answers_every_label_with_the_code_and_no_data() {
    let code = BootError::Mismatch.code();
    for label in [LABEL_BOOT_SEED, LABEL_TLS_SIGN, 0, 1, u64::MAX] {
        let mut reply = [u64::MAX; MAX_WORDS];
        let (got, n) = unavailable(TLS, code, &mut reply);
        assert_eq!((unavailable_code(got), n), (Some(code), 0), "{label}");
        assert_eq!(reply, [0; MAX_WORDS]);
    }
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(unavailable(None, code, &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

// ---------------------------------------------------------------- the seed

fn seed_of(o: &Oracle<'_>) -> [u8; 32] {
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(o, TLS, &mut bucket(), LABEL_BOOT_SEED, &[], &mut reply), (OK, BOOT_SEED_REPLY_WORDS));
    unpack32(&reply[..4]).unwrap()
}

/// The seed a boot of `scalar` and `seed` hands out, RNDR and CNTPCT fixed.
fn booted_seed(scalar: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    let mut r = region_with(scalar, seed);
    let o = Oracle::boot(&mut r, &public_of(scalar), &mut hw()).unwrap();
    seed_of(&o)
}

#[test]
fn the_boot_seed_is_blake2s_of_the_blob_seed_rndr_and_cntpct() {
    let mut want = std::vec::Vec::from(SEED);
    want.extend_from_slice(&[0x42; SEED_SAMPLES * 8]);
    want.extend_from_slice(&7u64.to_le_bytes());
    assert_eq!(booted_seed(&TLS_PRIVATE, &SEED), secret_blob::blake2s(&[&want]));
}

#[test]
fn the_same_blob_seed_gives_the_same_boot_seed_and_another_a_different_one() {
    assert_eq!(booted_seed(&TLS_PRIVATE, &SEED), booted_seed(&TLS_PRIVATE, &SEED));
    assert_ne!(booted_seed(&TLS_PRIVATE, &SEED), booted_seed(&TLS_PRIVATE, &[0x5f; 32]));
}

/// M6 plan C12 (R2-T N2): the scalar is no input of the seed, so another
/// scalar under the same blob seed hands out the same seed.
#[test]
fn another_scalar_with_the_same_blob_seed_gives_the_same_boot_seed() {
    assert_eq!(booted_seed(&TLS_PRIVATE, &SEED), booted_seed(&OTHER_PRIVATE, &SEED));
}

#[test]
fn rndr_and_cntpct_are_inputs_of_the_boot_seed() {
    let mut r = region();
    let a = seed_of(&Oracle::boot(&mut r, &tls_public(), &mut FakeHw { ok: true, byte: 0x43, tick: 7 }).unwrap());
    let mut r = region();
    let b = seed_of(&Oracle::boot(&mut r, &tls_public(), &mut FakeHw { ok: true, byte: 0x42, tick: 8 }).unwrap());
    let base = booted_seed(&TLS_PRIVATE, &[0x99; 32]);
    assert_ne!(a, base);
    assert_ne!(b, base);
}

/// F12: a repeated call returns the same value and spends the bucket each
/// time.
#[test]
fn repeated_boot_seed_calls_return_the_same_value_and_count_against_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Bucket::new(2, 1000);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    let first = unpack32(&reply[..4]).unwrap();
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(unpack32(&reply[..4]).unwrap(), first);
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_RATE_LIMITED, 0));
}

// ---------------------------------------------------------------- the table

/// Labels outside `Tls`'s row: either side of it, `key`'s `STATIC_DH` (1)
/// and the retired static-PSK label (2), and the largest label.
const OUTSIDE_TLS: [u64; 5] = [0, 1, 2, 5, u64::MAX];

#[test]
fn labels_outside_the_tls_row_are_refused_without_spending_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    // A one-call bucket: if any refusal spent it, the final call would be
    // rate limited.
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    for label in OUTSIDE_TLS {
        assert!(!Caller::Tls.allows(label), "{label}");
        for req in [&[][..], &[0; 1], &[0; 4], &[0; 5], &[0; 8]] {
            assert_eq!(call(&o, TLS, &mut b, label, req, &mut reply), (ERR_BAD_REQUEST, 0), "{label}");
            assert_eq!(reply, [0; MAX_WORDS]);
        }
    }
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, ERR_RATE_LIMITED);
}

#[test]
fn wrong_sizes_are_bad_requests_that_cost_nothing() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    for (label, req) in [(LABEL_BOOT_SEED, &[0u64][..]), (LABEL_TLS_SIGN, &[0; 3]), (LABEL_TLS_SIGN, &[0; 5]), (LABEL_TLS_SIGN, &[0; 8])] {
        assert_eq!(call(&o, TLS, &mut b, label, req, &mut reply), (ERR_BAD_REQUEST, 0), "{label} {}", req.len());
        assert_eq!(reply, [0; MAX_WORDS]);
    }
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

#[test]
fn an_unknown_caller_is_refused_for_every_label_without_spending_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    assert_eq!(call(&o, None, &mut b, LABEL_BOOT_SEED, &[], &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(call(&o, None, &mut b, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_BAD_REQUEST, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(call(&o, TLS, &mut b, LABEL_BOOT_SEED, &[], &mut reply).0, OK);
}

static SIGNS: AtomicUsize = AtomicUsize::new(0);

fn counting_sign(sig: &mut [u8; 64], msg: &[u8], private: &[u8; 32], nonce: &[u8; 32]) -> bool {
    SIGNS.fetch_add(1, Ordering::SeqCst);
    libcrux_sign(sig, msg, private, nonce)
}

/// A refusal of the bucket does no signing work at all.
#[test]
fn a_rate_limited_sign_spends_no_signature() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    let hash = pack32(&[7; 32]);
    let before = SIGNS.load(Ordering::SeqCst);
    assert_eq!(o.handle_with(counting_sign, TLS, &mut b, 0, &mut hw(), LABEL_TLS_SIGN, &hash, &mut reply).0, OK);
    assert_eq!(SIGNS.load(Ordering::SeqCst) - before, 1);
    reply.fill(u64::MAX);
    assert_eq!(o.handle_with(counting_sign, TLS, &mut b, 0, &mut hw(), LABEL_TLS_SIGN, &hash, &mut reply), (ERR_RATE_LIMITED, 0));
    assert_eq!(SIGNS.load(Ordering::SeqCst) - before, 1, "the refused call signed");
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(o.handle_with(counting_sign, TLS, &mut b, 1000, &mut hw(), LABEL_TLS_SIGN, &hash, &mut reply).0, OK);
}

#[test]
fn the_production_bucket_has_the_documented_size() {
    let mut b = Bucket::default();
    for _ in 0..TLS_SIGN_BURST {
        assert!(b.take(0));
    }
    assert!(!b.take(0));
    assert!(b.take(TLS_SIGN_INTERVAL_NS));
    assert_eq!((TLS_SIGN_BURST, TLS_SIGN_INTERVAL_NS, TLS_BOOT_CALLS), (32, 50_000_000, 1));
}

#[test]
fn pack_and_unpack_round_trip() {
    let v: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(unpack32(&pack32(&v)), Some(v));
}

// ---------------------------------------------------------------- TLS_SIGN

fn verify(content: &[u8], sig: &[u8; 64]) -> bool {
    libcrux_p256::ecdsa_verif_p256_sha2(content.len() as u32, content, &xy(&TLS_PRIVATE), &sig[..32], &sig[32..])
}

fn sig_of(reply: &[u64]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    for (c, w) in sig.chunks_mut(8).zip(reply) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    sig
}

fn content_for(hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut c = std::vec![0x20u8; 64];
    c.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    c.push(0);
    c.extend_from_slice(hash);
    c
}

/// RFC 8446 §4.4.3: `tlskey` signs the server CertificateVerify content it
/// builds around the hash, not the hash or anything else (M6 plan C5).
#[test]
fn tls_sign_signs_the_server_certificate_verify_content_of_the_hash() {
    let mut r = region();
    let o = oracle(&mut r);
    let hash: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0xa5);
    let mut reply = [0u64; MAX_WORDS];
    assert_eq!(call(&o, TLS, &mut bucket(), LABEL_TLS_SIGN, &pack32(&hash), &mut reply), (OK, 8));
    let sig = sig_of(&reply);
    let content = content_for(&hash);
    assert_eq!(content.len(), CV_CONTENT_LEN);
    assert!(verify(&content, &sig), "not a signature over the CertificateVerify content");
    assert!(!verify(&hash, &sig));
    let mut client = content.clone();
    client[64 + 9] = b'c'; // "client CertificateVerify"
    client[64 + 10..64 + 15].copy_from_slice(b"lient");
    assert!(!verify(&client, &sig));
}

#[test]
fn certificate_verify_content_is_the_rfc_8446_layout() {
    let mut c = Secret::<CV_CONTENT_LEN>::zero();
    certificate_verify_content(&mut c, &[9; 32]);
    assert_eq!(&c.as_bytes()[..], &content_for(&[9; 32])[..]);
}

/// L9: no RNDR, no k', no signature.
#[test]
fn tls_sign_with_rndr_failing_is_a_crypto_error_and_spends_the_bucket() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut b = Bucket::new(1, 1000);
    let mut reply = [u64::MAX; MAX_WORDS];
    let mut bad = FakeHw { ok: false, byte: 0x42, tick: 0 };
    assert_eq!(o.handle(TLS, &mut b, 0, &mut bad, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_CRYPTO, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
    assert_eq!(call(&o, TLS, &mut b, LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_RATE_LIMITED, 0));
}

/// S7: k' is an input of the nonce, so two RNDR draws give two r for one
/// transcript (and both verify).
#[test]
fn two_k_prime_values_give_different_r_for_the_same_hash() {
    let mut r = region();
    let o = oracle(&mut r);
    let hash = pack32(&[3; 32]);
    let mut sigs = std::vec::Vec::new();
    for byte in [0x42, 0x43] {
        let mut reply = [0u64; MAX_WORDS];
        let mut e = FakeHw { ok: true, byte, tick: 7 };
        assert_eq!(o.handle(TLS, &mut bucket(), 0, &mut e, LABEL_TLS_SIGN, &hash, &mut reply).0, OK);
        let sig = sig_of(&reply);
        assert!(verify(&content_for(&[3; 32]), &sig));
        sigs.push(sig);
    }
    assert_ne!(sigs[0][..32], sigs[1][..32]);
    // The same k' gives the same signature (the nonce is deterministic in it).
    let mut reply = [0u64; MAX_WORDS];
    o.handle(TLS, &mut bucket(), 0, &mut hw(), LABEL_TLS_SIGN, &hash, &mut reply);
    assert_eq!(sig_of(&reply), sigs[0]);
}

fn sign_hex(msg: &[u8], extra: &[u8]) -> (std::string::String, std::string::String) {
    let mut sig = Secret::<64>::zero();
    assert!(sign_rfc6979(libcrux_sign, &mut sig, msg, &TLS_PRIVATE, extra));
    let hex = |b: &[u8]| b.iter().map(|x| std::format!("{x:02X}")).collect::<std::string::String>();
    (hex(&sig.as_bytes()[..32]), hex(&sig.as_bytes()[32..]))
}

/// RFC 6979 A.2.5, P-256 with SHA-256, empty k': both messages' signatures.
#[test]
fn rfc6979_a_2_5_signatures_are_reproduced_with_an_empty_additional_input() {
    let pub_xy = xy(&TLS_PRIVATE);
    assert_eq!(pub_xy[..32], hex32("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"));
    assert_eq!(pub_xy[32..], hex32("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"));
    assert_eq!(
        sign_hex(b"sample", &[]),
        (
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716".into(),
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8".into()
        )
    );
    assert_eq!(
        sign_hex(b"test", &[]),
        (
            "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367".into(),
            "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083".into()
        )
    );
}

/// The nonces a sign function was handed, and how many it refused first.
static NONCES: std::sync::Mutex<std::vec::Vec<[u8; 32]>> = std::sync::Mutex::new(std::vec::Vec::new());
static REFUSE_FIRST: AtomicUsize = AtomicUsize::new(0);

fn recording_sign(sig: &mut [u8; 64], msg: &[u8], private: &[u8; 32], nonce: &[u8; 32]) -> bool {
    let mut seen = NONCES.lock().unwrap();
    seen.push(*nonce);
    if seen.len() <= REFUSE_FIRST.load(Ordering::SeqCst) {
        return false;
    }
    libcrux_sign(sig, msg, private, nonce)
}

/// The candidates sign_rfc6979 hands `recording_sign` (which refuses the
/// first `refuse`), and its result. One test at a time holds the lock.
fn candidates(refuse: usize, msg: &[u8], extra: &[u8]) -> (bool, std::vec::Vec<[u8; 32]>, [u8; 64]) {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    NONCES.lock().unwrap().clear();
    REFUSE_FIRST.store(refuse, Ordering::SeqCst);
    let mut sig = Secret::<64>::zero();
    let ok = sign_rfc6979(recording_sign, &mut sig, msg, &TLS_PRIVATE, extra);
    (ok, NONCES.lock().unwrap().clone(), *sig.as_bytes())
}

use rfc6979::bigint::U256;
use sha2::{Digest, Sha256};

const N: U256 = U256::from_be_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

/// RustCrypto's generator: its first `count` candidates for (x, h, k').
fn reference_ks(x: &[u8; 32], h: &[u8; 32], extra: &[u8], count: usize) -> std::vec::Vec<[u8; 32]> {
    let mut g = rfc6979::KGenerator::<Sha256, U256>::new(x, h, extra, &N);
    (0..count)
        .map(|_| {
            let mut k = [0u8; 32];
            g.fill_next_k(&mut k);
            k
        })
        .collect()
}

#[test]
fn rfc6979_a_2_5_nonce_is_the_first_candidate() {
    let (ok, ks, _) = candidates(0, b"sample", &[]);
    assert!(ok);
    assert_eq!(ks, [hex32("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")]);
}

/// The step h.3 branch: a candidate the sign function refuses moves the
/// DRBG on, and the next candidate is the reference generator's second.
#[test]
fn a_refused_candidate_continues_with_the_next_drbg_output() {
    let extra = [0x5a; 32];
    let msg = b"forced rejection";
    let (ok, ks, sig) = candidates(1, msg, &extra);
    assert!(ok);
    let h: [u8; 32] = Sha256::digest(msg).into();
    assert_eq!(ks, reference_ks(&TLS_PRIVATE, &h, &extra, 2));
    assert!(verify(msg, &sig));
}

/// S-N4, F-N6: at most `MAX_NONCE_CANDIDATES`, then a failure with the
/// signature wiped.
#[test]
fn a_sign_function_that_keeps_refusing_stops_at_the_candidate_cap() {
    let (ok, ks, sig) = candidates(usize::MAX, b"cap", &[1; 32]);
    assert!(!ok);
    assert_eq!(ks.len(), MAX_NONCE_CANDIDATES);
    assert_eq!(MAX_NONCE_CANDIDATES, 8);
    assert_eq!(sig, [0; 64]);
    let h: [u8; 32] = Sha256::digest(b"cap").into();
    assert_eq!(ks, reference_ks(&TLS_PRIVATE, &h, &[1; 32], MAX_NONCE_CANDIDATES));
}

#[test]
fn tls_sign_answers_a_crypto_error_when_every_candidate_is_refused() {
    let mut r = region();
    let o = oracle(&mut r);
    let mut reply = [u64::MAX; MAX_WORDS];
    fn never(_: &mut [u8; 64], _: &[u8], _: &[u8; 32], _: &[u8; 32]) -> bool {
        false
    }
    assert_eq!(o.handle_with(never, TLS, &mut bucket(), 0, &mut hw(), LABEL_TLS_SIGN, &pack32(&[1; 32]), &mut reply), (ERR_CRYPTO, 0));
    assert_eq!(reply, [0; MAX_WORDS]);
}

/// splitmix64: reproducible test inputs (no OS randomness in crates/, P8).
struct Mix(u64);

impl Mix {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *b = (z ^ (z >> 31)) as u8;
        }
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
}

/// h mod n with RustCrypto's big integers: the reduction computed apart
/// from `bits2octets`.
fn reduced(h: &[u8; 32]) -> [u8; 32] {
    let v = U256::from_be_slice(h);
    let r = if v >= N { v.wrapping_sub(&N) } else { v };
    r.to_be_bytes().into()
}

fn our_ks(x: &[u8; 32], h: &[u8; 32], extra: &[u8], count: usize) -> std::vec::Vec<[u8; 32]> {
    let mut d = Drbg::new(x, &bits2octets(h), extra).unwrap();
    let mut k = Secret::<32>::zero();
    (0..count)
        .map(|i| {
            if i > 0 {
                d.reject().unwrap();
            }
            d.candidate(&mut k).unwrap();
            *k.as_bytes()
        })
        .collect()
}

/// S-N4: the DRBG against RustCrypto's `rfc6979` over random keys, hashes
/// and k' values, and hashes at and above n (whose reduction is checked
/// against an independent one first).
#[test]
fn the_drbg_matches_rustcrypto_rfc6979_over_random_inputs_and_hashes_at_or_above_n() {
    let mut m = Mix(0x6979);
    let n = N.to_be_bytes();
    let mut hashes: std::vec::Vec<[u8; 32]> = (0..64).map(|_| m.bytes32()).collect();
    hashes.push(n.into());
    hashes.push([0xff; 32]);
    let mut above = [0u8; 32];
    above.copy_from_slice(&n);
    above[31] = above[31].wrapping_add(1);
    hashes.push(above);
    for _ in 0..8 {
        // Above n: n's top 32 bits are all ones and its next 32 all zeros.
        let mut h = m.bytes32();
        h[..4].copy_from_slice(&[0xff; 4]);
        h[4] |= 1;
        assert!(U256::from_be_slice(&h) > N);
        hashes.push(h);
    }
    for h in &hashes {
        assert_eq!(bits2octets(h), reduced(h), "bits2octets({h:02x?})");
        let x = loop {
            let x = m.bytes32();
            if U256::from_be_slice(&x) < N && x != [0; 32] {
                break x;
            }
        };
        let mut extra = [0u8; 32];
        m.fill(&mut extra);
        for e in [&extra[..], &[][..]] {
            assert_eq!(our_ks(&x, h, e, 3), reference_ks(&x, h, e, 3), "x {x:02x?} h {h:02x?}");
        }
    }
}
