//! Residue mode (M4 plan C9, invariant I5): runs natively. Each KEM call
//! runs on a painted stack the harness owns (`stack.rs`); after the join
//! the stack is searched for every stored form of every secret the call
//! handled. The needles are computed on the main thread into the heap,
//! from the port's own `pub` stage, pack and transpose functions.
//!
//! The same scan covers the envelope-open closure `key` and `pqkey` ship
//! (M5 plan I10.3): `tpm2::envelope::open_sealed` on an envelope sealed
//! here under a known KEK, its needles the KEK and the opened blob.
//!
//! And the hybrid key exchange `tls` ships (M6 plan C7, T-R4-1):
//! `tls_core::exchange_with_randomness` with known randomness, answering a
//! client share made here, then `tls_core::scrub_session_stack` from the
//! same frame. Its needles are the X25519 ephemeral (raw and clamped), the
//! ML-KEM encapsulation randomness and the G state derived from it, and
//! both component shared secrets, computed on the client side. A run
//! without the scrub first measures the exchange's own depth against
//! `SCRUB_DEPTH_EXCHANGE`, what the scrub covers.
//!
//! And the same exchange at its production call site: a ClientHello
//! carrying that client share through `tls_core::handshake::Session`, the
//! randomness replayed through the `Rng` seam, so that the scrub
//! `on_hello_record` runs after `HybridSecret::exchange` is the only one
//! between the exchange and the scan (the harness adds none), with the
//! same needles.

use std::collections::{HashMap, HashSet};
use std::hint::black_box;

use mce460896::stages::{self, Vec13};
use mce460896::{
    CT_LEN, ENCAPS_RAND_LEN, PK_LEN, RngError, SCRUB_DEPTH, SCRUB_DEPTH_ENCAPS, SK_LEN, SS_LEN, decaps, encaps,
    encaps_attempt,
};

use tpm2::Secret;
use tpm2::envelope::{self, Envelope, Kind, OPEN_SCRUB_DEPTH, SEAL_ENTROPY_LEN};

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext};
use sha3::{Digest, Sha3_256, Sha3_512};
use tls_core::handshake::{self, Buffers, Ctx, RX_BUF_LEN, Session, Signer, TX_BUF_LEN};
use tls_core::hybrid::EXCHANGE_RANDOMNESS_LEN;
use tls_core::rng::{self, Rng};
use tls_core::{
    CLIENT_SHARE_LEN, Refusal, SCRUB_DEPTH_EXCHANGE, SERVER_SHARE_LEN, exchange_with_randomness, scrub_session_stack,
};
use tls_wire::{ECDSA_SECP256R1_SHA256, TLS12, TLS13, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768, ext, hs};

use crate::stack::OwnedStack;
use crate::vectors::{self, CLASSES, ENTRIES, SYND_BYTES, SYS_N, Vectors, boxed, h32};
use crate::vg;

/// The needle forms; a hit line names one.
const FORMS: [&str; 17] = [
    "rand",
    "e-bytes",
    "ind",
    "e-bitsliced",
    "g",
    "support",
    "syndrome",
    "bm",
    "keccak",
    "ss",
    "kek",
    "plain",
    "eph",
    "kem-rand",
    "kem-g",
    "kem-ss",
    "x-ss",
];
#[derive(Clone, Copy)]
enum Form {
    Rand,
    EBytes,
    Ind,
    EBitsliced,
    G,
    Support,
    Syndrome,
    Bm,
    Keccak,
    Ss,
    Kek,
    Plain,
    Eph,
    KemRand,
    KemG,
    KemSs,
    XSs,
}

/// The stack each call runs on, and the padding frame between the
/// thread's entry and the call: glibc's thread exit runs above the pad, so
/// it cannot overwrite what the call left.
const STACK: usize = 1 << 20;
const PAD: usize = 64 * 1024;
const PAINT: u8 = 0x5c;
/// The painted-depth floors: every call must have disturbed at least this
/// much stack below the pad, so that the scanned region holds its frames.
/// About half of each `_core` stage's own peak on this build (decaps_core
/// 63 KiB, encaps_attempt_core 4 KiB), so that they hold with or without
/// the scrub; with it, every call reaches its scrub depth.
const FLOOR_DECAPS: usize = 32 * 1024;
const FLOOR_ENCAPS: usize = 2 * 1024;
const _: () = assert!(
    SCRUB_DEPTH >= FLOOR_DECAPS && SCRUB_DEPTH_ENCAPS >= FLOOR_ENCAPS,
    "the scrub must cover the painted-depth floor"
);

/// The envelope open's floor: what `open_core` and the AEAD disturb with
/// or without the scrub (the scrub alone writes `OPEN_SCRUB_DEPTH`).
const FLOOR_OPEN: usize = 512;
const _: () = assert!(
    OPEN_SCRUB_DEPTH >= FLOOR_OPEN,
    "the open's scrub must cover the painted-depth floor"
);

/// The hybrid exchange's floor: what `exchange_with_randomness` disturbs
/// with or without the scrub, about half its own peak on this build
/// (33 KiB, the `exchange-depth` run).
const FLOOR_EXCHANGE: usize = 16 * 1024;
const _: () = assert!(
    SCRUB_DEPTH_EXCHANGE >= FLOOR_EXCHANGE,
    "the exchange's scrub must cover the painted-depth floor"
);

const MLKEM_CT_LEN: usize = 1088;

/// Decapsulations (the four classes per entry), encapsulation attempts
/// (every draw of each stream, the two crafted rejections), the generic
/// shim once per entry, the envelope open for each blob kind (key, pq and,
/// since M6 plan C12, tls), the hybrid exchange (its depth run, then its
/// scan), the ClientHello's keys at their call site (a depth run) and the
/// ClientHello through the handshake.
const CASES: usize = ENTRIES * CLASSES.len() + (1 + 3 + 4) + 2 + ENTRIES + 3 + 2 + 1 + 1;

/// 8-byte windows of the secret forms, at every byte offset.
struct Needles {
    windows: HashMap<u64, u32>,
    public: HashSet<u64>,
}

impl Needles {
    fn new() -> Self {
        Self {
            windows: HashMap::new(),
            public: HashSet::new(),
        }
    }

    /// A window counts if it could not be stack filler: three or more
    /// nonzero bytes, not all equal (the paint is one repeated byte).
    fn distinctive(w: &[u8]) -> bool {
        w.iter().filter(|&&b| b != 0).count() >= 3 && w.iter().any(|&b| b != w[0])
    }

    fn add(&mut self, form: Form, bytes: &[u8]) {
        for w in bytes.windows(8).filter(|w| Self::distinctive(w)) {
            *self
                .windows
                .entry(u64::from_le_bytes(w.try_into().expect("8")))
                .or_insert(0) |= 1 << form as u32;
        }
    }

    /// Public data the call may legitimately leave (the ciphertext): its
    /// windows are not needles.
    fn public(&mut self, bytes: &[u8]) {
        self.public.extend(
            bytes
                .windows(8)
                .map(|w| u64::from_le_bytes(w.try_into().expect("8"))),
        );
    }

    fn add_words(&mut self, form: Form, words: &[u64]) {
        self.add(form, &words_to_bytes(words));
    }

    fn add_vec13(&mut self, form: Form, v: &[Vec13]) {
        let words: Vec<u64> = v.iter().flatten().copied().collect();
        self.add_words(form, &words);
    }

    /// Per form: the number of matching offsets and the depth (from the
    /// top of the stack) of the deepest one.
    fn scan(&self, stack: &[u8], from: usize) -> Vec<(usize, usize, usize)> {
        let mut per = [(0usize, 0usize); FORMS.len()];
        for (o, w) in stack[from..].windows(8).enumerate() {
            let w = u64::from_le_bytes(w.try_into().expect("8"));
            if let Some(&mask) = self.windows.get(&w) {
                if self.public.contains(&w) {
                    continue;
                }
                for (f, p) in per.iter_mut().enumerate() {
                    if mask & (1 << f) != 0 {
                        if p.0 == 0 {
                            p.1 = stack.len() - (from + o);
                        }
                        p.0 += 1;
                    }
                }
            }
        }
        per.iter()
            .enumerate()
            .filter(|(_, p)| p.0 > 0)
            .map(|(f, p)| (f, p.0, p.1))
            .collect()
    }
}

fn words_to_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// SHAKE256's absorbed states for `msg`: each block's state before and
/// after `keccak::f1600`. Checked against `sha3`: the last state's first
/// 32 bytes are the digest.
fn shake256_states(msg: &[u8]) -> Vec<[u64; 25]> {
    const RATE: usize = 136;
    let mut padded = msg.to_vec();
    padded.push(0x1f);
    while !padded.len().is_multiple_of(RATE) {
        padded.push(0);
    }
    *padded.last_mut().expect("block") |= 0x80;
    let mut st = [0u64; 25];
    let mut out = Vec::new();
    for block in padded.chunks(RATE) {
        for (lane, c) in st.iter_mut().zip(block.chunks(8)) {
            *lane ^= u64::from_le_bytes(c.try_into().expect("8"));
        }
        out.push(st);
        keccak::f1600(&mut st);
        out.push(st);
    }
    assert_eq!(
        words_to_bytes(&st)[..32],
        h32(&[msg]),
        "sponge model differs from sha3"
    );
    out
}

/// The keccak needles of one `hash_32b` call: the secret part of its
/// preimage, and every absorbed state.
fn add_hash(n: &mut Needles, secret_prefix: &[u8], public_suffix: &[u8]) {
    n.add(Form::Keccak, secret_prefix);
    let msg = [secret_prefix, public_suffix].concat();
    for st in shake256_states(&msg) {
        n.add_words(Form::Keccak, &st);
    }
}

/// `benes`'s last horizontal form of the 128 words `r`: the halves
/// de-interleaved and transposed, as it holds them before writing back.
fn benes_transposed(r: &[u64; 128]) -> Vec<u64> {
    let mut v = [[0u64; 64]; 2];
    for i in 0..64 {
        v[0][i] = r[i * 2];
        v[1][i] = r[i * 2 + 1];
    }
    stages::transpose_64x64(&mut v[0]);
    stages::transpose_64x64(&mut v[1]);
    v.iter().flatten().copied().collect()
}

fn e_words(e: &[u8; SYS_N / 8]) -> [u64; 128] {
    let mut r = [0u64; 128];
    for (w, c) in r.iter_mut().zip(e.chunks(8)) {
        *w = u64::from_le_bytes(c.try_into().expect("8"));
    }
    r
}

/// Offsets into the secret key (`lib.rs`).
const SK_IRR: usize = 40;
const SK_COND: usize = SK_IRR + 192;
const SK_S: usize = SK_LEN - SYS_N / 8;

fn decaps_needles(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN], want: &[u8]) -> Needles {
    let mut n = Needles::new();
    n.public(ct);
    let d = stages::decode(sk, ct);

    n.add(Form::EBytes, &d.e);
    n.add_words(Form::EBitsliced, &benes_transposed(&e_words(&d.e)));

    let g = stages::g_bitsliced(sk);
    n.add_vec13(Form::G, &g);
    n.add(Form::G, &sk[SK_IRR..SK_COND]);

    n.add_vec13(Form::Support, &d.inv);
    n.add_words(Form::Support, &d.recv);
    n.add_words(Form::Support, &benes_transposed(&d.recv));
    n.add(Form::Support, &sk[SK_COND..SK_S]);

    let syn = stages::syndrome(sk, ct);
    assert!(syn == d.syndrome, "syndrome stage");
    n.add_vec13(Form::Syndrome, &syn);

    let loc = stages::bm(&syn);
    assert!(loc == d.locator, "bm stage");
    n.add_vec13(Form::Bm, &loc);
    // BM's last `C(x)` high half, which `bm` shifts into its output.
    let c_high: Vec<u64> = (0..13)
        .map(|i| (loc[1][i] << 31) | (loc[0][i] >> 33))
        .collect();
    n.add_words(Form::Bm, &c_high);

    let conf = h32(&[&[2], &d.e]);
    add_hash(&mut n, &[&[2u8][..], &d.e].concat(), &[]);
    let ok = d.fail == 0 && conf[..] == ct[SYND_BYTES..];
    let sel: &[u8] = if ok { &d.e } else { &sk[SK_S..] };
    let prefix = [&[u8::from(ok)][..], sel].concat();
    add_hash(&mut n, &prefix, ct);
    assert_eq!(h32(&[&prefix, ct]), want, "decaps needle derivation");
    n.add(Form::Ss, want);
    n
}

/// One attempt's needles. Returns the attempt's shared secret (the
/// output if it accepts).
fn attempt_needles(
    n: &mut Needles,
    pk: &[u8; PK_LEN],
    rand: &[u8; ENCAPS_RAND_LEN],
) -> (bool, [u8; CT_LEN], [u8; SS_LEN]) {
    n.add(Form::Rand, rand);
    let nums: Vec<u8> = rand
        .chunks(2)
        .flat_map(|c| (u16::from_le_bytes([c[0], c[1]]) & 0x1fff).to_le_bytes())
        .collect();
    n.add(Form::Rand, &nums);

    let s = stages::sample(rand);
    let accept = s.accept == 0xffff;
    n.add(Form::Ind, &stages::pack_ind(&s.ind));
    n.add(Form::EBytes, &s.e);
    n.add_words(Form::EBitsliced, &s.e_words);

    let c0 = stages::encrypt_syndrome(pk, &s.e);
    let c1 = h32(&[&[2], &s.e]);
    let mut ct = [0u8; CT_LEN];
    ct[..SYND_BYTES].copy_from_slice(&c0);
    ct[SYND_BYTES..].copy_from_slice(&c1);
    if accept {
        n.public(&ct);
    } else {
        n.add(Form::Syndrome, &c0);
    }
    add_hash(n, &[&[2u8][..], &s.e].concat(), &[]);
    add_hash(n, &[&[1u8][..], &s.e].concat(), &ct);
    let ss = h32(&[&[1], &s.e, &ct]);
    n.add(Form::Ss, &ss);
    (accept, ct, ss)
}

/// Deterministic bytes per label, every 8-byte window distinctive.
fn stream(label: &[u8], len: usize) -> Vec<u8> {
    let mut rng = vectors::SplitMix::new(u64::from_le_bytes(h32(&[label])[..8].try_into().expect("8")));
    let mut out = vec![0u8; len];
    rng.fill(&mut out);
    out
}

/// An envelope of `kind` sealed here (to an SRK of a fixed scalar, PCR 8
/// fixed): the envelope, its KEK and the blob it opens to (the region,
/// its payload nonzero up to `len`).
fn sealed_envelope(kind: Kind, len: usize) -> (Vec<u8>, Box<Secret<32>>, Vec<u8>) {
    let mut scalar = Secret::<32>::zero();
    scalar.as_mut_bytes().copy_from_slice(&stream(b"srk", 32));
    let point = tpm2::crypto::public_point(&scalar).expect("SRK scalar");
    let srk = [&tpm2_wire::SRK_PUBLIC_PREFIX[..], &tpm2::crypto::ecc_point(&point)].concat();
    let mut entropy = Secret::<SEAL_ENTROPY_LEN>::zero();
    entropy
        .as_mut_bytes()
        .copy_from_slice(&stream(&[b"seal".as_slice(), &kind.code().to_le_bytes()].concat(), SEAL_ENTROPY_LEN));
    let mut plain = vec![0u8; kind.region_size()];
    plain[..len].copy_from_slice(&stream(b"blob", len));
    plain[len - 1] |= 1;
    let mut env = vec![0u8; kind.region_size()];
    envelope::seal(&mut env, kind, &plain, &srk, &[[0x88; 32]; tpm2_wire::POLICY_PCR_COUNT], &entropy).expect("seal");
    let mut kek = Box::new(Secret::<32>::zero());
    kek.as_mut_bytes().copy_from_slice(&entropy.as_bytes()[..32]);
    (env, kek, plain)
}

/// A client share made here from fixed seeds (an ML-KEM-768 encapsulation
/// key, then an X25519 public key), the server's randomness, and the
/// client's two secret keys, to compute the component secrets with.
struct ClientShare {
    share: Box<[u8; CLIENT_SHARE_LEN]>,
    randomness: Box<[u8; EXCHANGE_RANDOMNESS_LEN]>,
    kem: mlkem768::MlKem768KeyPair,
    x_sk: [u8; 32],
}

fn client_share() -> ClientShare {
    let kem = mlkem768::generate_key_pair(stream(b"tls-client-kem", 64).try_into().expect("64"));
    let x_sk: [u8; 32] = stream(b"tls-client-x25519", 32).try_into().expect("32");
    let mut x_pk = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut x_pk, &x_sk);
    let mut share = Box::new([0u8; CLIENT_SHARE_LEN]);
    share[..CLIENT_SHARE_LEN - 32].copy_from_slice(kem.pk());
    share[CLIENT_SHARE_LEN - 32..].copy_from_slice(&x_pk);
    let randomness = Box::new(stream(b"tls-exchange", EXCHANGE_RANDOMNESS_LEN).try_into().expect("64"));
    ClientShare {
        share,
        randomness,
        kem,
        x_sk,
    }
}

/// SHA3-512's state after its one permutation of the 64-byte `msg` (rate
/// 72, domain 0x06). Checked against `sha3`: its first 64 bytes are the
/// digest.
fn sha3_512_state(msg: &[u8]) -> [u64; 25] {
    let mut block = [0u8; 72];
    block[..64].copy_from_slice(msg);
    block[64] = 0x06;
    block[71] |= 0x80;
    let mut st = [0u64; 25];
    for (lane, c) in st.iter_mut().zip(block.chunks(8)) {
        *lane = u64::from_le_bytes(c.try_into().expect("8"));
    }
    keccak::f1600(&mut st);
    assert_eq!(
        words_to_bytes(&st)[..64],
        Sha3_512::digest(msg)[..],
        "sponge model differs from sha3"
    );
    st
}

/// The exchange's needles, from the server share it answered with: the
/// ephemeral as drawn and clamped, the encapsulation randomness m, G's
/// state over m ‖ H(ek) (K ‖ r and the rest of the sponge), K as the
/// client decapsulates it, and the X25519 secret as the client computes
/// it.
fn exchange_needles(c: &ClientShare, server: &[u8; SERVER_SHARE_LEN]) -> Needles {
    let mut n = Needles::new();
    n.public(server);
    let (m, scalar) = c.randomness.split_at(32);
    n.add(Form::Eph, scalar);
    let mut clamped: [u8; 32] = scalar.try_into().expect("32");
    libcrux_curve25519::clamp(&mut clamped);
    n.add(Form::Eph, &clamped);

    n.add(Form::KemRand, m);
    let g = sha3_512_state(&[m, &Sha3_256::digest(c.kem.pk())[..]].concat());
    n.add_words(Form::KemG, &g);
    let (ct, x_pk) = server.split_at(MLKEM_CT_LEN);
    let ct = MlKem768Ciphertext::try_from(ct).expect("ciphertext");
    let kem_ss = mlkem768::decapsulate(c.kem.private_key(), &ct);
    assert_eq!(words_to_bytes(&g)[..32], kem_ss[..], "exchange needle derivation");
    n.add(Form::KemSs, &kem_ss);

    let mut x_ss = [0u8; 32];
    assert!(libcrux_curve25519::ecdh(&mut x_ss, x_pk.try_into().expect("32"), &c.x_sk).is_ok(), "X25519");
    n.add(Form::XSs, &x_ss);
    n
}

fn vec8(data: &[u8]) -> Vec<u8> {
    [&[u8::try_from(data.len()).expect("u8")][..], data].concat()
}

fn vec16(data: &[u8]) -> Vec<u8> {
    [&u16::try_from(data.len()).expect("u16").to_be_bytes()[..], data].concat()
}

fn ext_block(ty: u16, data: &[u8]) -> Vec<u8> {
    [&ty.to_be_bytes()[..], &vec16(data)].concat()
}

/// A ClientHello record offering the profile's minimum (the shape of
/// tls-core's test client) with `share` as its one key share.
fn client_hello_record(share: &[u8; CLIENT_SHARE_LEN]) -> Vec<u8> {
    let mut body = TLS12.to_be_bytes().to_vec();
    body.extend_from_slice(&[0xc1; 32]);
    body.extend_from_slice(&vec8(&[0x5e; 32]));
    body.extend_from_slice(&vec16(&TLS_CHACHA20_POLY1305_SHA256.to_be_bytes()));
    body.extend_from_slice(&vec8(&[0]));
    let mut exts = ext_block(ext::SUPPORTED_VERSIONS, &vec8(&TLS13.to_be_bytes()));
    exts.extend(ext_block(ext::SUPPORTED_GROUPS, &vec16(&X25519MLKEM768.to_be_bytes())));
    let entry = [&X25519MLKEM768.to_be_bytes()[..], &vec16(share)].concat();
    exts.extend(ext_block(ext::KEY_SHARE, &vec16(&entry)));
    exts.extend(ext_block(ext::SIGNATURE_ALGORITHMS, &vec16(&ECDSA_SECP256R1_SHA256.to_be_bytes())));
    body.extend_from_slice(&vec16(&exts));
    let mut msg = vec![hs::CLIENT_HELLO];
    msg.extend_from_slice(&u32::try_from(body.len()).expect("u32").to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&u16::try_from(msg.len()).expect("u16").to_be_bytes());
    record.extend_from_slice(&msg);
    record
}

/// The deterministic RNG seam: replays `bytes` from the heap, so the
/// handshake's exchange draws the residue case's known randomness first.
struct Replay {
    bytes: Vec<u8>,
    at: usize,
}

impl Rng for Replay {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), rng::RngError> {
        let src = self.bytes.get(self.at..self.at + out.len()).ok_or(rng::RngError)?;
        out.copy_from_slice(src);
        self.at += out.len();
        Ok(())
    }
}

/// `tlskey`'s TlsSign stand-in: a fixed, public r ‖ s (the flight is not
/// verified here).
struct FixedSigner;

impl Signer for FixedSigner {
    fn sign(&mut self, _: &[u8; 32]) -> Result<[u8; 64], Refusal> {
        Ok([0x42; 64])
    }
}

#[inline(never)]
fn padded(f: impl FnOnce()) {
    let mut pad = [0u8; PAD];
    black_box(&mut pad);
    f();
    black_box(&pad);
}

struct Scan {
    stack: OwnedStack,
    base: usize,
    cases: usize,
    failed: bool,
}

impl Scan {
    /// Paints the stack, runs `f` on it, and returns how deep (from the
    /// top) the paint was disturbed.
    fn run(&mut self, f: impl FnOnce() + Send) -> usize {
        self.stack.bytes_mut().fill(PAINT);
        self.stack.run(|| padded(f));
        let low = self
            .stack
            .bytes()
            .iter()
            .position(|&b| b != PAINT)
            .unwrap_or(STACK);
        STACK - low
    }

    fn case(&mut self, name: &str, floor: usize, needles: &Needles, f: impl FnOnce() + Send) {
        let depth = self.run(f);
        let used = depth.saturating_sub(self.base);
        println!("RESIDUE-DEPTH {name} {used}");
        if used < floor {
            println!("RESIDUE-SHALLOW {name}: {used} bytes below the pad, floor {floor}");
            self.failed = true;
        }
        for (f, count, at) in needles.scan(self.stack.bytes(), STACK - depth) {
            println!(
                "RESIDUE-HIT {} case={name} windows={count} depth={at}",
                FORMS[f]
            );
            self.failed = true;
        }
        self.cases += 1;
    }

    /// Runs `f`, with no scrub after it, and fails if it disturbed more
    /// stack below the pad than `limit`: what the scrub following it must
    /// cover.
    fn ceiling(&mut self, name: &str, limit: usize, f: impl FnOnce() + Send) {
        let used = self.run(f).saturating_sub(self.base);
        println!("RESIDUE-DEPTH {name} {used}");
        if used > limit {
            println!("RESIDUE-DEEP {name}: {used} bytes below the pad, the scrub covers {limit}");
            self.failed = true;
        }
        self.cases += 1;
    }

    fn check(&mut self, what: &str, ok: bool) {
        if !ok {
            println!("RESIDUE-FAIL {what}");
            self.failed = true;
        }
    }
}

pub fn run() -> ! {
    if vg::running_on_valgrind() {
        println!("RESIDUE-UNDER-VALGRIND residue mode must run natively, not under valgrind");
        std::process::exit(4);
    }
    println!("RESIDUE-CASES {CASES}");

    let mut scan = Scan {
        stack: OwnedStack::new(STACK),
        base: 0,
        cases: 0,
        failed: false,
    };
    scan.base = scan.run(|| {});

    let v = Vectors::load();
    let mut shim_rejected = false;
    for i in 0..ENTRIES {
        let sk = v.sk(i);
        let pk = v.pk(&sk);

        for class in CLASSES {
            let ct: Box<[u8; CT_LEN]> = Box::new(v.array(&format!("mce.{i}.dec.{class}.ct")));
            let want = v.get(&format!("mce.{i}.dec.{class}.ss"));
            let needles = decaps_needles(&sk, &ct, want);
            let mut ss = boxed::<SS_LEN>();
            scan.case(
                &format!("decaps.{i}.{class}"),
                FLOOR_DECAPS,
                &needles,
                || decaps(&sk, &ct, &mut ss),
            );
            scan.check(&format!("decaps.{i}.{class} output"), ss[..] == *want);
        }

        let attempts = v.attempts(i);
        let mut rands: Vec<(String, Box<[u8; ENCAPS_RAND_LEN]>)> = attempts
            .iter()
            .enumerate()
            .map(|(k, r)| (format!("encaps.{i}.attempt{k}"), r.clone()))
            .collect();
        if i == 0 {
            rands.push(("encaps.short".into(), Box::new(vectors::SHORT)));
            rands.push(("encaps.repeated".into(), Box::new(vectors::REPEATED)));
        }
        for (name, rand) in &rands {
            let mut needles = Needles::new();
            let (accept, ct, ss) = attempt_needles(&mut needles, &pk, rand);
            let (mut ct_out, mut ss_out) = (boxed::<CT_LEN>(), boxed::<SS_LEN>());
            let mut bit = Box::new(0u8);
            scan.case(name, FLOOR_ENCAPS, &needles, || {
                *bit = encaps_attempt(&pk, rand, &mut ct_out, &mut ss_out)
            });
            let ok = if accept {
                *bit == 1 && ct_out[..] == ct && ss_out[..] == ss
            } else {
                *bit == 0 && ct_out.iter().chain(ss_out.iter()).all(|&b| b == 0)
            };
            scan.check(&format!("{name} output"), ok);
        }

        // The generic shim, driven by a FnMut RNG that replays the entry's
        // stream from the heap.
        let stream: Vec<u8> = attempts.iter().flat_map(|r| r.iter().copied()).collect();
        let mut needles = Needles::new();
        for rand in &attempts {
            attempt_needles(&mut needles, &pk, rand);
        }
        let (mut ct_out, mut ss_out) = (boxed::<CT_LEN>(), boxed::<SS_LEN>());
        let mut drawn = Box::new(0usize);
        let mut result = Box::new(Err(RngError));
        scan.case(&format!("encaps-shim.{i}"), FLOOR_ENCAPS, &needles, || {
            let mut rng = |b: &mut [u8]| {
                let src = stream.get(*drawn..*drawn + b.len()).ok_or(RngError)?;
                b.copy_from_slice(src);
                *drawn += b.len();
                Ok(())
            };
            *result = encaps(&pk, &mut rng, &mut ct_out, &mut ss_out);
        });
        scan.check(
            &format!("encaps-shim.{i} output"),
            result.is_ok()
                && *drawn == stream.len()
                && ct_out[..] == *v.get(&format!("mce.{i}.ct"))
                && ss_out[..] == *v.get(&format!("mce.{i}.ss")),
        );
        shim_rejected |= attempts.len() > 1;
    }
    scan.check("the shim saw no rejected attempt", shim_rejected);

    // The envelope-open closure (I10.3): after it returns, neither the KEK
    // nor the blob it opened is left on the stack, and the KEK is wiped.
    for (kind, len) in [(Kind::Key, 1000), (Kind::Pq, secret_blob::pq::USED_LEN), (Kind::Tls, secret_blob::tls::USED_LEN)] {
        let (env, mut kek, plain) = sealed_envelope(kind, len);
        let mut needles = Needles::new();
        needles.add(Form::Kek, kek.as_bytes());
        needles.add(Form::Plain, &plain[..len]);
        let parsed = Envelope::parse(&env, kind).expect("envelope");
        let mut out = vec![0u8; kind.region_size()];
        let mut result = Box::new(Err(envelope::EnvError::Seal));
        let name = format!("open.{kind:?}");
        scan.case(&name, FLOOR_OPEN, &needles, || {
            *result = envelope::open_sealed(&parsed, &mut kek, &mut out);
        });
        scan.check(
            &format!("{name} output"),
            result.is_ok() && out == plain && kek.as_bytes().iter().all(|b| *b == 0),
        );
    }

    // The hybrid exchange (C7): without the scrub, within its depth; with
    // it, called from the frame that called the exchange, nothing left.
    // The result is dropped in place, wiping the secret it holds, before
    // the scan.
    let client = client_share();
    let mut first = Box::new([0u8; SERVER_SHARE_LEN]);
    scan.ceiling("exchange-depth", SCRUB_DEPTH_EXCHANGE, || {
        let r = exchange_with_randomness(&client.share, &client.randomness);
        if let Ok((_, share)) = &r {
            first.copy_from_slice(share);
        }
    });
    let needles = exchange_needles(&client, &first);
    let mut second = Box::new([0u8; SERVER_SHARE_LEN]);
    scan.case("exchange", FLOOR_EXCHANGE, &needles, || {
        let r = exchange_with_randomness(&client.share, &client.randomness);
        scrub_session_stack();
        if let Ok((_, share)) = &r {
            second.copy_from_slice(share);
        }
    });
    scan.check(
        "exchange output",
        first.iter().any(|&b| b != 0) && first == second,
    );

    // What the production scrub after `hello_keys` must cover (M6 code
    // review T5): its frames (the exchange, the ServerHello, the key
    // schedule and every copy of the hybrid secret) below the frame that
    // called it, here the closure's as on_hello_record's in the PD, with no
    // scrub after it.
    let record = client_hello_record(&client.share);
    let hello = &record[5..];
    let ch = tls_wire::hello::client_hello(&hello[4..]).expect("the residue case's ClientHello");
    let mut depth_rng = Box::new(Replay {
        bytes: [&client.randomness[..], &[0x7a; 32][..]].concat(),
        at: 0,
    });
    let mut depth_out = vec![0u8; 16 * 1024];
    let mut keyed = Box::new(false);
    scan.ceiling("hello-depth", SCRUB_DEPTH_EXCHANGE, || {
        let mut transcript = libcrux_sha2::Sha256::new();
        *keyed = handshake::hello_keys(&mut transcript, hello, &ch, &mut depth_out, &mut *depth_rng).is_ok();
    });
    scan.check("hello-depth keys", *keyed && depth_rng.at == depth_rng.bytes.len());

    // The same exchange at its production call site: on_hello_record calls
    // HybridSecret::exchange, then scrub_session_stack, then builds the
    // flight. Nothing here scrubs after the call, so a missing production
    // scrub leaves the exchange's secrets in the dead frames below it. The
    // session and buffers are on the heap, so only frames are scanned.
    let mut rng = Box::new(Replay {
        bytes: [&client.randomness[..], &[0x7a; 32][..]].concat(),
        at: 0,
    });
    let mut session = Box::new(Session::new());
    let (mut rx, mut tx, mut out) = (vec![0u8; RX_BUF_LEN], vec![0u8; TX_BUF_LEN], vec![0u8; 16 * 1024]);
    let mut step = Box::new(Err(Refusal::Internal));
    scan.case("hello", FLOOR_EXCHANGE, &needles, || {
        let mut bufs = Buffers {
            rx: &mut rx,
            tx: &mut tx,
            out: &mut out,
        };
        let mut ctx = Ctx {
            cert: &[0x30, 0x03, 0x02, 0x01, 0x01],
            rng: &mut *rng,
            signer: &mut FixedSigner,
        };
        *step = session.on_record(&record, &mut bufs, &mut ctx);
    });
    // ServerHello first, in the clear, its key share last.
    let sh_len = usize::from(u16::from_be_bytes([out[3], out[4]]));
    let sh = &out[5..5 + sh_len];
    scan.check(
        "hello output",
        matches!(*step, Ok(s) if s.event == handshake::Event::Flight)
            && rng.at == rng.bytes.len()
            && sh[sh.len() - SERVER_SHARE_LEN..] == first[..],
    );

    scan.check(
        &format!("{} cases run, {CASES} planned", scan.cases),
        scan.cases == CASES,
    );

    if scan.failed {
        println!("RESIDUE-FAILED");
        std::process::exit(1);
    }
    println!("RESIDUE-DONE {}", scan.cases);
    std::process::exit(0);
}
