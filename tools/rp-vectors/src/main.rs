//! Captures Rosenpass V02 golden vectors from upstream for rosenpass-core's
//! unit tests (M3 plan C1, T1). See README.md for the regeneration command.
//!
//! One upstream initiator (`a`, the client) and one upstream responder (`b`,
//! the gateway) run a full V02 handshake. Only the responder runs under
//! `assert_tv::TestVectorActive` in init mode, so the recorded values (ck
//! chain, sidr, the two encapsulations, the biscuit) are exactly the ones the
//! secureos responder must reproduce. Everything else (domains, macs, peer
//! ids, ICR ck values, the OSK) is computed with upstream's own functions.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, ensure, Context};
use assert_tv::{finalize_tv_case, initialize_tv_case_from_file, TestMode, TestVectorActive, TestVectorFileFormat};
use base64::Engine;
use rosenpass::hash_domains as hd;
use rosenpass::internal::cipher_traits::primitives::{AeadWithNonceInCiphertext, Kem, KeyedHashInstance};
use rosenpass::internal::ciphers::{EphemeralKem, KeyedHash, StaticKem, XAead};
use rosenpass::internal::secret_memory::policy::secret_policy_use_only_malloc_secrets;
use rosenpass::protocol::basic_types::{MsgBuf, SPk, SSk, SessionId};
use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
use rosenpass::protocol::{CryptoServer, HandshakeState, PeerPtr, ProtocolVersion};
use std::ops::DerefMut;

const UPSTREAM_REV: &str = "9e72f1eb871c4c403e99e9b78262fff8dd8d7357";
const KYBER_KAT_SEED: u64 = 0x5eed_0000_0000_4b59;
const MCELIECE_KAT_SEED: u64 = 0x5eed_0000_0000_4d43;

/// SplitMix64 as a byte stream (8 bytes LE per step). rosenpass-core's KAT
/// test implements the same stream, so liboqs and the Rust KEMs see the same
/// randomness whatever chunk sizes they request.
struct SplitMix {
    state: u64,
    buf: [u8; 8],
    used: usize,
}

impl SplitMix {
    fn new(seed: u64) -> Self {
        Self { state: seed, buf: [0; 8], used: 8 }
    }

    fn byte(&mut self) -> u8 {
        if self.used == 8 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            self.buf = (z ^ (z >> 31)).to_le_bytes();
            self.used = 0;
        }
        let b = self.buf[self.used];
        self.used += 1;
        b
    }
}

static STREAM: Mutex<Option<SplitMix>> = Mutex::new(None);

unsafe extern "C" fn stream_randombytes(buf: *mut u8, len: usize) {
    let mut guard = STREAM.lock().expect("stream lock");
    let s = guard.as_mut().expect("stream installed");
    // SAFETY: liboqs passes a writable buffer of `len` bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    for b in out {
        *b = s.byte();
    }
}

fn with_stream<T>(seed: u64, f: impl FnOnce() -> T) -> T {
    *STREAM.lock().expect("stream lock") = Some(SplitMix::new(seed));
    unsafe { oqs_sys::rand::OQS_randombytes_custom_algorithm(Some(stream_randombytes)) };
    let r = f();
    let system = oqs_sys::rand::OQS_RAND_alg_system.as_ptr().cast();
    let status = unsafe { oqs_sys::rand::OQS_randombytes_switch_algorithm(system) };
    assert_eq!(status, oqs_sys::rand::OQS_STATUS::OQS_SUCCESS);
    *STREAM.lock().expect("stream lock") = None;
    r
}

struct Out(BTreeMap<String, Vec<u8>>);

impl Out {
    fn put(&mut self, name: &str, v: &[u8]) -> anyhow::Result<()> {
        if self.0.insert(name.to_owned(), v.to_vec()).is_some() {
            bail!("duplicate vector {name}");
        }
        Ok(())
    }
}

fn gen_keypair() -> anyhow::Result<(SSk, SPk)> {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

fn ck_of(hs: &HandshakeState) -> Vec<u8> {
    hs.ck.clone().danger_into_secret().secret().to_vec()
}

/// Reads back the responder's recorded values from assert_tv's JSON file.
///
/// Upstream's `handle_msg` first tries an InitHello as V03 (SHAKE256); that
/// attempt records IHR4 and IHR5 and then fails at IHR6, after which the V02
/// attempt records the full sequence. Only the last sequence is ours. Unnamed
/// fields (assert_tv records them with a null name) are mapped by position.
fn recorded(path: &Path, out: &mut Out) -> anyhow::Result<()> {
    const SEQUENCE: [(Option<&str>, &str); 19] = [
        (Some("chaining_key_ihr IHR 4"), "ck.ihr4"),
        (Some("chaining_key_ihr IHR 5"), "ck.ihr5"),
        (Some("chaining_key_ihr IHR 6"), "ck.ihr6"),
        (Some("chaining_key_ihr IHR 7"), "ck.ihr7"),
        (Some("chaining_key_ihr IHR 8"), "ck.ihr8"),
        (Some("session_id"), "rhr1.sidr"),
        (Some("chaining_key_ihr RHR 3"), "ck.rhr3"),
        (None, "rhr4.shk"),
        (None, "rhr4.ct"),
        (Some("chaining_key_ihr RHR 4"), "ck.rhr4"),
        (None, "rhr5.shk"),
        (None, "rhr5.ct"),
        (Some("chaining_key_ihr RHR 5"), "ck.rhr5"),
        (None, "biscuit.pt"),
        (Some("CryptoServer::biscuit_key[r]"), "biscuit.key"),
        (None, "biscuit.nonce_drawn"),
        (None, "biscuit.ct"),
        (Some("chaining_key_ihr RHR 6"), "ck.rhr6"),
        (Some("chaining_key_ihr RHR 7"), "ck.rhr7"),
    ];
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let entries = json["entries"].as_array().context("entries")?;
    let first = entries
        .iter()
        .rposition(|e| e["name"].as_str() == Some("chaining_key_ihr IHR 4"))
        .context("no IHR4 recorded")?;
    let ours = &entries[first..];
    ensure!(ours.len() == SEQUENCE.len(), "recorded {} values, expected {}", ours.len(), SEQUENCE.len());
    for (e, (name, key)) in ours.iter().zip(SEQUENCE) {
        ensure!(e["name"].as_str() == name, "recorded {:?} where {name:?} was expected", e["name"]);
        let value = e["value"].as_str().context("entry value is not a string")?;
        out.put(key, &base64::engine::general_purpose::STANDARD.decode(value)?)?;
    }
    ensure!(out.0["rhr4.ct"].len() == 768 && out.0["rhr5.ct"].len() == 188, "encapsulation order");
    Ok(())
}

/// The cookie tree's vectors (M3b plan C1, VE11), from upstream's own
/// functions with the SHAKE256 keyed hash its cookie code always uses.
/// Reads the committed `spkm.bin` and InitHello seed instead of making new
/// keys, so `v02.txt` and the keys stay as they are.
fn cookie_vectors(vec_dir: &Path, seed_dir: &Path) -> anyhow::Result<()> {
    let ks = KeyedHash::keyed_shake256();
    let ek = EphemeralKem::Kyber512Round3;
    let spkm = std::fs::read(vec_dir.join("spkm.bin"))?;
    let ih = std::fs::read(seed_dir.join("seed-init-hello"))?;
    ensure!(ih.len() == 1092, "seed-init-hello is not an InitHello");
    let mut out = Out(BTreeMap::new());

    let mut kh_out = [0u8; 32];
    let kh_key: [u8; 32] = std::array::from_fn(|i| i as u8);
    ks.keyed_hash(&kh_key, b"secureos rosenpass-core keyed shake256 KAT", &mut kh_out)?;
    out.put("shake.key", &kh_key)?;
    out.put("shake.data", b"secureos rosenpass-core keyed shake256 KAT")?;
    out.put("shake.out", &kh_out)?;
    out.put("cookie.domain.protocol", &hd::protocol(ks.clone(), ek)?.into_value())?;

    let cookie_key = hd::cookie_key(ks.clone(), ek)?.mix(&spkm)?.into_value();
    out.put("cookie.key", &cookie_key)?;

    let secret = [0x11u8; 16];
    // ::ffff:10.0.3.1 port 41001, as `rosenpass_core::cookie::host_info`.
    let mut host = [0u8; 18];
    host[10..16].copy_from_slice(&[0xff, 0xff, 10, 0, 3, 1]);
    host[16..18].copy_from_slice(&41001u16.to_be_bytes());
    let value = hd::cookie_value(ks.clone(), ek)?.mix(&secret)?.mix(&host)?.into_value();
    out.put("cookie.secret", &secret)?;
    out.put("cookie.host", &host)?;
    out.put("cookie.value", &value[..16])?;

    // The field an initiator writes into this InitHello once it holds the
    // value: over every byte before the cookie field.
    let before = &ih[..1092 - 16];
    let field = hd::cookie(ks.clone(), ek)?.mix(&value[..16])?.mix(before)?.into_value();
    out.put("cookie.msg", &ih)?;
    out.put("cookie.field", &field[..16])?;

    // The sealed part of a CookieReply to this InitHello: XAEAD under the
    // cookie key, nonce prepended, the InitHello's mac as associated data.
    let nonce = [0x22u8; 24];
    let mac = &ih[1092 - 32..1092 - 16];
    let mut sealed = [0u8; 24 + 16 + 16];
    XAead.encrypt_with_nonce_in_ctxt(&mut sealed, &cookie_key, &nonce, mac, &value[..16])?;
    out.put("cookie.nonce", &nonce)?;
    out.put("cookie.sidi", &ih[4..8])?;
    out.put("cookie.sealed", &sealed)?;

    let mut text = String::new();
    writeln!(text, "# Rosenpass cookie golden vectors for crates/rosenpass-core (M3b plan C1, VE11).")?;
    writeln!(text, "# upstream: https://github.com/rosenpass/rosenpass rev {UPSTREAM_REV}")?;
    writeln!(text, "# keyed hash: keyed_shake256; ekem: Kyber512Round3 (as upstream's cookie code)")?;
    writeln!(text, "# inputs: spkm.bin and the InitHello seed of the V02 vectors")?;
    writeln!(text, "# regenerate: tools/rp-vectors/README.md, with --cookie")?;
    for (k, v) in &out.0 {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(text, "{k} {hex}")?;
    }
    std::fs::write(vec_dir.join("cookie.txt"), text)?;
    println!("rp-vectors: wrote {} cookie vectors to {}", out.0.len(), vec_dir.display());
    Ok(())
}

/// McEliece vectors for crates/mce460896 (M4 plan C8): liboqs 0.8's round-3
/// mceliece460896, the code the 0.2.3 and master clients run, driven by the
/// SplitMix64 stream. Per key: the keygen seed, SHA3-256 of the public key
/// (524160 bytes), the secret key in liboqs's layout, one encapsulation and
/// decapsulations in four classes (valid, C0 corrupt, C1 corrupt, both).
const MCE_KEYS: u64 = 3;
const MCE_PK: usize = 524_160;
const MCE_SK_OQS: usize = 13_568;
const MCE_CT: usize = 188;
const MCE_C0: usize = 156;

fn sha3_256(b: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Sha3_256::digest(b).into()
}

fn mce_classes(ct: &[u8; MCE_CT]) -> [(&'static str, [u8; MCE_CT]); 4] {
    let flip = |mut c: [u8; MCE_CT], at: usize| {
        c[at] ^= 0x01;
        c
    };
    [
        ("valid", *ct),
        ("c0", flip(*ct, 7)),
        ("c1", flip(*ct, MCE_C0 + 5)),
        ("both", flip(flip(*ct, 7), MCE_C0 + 5)),
    ]
}

fn write_vectors(path: &Path, header: &[&str], out: &Out) -> anyhow::Result<()> {
    let mut text = String::new();
    for h in header {
        writeln!(text, "# {h}")?;
    }
    for (k, v) in &out.0 {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(text, "{k} {hex}")?;
    }
    std::fs::create_dir_all(path.parent().context("vector path has a parent")?)?;
    std::fs::write(path, text)?;
    println!("rp-vectors: wrote {} vectors to {}", out.0.len(), path.display());
    Ok(())
}

fn mce_vectors(repo: &Path) -> anyhow::Result<()> {
    use oqs_sys::kem::{
        OQS_KEM_classic_mceliece_460896_decaps as decaps, OQS_KEM_classic_mceliece_460896_encaps as encaps,
        OQS_KEM_classic_mceliece_460896_keypair as keypair, OQS_STATUS::OQS_SUCCESS,
    };
    let mut out = Out(BTreeMap::new());
    for i in 0..MCE_KEYS {
        let kp_seed = 0x5eed_0000_6d63_0000 + i;
        let (mut pk, mut sk) = (vec![0u8; MCE_PK], vec![0u8; MCE_SK_OQS]);
        with_stream(kp_seed, || assert_eq!(unsafe { keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) }, OQS_SUCCESS));
        let enc_seed = 0x5eed_0000_6563_0000 + i;
        let (mut ct, mut ss) = ([0u8; MCE_CT], [0u8; 32]);
        with_stream(enc_seed, || {
            assert_eq!(unsafe { encaps(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) }, OQS_SUCCESS)
        });
        out.put(&format!("mce.{i}.kp_seed"), &kp_seed.to_le_bytes())?;
        out.put(&format!("mce.{i}.pk_sha3"), &sha3_256(&pk))?;
        out.put(&format!("mce.{i}.sk_oqs"), &sk)?;
        out.put(&format!("mce.{i}.enc_seed"), &enc_seed.to_le_bytes())?;
        out.put(&format!("mce.{i}.ct"), &ct)?;
        out.put(&format!("mce.{i}.ss"), &ss)?;
        for (class, c) in mce_classes(&ct) {
            let mut k = [0u8; 32];
            assert_eq!(unsafe { decaps(k.as_mut_ptr(), c.as_ptr(), sk.as_ptr()) }, OQS_SUCCESS);
            out.put(&format!("mce.{i}.dec.{class}.ct"), &c)?;
            out.put(&format!("mce.{i}.dec.{class}.ss"), &k)?;
        }
    }
    write_vectors(
        &repo.join("crates/mce460896/tests/vectors/liboqs.txt"),
        &[
            "Classic McEliece 460896 round 3 vectors for crates/mce460896 (M4 plan C8).",
            "oracle: liboqs via oqs-sys 0.8.0 (the peers' code), SplitMix64 randombytes",
            "pk_sha3: SHA3-256 of the public key; sk_oqs: liboqs's secret-key layout",
            "dec classes: valid; c0 = byte 7 flipped; c1 = byte 161 flipped; both",
            "regenerate: tools/rp-vectors/README.md, with --mce",
        ],
        &out,
    )
}

/// The cmr bridge (M4 plan C8, slice M0): the same keys and ciphertexts as
/// cmr 2.0.2 makes them, frozen before cmr leaves the tree, so the port is
/// shown to decapsulate cmr-era keys (the dev secrets blob) identically.
fn cmr_vectors(repo: &Path) -> anyhow::Result<()> {
    use classic_mceliece_rust as cmr;
    struct Stream(SplitMix);
    impl rand_core::RngCore for Stream {
        fn next_u32(&mut self) -> u32 {
            u32::from_le_bytes(std::array::from_fn(|_| self.0.byte()))
        }
        fn next_u64(&mut self) -> u64 {
            u64::from_le_bytes(std::array::from_fn(|_| self.0.byte()))
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.iter_mut().for_each(|b| *b = self.0.byte());
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for Stream {}

    let mut out = Out(BTreeMap::new());
    for i in 0..MCE_KEYS {
        let kp_seed = 0x5eed_0000_636d_0000 + i;
        let mut pk_buf = vec![0u8; cmr::CRYPTO_PUBLICKEYBYTES];
        let mut sk_buf = vec![0u8; cmr::CRYPTO_SECRETKEYBYTES];
        let pk_arr: &mut [u8; cmr::CRYPTO_PUBLICKEYBYTES] = pk_buf.as_mut_slice().try_into()?;
        let sk_arr: &mut [u8; cmr::CRYPTO_SECRETKEYBYTES] = sk_buf.as_mut_slice().try_into()?;
        let (pk, sk) = cmr::keypair(pk_arr, sk_arr, &mut Stream(SplitMix::new(kp_seed)));
        let enc_seed = 0x5eed_0000_6365_0000 + i;
        let mut ss_buf = [0u8; cmr::CRYPTO_BYTES];
        let (ct, ss) = cmr::encapsulate(&pk, &mut ss_buf, &mut Stream(SplitMix::new(enc_seed)));
        let ct: [u8; MCE_CT] = *ct.as_array();
        out.put(&format!("cmr.{i}.kp_seed"), &kp_seed.to_le_bytes())?;
        out.put(&format!("cmr.{i}.pk_sha3"), &sha3_256(pk.as_array()))?;
        out.put(&format!("cmr.{i}.sk"), sk.as_array())?;
        out.put(&format!("cmr.{i}.enc_seed"), &enc_seed.to_le_bytes())?;
        out.put(&format!("cmr.{i}.ct"), &ct)?;
        out.put(&format!("cmr.{i}.ss"), ss.as_array())?;
        drop(ss);
        for (class, c) in mce_classes(&ct) {
            let mut k = [0u8; cmr::CRYPTO_BYTES];
            let ss = cmr::decapsulate(&cmr::Ciphertext::from(c), &sk, &mut k);
            out.put(&format!("cmr.{i}.dec.{class}.ct"), &c)?;
            out.put(&format!("cmr.{i}.dec.{class}.ss"), ss.as_array())?;
        }
    }
    write_vectors(
        &repo.join("crates/mce460896/tests/vectors/cmr-2.0.2.txt"),
        &[
            "cmr bridge vectors for crates/mce460896 (M4 plan C8, slice M0): FROZEN.",
            "producer: classic-mceliece-rust 2.0.2 (mceliece460896), SplitMix64 stream,",
            "via tools/rp-vectors --cmr at the commit that adds this file. The mode and",
            "its cmr dependency are deleted in C11; this file is never regenerated.",
            "sk: cmr's layout (the blob's); dec classes as in liboqs.txt",
        ],
        &out,
    )
}

fn main() -> anyhow::Result<()> {
    let repo: PathBuf =
        std::env::args().nth(1).context("usage: rp-vectors <secureos repo root> [--cookie|--mce|--cmr]")?.into();
    match std::env::args().nth(2).as_deref() {
        Some("--mce") => return mce_vectors(&repo),
        Some("--cmr") => return cmr_vectors(&repo),
        _ => {}
    }
    let vec_dir = repo.join("crates/rosenpass-core/tests/vectors");
    let seed_dir = repo.join("crates/rosenpass-wire/src/__fuzz__/tests__parsers_never_panic_and_round_trip/corpus");
    ensure!(vec_dir.is_dir() && seed_dir.is_dir(), "run from a secureos checkout: {repo:?}");
    if std::env::args().nth(2).as_deref() == Some("--cookie") {
        return cookie_vectors(&vec_dir, &seed_dir);
    }

    secret_policy_use_only_malloc_secrets();
    let kh = KeyedHash::incorrect_hmac_blake2b();
    let ek = EphemeralKem::Kyber512Round3;
    let mut out = Out(BTreeMap::new());

    // The keyed-hash primitive itself.
    let kh_key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let kh_data = b"secureos rosenpass-core keyed hash KAT";
    let mut kh_out = [0u8; 32];
    kh.keyed_hash(&kh_key, kh_data, &mut kh_out)?;
    out.put("kh.key", &kh_key)?;
    out.put("kh.data", kh_data)?;
    out.put("kh.out", &kh_out)?;

    // Every hash-domain label of the V02 tree.
    out.put("domain.protocol", &hd::protocol(kh.clone(), ek)?.into_value())?;
    out.put("domain.mac", &hd::mac(kh.clone(), ek)?.into_value())?;
    out.put("domain.peerid", &hd::peerid(kh.clone(), ek)?.into_value())?;
    out.put("domain.biscuit_ad", &hd::biscuit_ad(kh.clone(), ek)?.into_value())?;
    out.put("domain.ckinit", &hd::ckinit(kh.clone(), ek)?.into_value())?;
    out.put("domain.ckextract", &hd::_ckextract(kh.clone(), ek)?.into_value())?;
    out.put("domain.mix", &hd::mix(kh.clone(), ek)?)?;
    out.put("domain.hs_enc", &hd::hs_enc(kh.clone(), ek)?)?;
    out.put("domain.ini_enc", &hd::ini_enc(kh.clone(), ek)?)?;
    out.put("domain.res_enc", &hd::res_enc(kh.clone(), ek)?)?;
    out.put("domain.cke_user", &hd::cke_user(kh.clone(), ek)?.into_value())?;
    out.put("domain.cke_user_rosenpass", &hd::cke_user_rosenpass(kh.clone(), ek)?.into_value())?;
    out.put("domain.osk", &hd::ext_wireguard_psk_osk(kh.clone(), ek)?)?;
    out.put("domain.osk_compressed", &OskDomainSeparator::default().compress_with(kh.clone(), ek)?)?;

    let (a_sk, a_pk) = gen_keypair()?;
    let (b_sk, b_pk) = gen_keypair()?;
    let spkt: Vec<u8> = a_pk.to_vec();
    let spkm: Vec<u8> = b_pk.to_vec();

    out.put("mac_key.spkm", &hd::mac(kh.clone(), ek)?.mix(&spkm)?.into_value())?;
    out.put("pid.spkm", &hd::peerid(kh.clone(), ek)?.mix(&spkm)?.into_value())?;
    out.put("pid.spkt", &hd::peerid(kh.clone(), ek)?.mix(&spkt)?.into_value())?;

    let mut a = CryptoServer::new(a_sk, a_pk.clone());
    let mut b = CryptoServer::new(b_sk, b_pk.clone());
    // No PSK (SC25): upstream mixes 32 zero bytes at IHR7.
    a.add_peer(None, b_pk, ProtocolVersion::V02, OskDomainSeparator::default())?;
    b.add_peer(None, a_pk, ProtocolVersion::V02, OskDomainSeparator::default())?;
    let (mut abuf, mut bbuf) = (MsgBuf::zero(), MsgBuf::zero());

    let raw = std::env::temp_dir().join(format!("rp-vectors-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&raw);
    let guard = initialize_tv_case_from_file(&raw, TestVectorFileFormat::Json, TestMode::Init)?;

    let n = a.initiate_handshake(PeerPtr(0), &mut abuf[..])?;
    let ih = abuf[..n].to_vec();
    let n = b.handle_msg_with_test_vector::<TestVectorActive>(&ih, &mut bbuf[..])?.resp.context("RespHello")?;
    let rh = bbuf[..n].to_vec();
    let n = a.handle_msg(&rh, &mut abuf[..])?.resp.context("InitConf")?;
    let ic = abuf[..n].to_vec();

    // ICR1-ICR4 replayed with upstream's own HandshakeState before `b`
    // consumes the InitConf (load_biscuit only reads the server).
    let (sidi, sidr) = (&ic[4..8], &ic[8..12]);
    let (biscuit_ct, auth) = (&ic[12..128], &ic[128..144]);
    let (_, biscuit_no, mut hs) = HandshakeState::load_biscuit(
        &b,
        biscuit_ct,
        SessionId::from_slice(sidi),
        SessionId::from_slice(sidr),
        kh.clone(),
        ek,
    )?;
    out.put("biscuit.no", &biscuit_no[..])?;
    out.put("ck.icr1", &ck_of(&hs))?;
    hs.encrypt_and_mix(&mut [0u8; 16], &[])?;
    out.put("ck.icr2", &ck_of(&hs))?;
    hs.mix(sidi)?.mix(sidr)?;
    out.put("ck.icr3", &ck_of(&hs))?;
    hs.decrypt_and_mix(&mut [0u8; 0], auth)?;
    out.put("ck.icr4", &ck_of(&hs))?;

    // Upstream casts EmptyData over its tx buffer and never writes the
    // cookie field, so it would carry stale bytes of the previous message.
    bbuf = MsgBuf::zero();
    let n = b.handle_msg_with_test_vector::<TestVectorActive>(&ic, &mut bbuf[..])?.resp.context("EmptyData")?;
    let ed = bbuf[..n].to_vec();
    finalize_tv_case()?;
    drop(guard);
    ensure!(a.handle_msg(&ed, &mut abuf[..])?.resp.is_none(), "initiator answered EmptyData");

    recorded(&raw, &mut out)?;
    std::fs::remove_file(&raw)?;

    let osk_a = a.osk(PeerPtr(0))?;
    let osk_b = b.osk(PeerPtr(0))?;
    ensure!(osk_a.secret() == osk_b.secret(), "OSK mismatch between upstream peers");
    let session = b.peers[0].session.as_ref().context("responder session")?;
    ensure!(session.ck.clone().danger_into_secret().secret()[..] == out.0["ck.icr4"][..], "ICR4 ck");
    out.put("osk", osk_b.secret())?;

    // IHR5's shared key, as the pqkey PD will return it.
    let mut ihr5_shk = [0u8; 32];
    let sctr: &[u8; 188] = ih[808..996].try_into()?;
    StaticKem.decaps(&mut ihr5_shk, b.sskm.secret(), sctr)?;
    out.put("ihr5.shk", &ihr5_shk)?;
    out.put("biscuit.ad", &hd::biscuit_ad(kh.clone(), ek)?.mix(&spkm)?.mix(sidi)?.mix(sidr)?.into_value())?;

    out.put("msg.init_hello", &ih)?;
    out.put("msg.resp_hello", &rh)?;
    out.put("msg.init_conf", &ic)?;
    out.put("msg.empty_data", &ed)?;

    // Deterministic KEM KATs (R2-T-N12): liboqs with a SplitMix64 stream.
    let epki = &ih[8..808];
    let mut kyber_r = [0u8; 32];
    let mut s = SplitMix::new(KYBER_KAT_SEED);
    kyber_r.iter_mut().for_each(|b| *b = s.byte());
    let (mut kct, mut kss) = ([0u8; 768], [0u8; 32]);
    with_stream(KYBER_KAT_SEED, || {
        let st = unsafe { oqs_sys::kem::OQS_KEM_kyber_512_encaps(kct.as_mut_ptr(), kss.as_mut_ptr(), epki.as_ptr()) };
        assert_eq!(st, oqs_sys::kem::OQS_STATUS::OQS_SUCCESS);
    });
    out.put("kat.kyber512.r", &kyber_r)?;
    out.put("kat.kyber512.ct", &kct)?;
    out.put("kat.kyber512.ss", &kss)?;

    let (mut mct, mut mss) = ([0u8; 188], [0u8; 32]);
    with_stream(MCELIECE_KAT_SEED, || {
        let st = unsafe {
            oqs_sys::kem::OQS_KEM_classic_mceliece_460896_encaps(mct.as_mut_ptr(), mss.as_mut_ptr(), spkt.as_ptr())
        };
        assert_eq!(st, oqs_sys::kem::OQS_STATUS::OQS_SUCCESS);
    });
    out.put("kat.mceliece460896.seed", &MCELIECE_KAT_SEED.to_le_bytes())?;
    out.put("kat.mceliece460896.ct", &mct)?;
    out.put("kat.mceliece460896.ss", &mss)?;

    let mut text = String::new();
    writeln!(text, "# Rosenpass V02 golden vectors for crates/rosenpass-core (M3 plan C1, T1).")?;
    writeln!(text, "# upstream: https://github.com/rosenpass/rosenpass rev {UPSTREAM_REV}")?;
    writeln!(
        text,
        "# features: expose_internal_modules; ProtocolVersion::V02; psk: none; OSK domain: default (wireguard psk)"
    )?;
    writeln!(text, "# roles: upstream initiator = client (spkt), upstream responder = gateway (spkm)")?;
    writeln!(text, "# kem KATs: liboqs (oqs-sys 0.8.0) with a SplitMix64 randombytes stream")?;
    writeln!(text, "# regenerate: see tools/rp-vectors/README.md; keys are in spkm.bin / spkt.bin")?;
    for (k, v) in &out.0 {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(text, "{k} {hex}")?;
    }
    std::fs::write(vec_dir.join("v02.txt"), text)?;
    std::fs::write(vec_dir.join("spkm.bin"), &spkm)?;
    std::fs::write(vec_dir.join("spkt.bin"), &spkt)?;
    std::fs::write(seed_dir.join("seed-init-hello"), &ih)?;
    std::fs::write(seed_dir.join("seed-resp-hello"), &rh)?;
    std::fs::write(seed_dir.join("seed-init-conf"), &ic)?;
    std::fs::write(seed_dir.join("seed-empty-data"), &ed)?;
    println!("rp-vectors: wrote {} vectors to {}", out.0.len(), vec_dir.display());
    Ok(())
}
