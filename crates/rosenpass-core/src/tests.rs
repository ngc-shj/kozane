//! Golden vectors from upstream rosenpass 9e72f1eb (tools/rp-vectors, M3
//! plan C1, T1): every hash domain, the mac keys and peer ids, the ck chain
//! of a whole responder run, its RespHello, EmptyData and OSK, replaying
//! upstream's encapsulations through the seams; plus the Kyber KAT.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

extern crate std;

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::string::String;
use std::vec::Vec;

use rosenpass_wire::{ECT_LEN, EPK_LEN, INIT_HELLO_LEN, RESP_HELLO_LEN, SCT_LEN};

use crate::crypto::{self, PROTOCOL_V02};
use crate::*;

pub(crate) static SPKM: &[u8; SPK_LEN] = include_bytes!("../tests/vectors/spkm.bin");
pub(crate) static SPKT: &[u8; SPK_LEN] = include_bytes!("../tests/vectors/spkt.bin");
const V02: &str = include_str!("../tests/vectors/v02.txt");

std::thread_local! {
    static TRACE: RefCell<Vec<(&'static str, Vec<u8>)>> = const { RefCell::new(Vec::new()) };
}

/// Called by the responder's checkpoints in test builds.
pub(crate) fn trace(label: &'static str, v: &[u8]) {
    TRACE.with(|t| t.borrow_mut().push((label, v.to_vec())));
}

pub(crate) fn take_trace() -> Vec<(&'static str, Vec<u8>)> {
    TRACE.with(|t| core::mem::take(&mut *t.borrow_mut()))
}

pub(crate) fn vectors() -> BTreeMap<String, Vec<u8>> {
    let mut m = BTreeMap::new();
    for line in V02.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (k, hex) = line.split_once(' ').unwrap();
        let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        assert!(m.insert(String::from(k), bytes).is_none(), "duplicate {k}");
    }
    m
}

pub(crate) fn v(name: &str) -> Vec<u8> {
    vectors().remove(name).unwrap_or_else(|| panic!("no vector {name}"))
}

pub(crate) fn arr<const N: usize>(name: &str) -> [u8; N] {
    v(name).try_into().unwrap_or_else(|_| panic!("vector {name} is not {N} bytes"))
}

/// Hands out queued byte strings in order; each draw must match the next
/// entry's length, so a reordered draw fails loudly.
pub(crate) struct QueueRng(pub VecDeque<Vec<u8>>);

impl Rng for QueueRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        let next = self.0.pop_front().ok_or(RngError)?;
        assert_eq!(next.len(), out.len(), "draw of {} bytes, queued {}", out.len(), next.len());
        out.copy_from_slice(&next);
        Ok(())
    }
}

/// Deterministic non-repeating bytes; never fails.
pub(crate) struct CountRng(pub u64);

impl Rng for CountRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for b in out.iter_mut() {
            self.0 += 1;
            *b = (self.0 ^ (self.0 >> 8) ^ (self.0 >> 16)) as u8;
        }
        Ok(())
    }
}

pub(crate) struct FailRng;

impl Rng for FailRng {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), RngError> {
        Err(RngError)
    }
}

/// Upstream's IHR5 result for the captured InitHello, as `pqkey` returns it.
pub(crate) struct ReplayDecaps {
    pub ct: [u8; SCT_LEN],
    pub shk: [u8; SHK_LEN],
    pub calls: usize,
}

impl Decaps for ReplayDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        self.calls += 1;
        assert_eq!(sct, &self.ct, "decapsulated an unexpected ciphertext");
        Ok(Secret::from_bytes(self.shk))
    }
}

/// Replays one upstream encapsulation to an expected public key.
pub(crate) struct ReplayEncaps<const PK: usize, const CT: usize> {
    pub pk: &'static [u8],
    pub ct: [u8; CT],
    pub shk: [u8; SHK_LEN],
}

impl<const PK: usize, const CT: usize> Encaps<PK, CT> for ReplayEncaps<PK, CT> {
    fn encaps<R: Rng>(&mut self, pk: &[u8; PK], _: &mut R) -> Result<([u8; CT], Secret<SHK_LEN>), EncapsError> {
        assert!(pk[..] == self.pk[..], "encapsulated to an unexpected key");
        Ok((self.ct, Secret::from_bytes(self.shk)))
    }
}

pub(crate) fn init_hello() -> &'static [u8] {
    static IH: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    IH.get_or_init(|| v("msg.init_hello"))
}

pub(crate) fn epki() -> &'static [u8] {
    &init_hello()[8..8 + EPK_LEN]
}

pub(crate) fn replay_decaps() -> ReplayDecaps {
    ReplayDecaps { ct: init_hello()[808..808 + SCT_LEN].try_into().unwrap(), shk: arr("ihr5.shk"), calls: 0 }
}

pub(crate) fn replay_kyber() -> ReplayEncaps<EPK_LEN, ECT_LEN> {
    ReplayEncaps { pk: epki(), ct: arr("rhr4.ct"), shk: arr("rhr4.shk") }
}

pub(crate) fn replay_mceliece() -> ReplayEncaps<SPK_LEN, SCT_LEN> {
    ReplayEncaps { pk: SPKT, ct: arr("rhr5.ct"), shk: arr("rhr5.shk") }
}

/// A responder for the captured peer whose first biscuit key is upstream's.
pub(crate) fn upstream_responder() -> Responder<'static, 1> {
    let mut r = Responder::new(SPKM, [SPKT], &mut CountRng(0)).unwrap();
    r.tick(0, &mut QueueRng(VecDeque::from([v("biscuit.key")]))).unwrap();
    r
}

fn upstream_resp_hello(r: &mut Responder<'static, 1>) -> [u8; RESP_HELLO_LEN] {
    let mut rng = QueueRng(VecDeque::from([v("rhr1.sidr"), v("biscuit.nonce_drawn")]));
    let (mut d, mut k, mut m) = (replay_decaps(), replay_kyber(), replay_mceliece());
    let mut seams = Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    let mut out = [0u8; RESP_HELLO_LEN];
    assert_eq!(r.handle_init_hello(init_hello(), 1, &mut seams, &mut out), Ok(0));
    assert!(rng.0.is_empty(), "unused draws");
    out
}

fn assert_trace(labels: &[&str]) {
    let got = take_trace();
    let names: Vec<_> = got.iter().map(|(l, _)| *l).collect();
    assert_eq!(names, labels);
    for (label, value) in got {
        assert_eq!(value, v(label), "{label}");
    }
}

#[test]
fn keyed_hash_is_upstreams_incorrect_hmac() {
    let out = crypto::kh_public(&arr("kh.key"), &v("kh.data")).unwrap();
    assert_eq!(out.to_vec(), v("kh.out"));
}

#[test]
fn root_string_keeps_the_blake2s_quirk() {
    assert_eq!(PROTOCOL_V02, b"Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s");
    assert_eq!(Domains::v02().unwrap().protocol.to_vec(), v("domain.protocol"));
}

#[test]
fn every_hash_domain_matches_upstream() {
    let d = Domains::v02().unwrap();
    let cases: [(&str, &[u8; 32]); 16] = [
        ("domain.protocol", &d.protocol),
        ("domain.mac", &d.mac),
        ("domain.cookie", &d.cookie),
        ("domain.cookie_value", &d.cookie_value),
        ("domain.cookie_key", &d.cookie_key),
        ("domain.peerid", &d.peerid),
        ("domain.biscuit_ad", &d.biscuit_ad),
        ("domain.ckinit", &d.ckinit),
        ("domain.ckextract", &d.ckextract),
        ("domain.mix", &d.mix),
        ("domain.hs_enc", &d.hs_enc),
        ("domain.ini_enc", &d.ini_enc),
        ("domain.res_enc", &d.res_enc),
        ("domain.cke_user", &d.cke_user),
        ("domain.cke_user_rosenpass", &d.cke_user_rosenpass),
        ("domain.osk", &d.osk),
    ];
    for (name, value) in cases {
        assert_eq!(value.to_vec(), v(name), "{name}");
    }
    // The default OSK domain separator compresses to the same label.
    assert_eq!(v("domain.osk_compressed"), v("domain.osk"));
}

#[test]
fn mac_key_and_peer_ids_match_upstream() {
    let d = Domains::v02().unwrap();
    assert_eq!(mac_key(&d, SPKM).unwrap().to_vec(), v("mac_key.spkm"));
    assert_eq!(peer_id(&d, SPKM).unwrap().to_vec(), v("pid.spkm"));
    assert_eq!(peer_id(&d, SPKT).unwrap().to_vec(), v("pid.spkt"));
    let r = upstream_responder();
    assert_eq!(r.own_mac_key().to_vec(), v("mac_key.spkm"));
    assert_eq!(r.peer_id(0).unwrap().to_vec(), v("pid.spkt"));
    assert_eq!(r.peer_id(1), None);
}

#[test]
fn upstream_envelope_macs_verify_under_our_keys() {
    let d = Domains::v02().unwrap();
    let (to_us, to_peer) = (mac_key(&d, SPKM).unwrap(), mac_key(&d, SPKT).unwrap());
    for (msg, key) in [
        (v("msg.init_hello"), to_us),
        (v("msg.init_conf"), to_us),
        (v("msg.resp_hello"), to_peer),
        (v("msg.empty_data"), to_peer),
    ] {
        let off = msg.len() - 32;
        assert_eq!(envelope_mac(&key, &msg).unwrap()[..], msg[off..off + 16]);
    }
}

#[test]
fn resp_hello_and_its_ck_chain_match_upstream_byte_for_byte() {
    let mut r = upstream_responder();
    take_trace();
    let rh = upstream_resp_hello(&mut r);
    assert_trace(&[
        "ck.ihr4",
        "ck.ihr5",
        "ck.ihr6",
        "ck.ihr7",
        "ck.ihr8",
        "ck.rhr3",
        "ck.rhr4",
        "ck.rhr5",
        "biscuit.pt",
        "biscuit.ad",
        "ck.rhr6",
        "ck.rhr7",
    ]);
    assert_eq!(rh.to_vec(), v("msg.resp_hello"));
    assert_eq!(rh[984..1100].to_vec(), v("biscuit.ct"));
}

#[test]
fn init_conf_yields_upstreams_osk_and_empty_data() {
    let mut r = upstream_responder();
    upstream_resp_hello(&mut r);
    take_trace();
    let Ok(Conf::Fresh(p)) = r.handle_init_conf(&v("msg.init_conf"), 2) else {
        panic!("InitConf refused");
    };
    assert_trace(&["ck.icr1", "ck.icr2", "ck.icr3", "ck.icr4"]);
    let install = p.psk_install();
    assert_eq!(install.peer, 0);
    assert_eq!(install.osk.expose().to_vec(), v("osk"));
    let ed = r.commit_conf(p, 3).unwrap();
    assert_eq!(ed.to_vec(), v("msg.empty_data"));
}

#[test]
fn biscuit_counter_starts_at_upstreams_one() {
    assert_eq!(v("biscuit.no"), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(v("biscuit.pt")[32..44], v("biscuit.no")[..]);
}

#[test]
fn kyber512_encapsulation_matches_the_liboqs_kat() {
    let pk: &[u8; EPK_LEN] = epki().try_into().unwrap();
    let mut rng = QueueRng(VecDeque::from([v("kat.kyber512.r")]));
    let (ct, ss) = Kyber512.encaps(pk, &mut rng).unwrap();
    assert_eq!(ct.to_vec(), v("kat.kyber512.ct"));
    assert_eq!(ss.expose().to_vec(), v("kat.kyber512.ss"));
}

#[test]
fn kyber512_encapsulation_fails_closed_without_randomness() {
    let pk: &[u8; EPK_LEN] = epki().try_into().unwrap();
    assert!(matches!(Kyber512.encaps(pk, &mut FailRng), Err(EncapsError::Rng)));
}

#[test]
fn captured_init_hello_is_full_length() {
    assert_eq!(init_hello().len(), INIT_HELLO_LEN);
}

/// tools/rp-vectors' SplitMix64 byte stream (liboqs' `randombytes` in the KAT).
struct SplitMix {
    state: u64,
    buf: [u8; 8],
    used: usize,
}

impl Rng for SplitMix {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for b in out.iter_mut() {
            if self.used == 8 {
                self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                self.buf = (z ^ (z >> 31)).to_le_bytes();
                self.used = 0;
            }
            *b = self.buf[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

#[test]
fn mceliece460896_encapsulation_matches_the_liboqs_kat() {
    let seed = u64::from_le_bytes(arr("kat.mceliece460896.seed"));
    let mut rng = SplitMix { state: seed, buf: [0; 8], used: 8 };
    let (ct, ss) = McEliece460896.encaps(SPKT, &mut rng).unwrap();
    assert_eq!(ct.to_vec(), v("kat.mceliece460896.ct"));
    assert_eq!(ss.expose().to_vec(), v("kat.mceliece460896.ss"));
}

#[test]
fn mceliece460896_encapsulation_fails_closed_without_randomness() {
    assert!(matches!(McEliece460896.encaps(SPKT, &mut FailRng), Err(EncapsError::Rng)));
}
