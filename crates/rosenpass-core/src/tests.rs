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
    let cases: [(&str, &[u8; 32]); 13] = [
        ("domain.protocol", &d.protocol),
        ("domain.mac", &d.mac),
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

struct FakeHedgeHw {
    rndr: Option<u64>,
    counter: u64,
    /// RNDR reads that succeed before it fails (None: never fails).
    good_reads: Option<usize>,
}

impl FakeHedgeHw {
    fn new(rndr: Option<u64>) -> Self {
        Self { rndr, counter: 0, good_reads: None }
    }
}

impl crate::HedgeHw for FakeHedgeHw {
    fn rndr(&mut self) -> Option<u64> {
        match &mut self.good_reads {
            Some(0) => None,
            Some(n) => {
                *n -= 1;
                self.rndr
            }
            None => self.rndr,
        }
    }

    fn counter(&mut self) -> u64 {
        self.counter
    }
}

fn hedged_block(seed: u8, hw: FakeHedgeHw) -> [u8; 32] {
    let mut out = [0u8; 32];
    crate::Hedged::new(Secret::from_bytes([seed; 32]), hw).fill(&mut out).unwrap();
    out
}

#[test]
fn hedged_fails_the_draw_without_rndr() {
    let mut h = crate::Hedged::new(Secret::from_bytes([1; 32]), FakeHedgeHw::new(None));
    assert_eq!(h.fill(&mut [0u8; 40]), Err(RngError));
}

#[test]
fn hedged_fails_the_whole_draw_when_rndr_fails_on_a_later_block() {
    let hw = FakeHedgeHw { good_reads: Some(1), ..FakeHedgeHw::new(Some(7)) };
    let mut h = crate::Hedged::new(Secret::from_bytes([1; 32]), hw);
    assert_eq!(h.fill(&mut [0u8; 64]), Err(RngError));
}

#[test]
fn hedged_blocks_differ_with_identical_hardware_inputs() {
    // Same RNDR and counter every time: only the draw counter separates
    // the blocks, so they must still differ (and be nonzero).
    let mut h = crate::Hedged::new(Secret::from_bytes([1; 32]), FakeHedgeHw::new(Some(7)));
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    h.fill(&mut a).unwrap();
    h.fill(&mut b).unwrap();
    assert_ne!(a[..32], a[32..], "two blocks of one draw");
    assert_ne!(a, b, "two draws");
    assert_ne!(a, [0u8; 64]);
}

#[test]
fn hedged_output_depends_on_the_boot_seed() {
    assert_ne!(hedged_block(1, FakeHedgeHw::new(Some(7))), hedged_block(2, FakeHedgeHw::new(Some(7))));
}

#[test]
fn hedged_output_depends_on_rndr() {
    // A known seed must not make the output predictable while RNDR is sound.
    assert_ne!(hedged_block(1, FakeHedgeHw::new(Some(7))), hedged_block(1, FakeHedgeHw::new(Some(8))));
}

#[test]
fn hedged_output_depends_on_the_counter() {
    let late = FakeHedgeHw { counter: 1, ..FakeHedgeHw::new(Some(7)) };
    assert_ne!(hedged_block(1, FakeHedgeHw::new(Some(7))), hedged_block(1, late));
}

// ---- the cookie tree (M3b plan C1, VE11) ----

const COOKIE: &str = include_str!("../tests/vectors/cookie.txt");

fn cv(name: &str) -> Vec<u8> {
    for line in COOKIE.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (k, hex) = line.split_once(' ').unwrap();
        if k == name {
            return (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        }
    }
    panic!("no cookie vector {name}")
}

fn cookie_secret() -> Secret<16> {
    Secret::from_bytes(cv("cookie.secret").try_into().unwrap())
}

fn cookie_host() -> [u8; 18] {
    cv("cookie.host").try_into().unwrap()
}

#[test]
fn the_cookie_tree_is_rooted_at_the_shake256_protocol_string() {
    // The root alone pins the keyed SHAKE256 and the protocol string.
    let root = cookie::cookie_key_root_for_test();
    assert_eq!(root.to_vec(), cv("cookie.domain.protocol"));
    assert_ne!(root.to_vec(), v("domain.protocol"), "the cookie tree must not be the V02 tree");
}

#[test]
fn cookie_key_value_and_field_match_upstream() {
    assert_eq!(cookie::cookie_key(SPKM).to_vec(), cv("cookie.key"));
    assert_eq!(cookie::host_info([10, 0, 3, 1], 41001).to_vec(), cv("cookie.host"));
    let value = cookie::cookie_value(&cookie_secret(), &cookie_host());
    assert_eq!(value.expose().to_vec(), cv("cookie.value"));
    let msg = cv("cookie.msg");
    let field = cookie::cookie_field(&value, &msg[..msg.len() - 16]);
    assert_eq!(field.to_vec(), cv("cookie.field"));
}

#[test]
fn a_cookie_reply_seals_like_upstream_and_pads_to_the_init_hello() {
    let key: [u8; 32] = cv("cookie.key").try_into().unwrap();
    let msg = cv("cookie.msg");
    let mac: [u8; 16] = msg[msg.len() - 32..msg.len() - 16].try_into().unwrap();
    let sidi: [u8; 4] = cv("cookie.sidi").try_into().unwrap();
    let nonce: [u8; 24] = cv("cookie.nonce").try_into().unwrap();
    let value = cookie::cookie_value(&cookie_secret(), &cookie_host());
    let mut out = [0xaa; cookie::COOKIE_REPLY_LEN];
    cookie::seal_cookie_reply(&key, sidi, &nonce, &value, &mac, &mut out).unwrap();
    assert_eq!(out.len(), INIT_HELLO_LEN);
    assert_eq!(out[0], rosenpass_wire::MSG_COOKIE_REPLY);
    assert_eq!(&out[1..4], &[0, 0, 0]);
    assert_eq!(&out[4..8], &sidi);
    assert_eq!(out[8..64].to_vec(), cv("cookie.sealed"));
    assert!(out[64..].iter().all(|b| *b == 0), "padding is zeroed");
}

fn with_cookie(secret: &Secret<16>, host: &[u8; 18]) -> Vec<u8> {
    let mut msg = cv("cookie.msg");
    let cut = msg.len() - 16;
    let field = cookie::cookie_field(&cookie::cookie_value(secret, host), &msg[..cut]);
    msg[cut..].copy_from_slice(&field);
    msg
}

#[test]
fn a_cookie_is_valid_under_the_current_or_the_previous_secret_only() {
    let host = cookie_host();
    let (current, previous, older) = (cookie_secret(), Secret::from_bytes([0x33; 16]), Secret::from_bytes([0x44; 16]));
    let both = [Some(&current), Some(&previous)];
    assert!(cookie::cookie_valid(both, &host, &with_cookie(&current, &host)));
    assert!(cookie::cookie_valid(both, &host, &with_cookie(&previous, &host)));
    // A secret two rotations old is gone.
    assert!(!cookie::cookie_valid(both, &host, &with_cookie(&older, &host)));
    // The previous secret alone, once the current one is missing.
    assert!(cookie::cookie_valid([None, Some(&previous)], &host, &with_cookie(&previous, &host)));
    assert!(!cookie::cookie_valid([None, None], &host, &with_cookie(&current, &host)));
}

#[test]
fn a_cookie_is_bound_to_its_host_and_to_every_bit() {
    let host = cookie_host();
    let current = cookie_secret();
    let both = [Some(&current), None];
    let good = with_cookie(&current, &host);
    // Another port of the same address.
    let other = cookie::host_info([10, 0, 3, 1], 41002);
    assert!(!cookie::cookie_valid(both, &other, &good));
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert!(!cookie::cookie_valid(both, &host, &flipped));
    let mut body = good.clone();
    body[100] ^= 1;
    assert!(!cookie::cookie_valid(both, &host, &body), "the field covers the message");
    assert!(!cookie::cookie_valid(both, &host, &good[..15]));
}
