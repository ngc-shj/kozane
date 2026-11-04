//! The initiator against upstream's (M9 plan C7): `v02-initiator.txt` is one
//! exchange with upstream rosenpass `9e72f1eb`'s initiator as the subject
//! (tools/rp-vectors `--initiator`). Replaying its recorded draws through
//! the seams, in upstream's order (D-3), with real Kyber and McEliece on
//! both sides, the kozane initiator emits the same InitHello and InitConf
//! byte for byte and derives the same OSK.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

extern crate std;

use std::boxed::Box;
use std::collections::{BTreeMap, VecDeque};
use std::string::String;
use std::vec::Vec;

use rosenpass_wire::SCT_LEN;

use crate::initiator_state::{JITTER_LEN, Phase};
use crate::tests::QueueRng;
use crate::*;

static SPKI: &[u8; SPK_LEN] = include_bytes!("../tests/vectors/spkt-initiator.bin");
static SPKR: &[u8; SPK_LEN] = include_bytes!("../tests/vectors/spkm-initiator.bin");
static SKT_OQS: &[u8; 13_568] = include_bytes!("../tests/vectors/skt-initiator.bin");
const V02_INITIATOR: &str = include_str!("../tests/vectors/v02-initiator.txt");

const KEYS: InitiatorKeys<'static> = InitiatorKeys { spki: SPKI, spkr: SPKR };
const MISMATCH: &str = "initiator: vector mismatch";

fn vectors() -> BTreeMap<String, Vec<u8>> {
    let mut m = BTreeMap::new();
    for line in V02_INITIATOR.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (k, hex) = line.split_once(' ').unwrap();
        let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        assert!(m.insert(String::from(k), bytes).is_none(), "duplicate {k}");
    }
    m
}

/// The initiator's McEliece secret key in `mce460896`'s layout, from
/// liboqs's `c ‖ g ‖ alpha ‖ s` minus delta (as the mce460896 vectors
/// convert it); decapsulation never reads `delta ‖ c`.
struct OwnDecaps(Box<[u8; mce460896::SK_LEN]>);

impl OwnDecaps {
    fn new() -> Self {
        let mut sk = Box::new([0u8; mce460896::SK_LEN]);
        sk[40..40 + 13_568 - 576].copy_from_slice(&SKT_OQS[576..]);
        sk[mce460896::SK_LEN - 576..].copy_from_slice(&SKT_OQS[..576]);
        Self(sk)
    }
}

impl Decaps for OwnDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut ss = [0u8; SHK_LEN];
        mce460896::decaps(&self.0, sct, &mut ss);
        Ok(Secret::from_bytes(ss))
    }
}

/// Upstream's draws in its order, each as long as upstream's call: the
/// cookie value, sidi, Kyber's d ‖ z, then each McEliece attempt; then the
/// kozane-only jitter draw (D-3), which reaches no message byte.
fn start_draws(v: &BTreeMap<String, Vec<u8>>) -> VecDeque<Vec<u8>> {
    let mut q = VecDeque::from([v["draw.cookie"].clone(), v["draw.sidi"].clone(), v["draw.kyber"].clone()]);
    let mut mce = &v["draw.mceliece"][..];
    for len in v["draw.mceliece_calls"].chunks(4) {
        let (call, rest) = mce.split_at(u32::from_le_bytes(len.try_into().unwrap()) as usize);
        q.push_back(call.to_vec());
        mce = rest;
    }
    assert!(mce.is_empty(), "draw.mceliece longer than its calls");
    q.push_back(std::vec![0x5a; JITTER_LEN]);
    q
}

/// An initiator that sent upstream's InitHello, and, with `confirmed`,
/// also its InitConf for upstream's RespHello.
fn prefix(v: &BTreeMap<String, Vec<u8>>, confirmed: bool) -> Initiator {
    let mut ini = Initiator::new(&KEYS).unwrap();
    let (mut d, mut k, mut m) = (OwnDecaps::new(), Kyber512, McEliece460896);
    let mut rng = QueueRng(start_draws(v));
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    let ih = ini.start(&KEYS, 0, seams).unwrap();
    assert!(rng.0.is_empty(), "start left {} recorded draws unused", rng.0.len());
    assert!(ih[..] == v["msg.init_hello"][..], "{MISMATCH}: InitHello");
    if confirmed {
        let (ic, osk) = resp_hello(&mut ini, &v["msg.resp_hello"]).unwrap();
        assert!(ic[..] == v["msg.init_conf"][..], "{MISMATCH}: InitConf");
        assert!(osk.expose()[..] == v["osk"][..], "{MISMATCH}: OSK");
    }
    ini
}

fn resp_hello(ini: &mut Initiator, msg: &[u8]) -> Result<([u8; rosenpass_wire::INIT_CONF_LEN], Osk), Error> {
    let (mut d, mut k, mut m) = (OwnDecaps::new(), Kyber512, McEliece460896);
    let mut rng = QueueRng(VecDeque::from([std::vec![0xa5; JITTER_LEN]]));
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    ini.handle_resp_hello(&KEYS, msg, 1, seams)
}

#[test]
fn the_initiator_replays_upstreams_exchange_byte_for_byte() {
    let v = vectors();
    let mut ini = prefix(&v, true);
    assert_eq!(ini.handle_empty_data(&v["msg.empty_data"], 2), Ok(()));
    assert_eq!(ini.state().phase(), Phase::Established);
}

/// The fuzz input's first byte picks the prefix (bit 0: upstream's
/// RespHello already handled) and the handler (the rest, mod 3); the other
/// bytes are the message. Whatever it is: no panic, a refusal leaves the
/// state core as it was (I7.3), and an accepted RespHello or EmptyData is
/// upstream's own up to the unauthenticated cookie field, the RespHello
/// releasing upstream's OSK (I7.1).
fn fuzz_one(v: &BTreeMap<String, Vec<u8>>, data: &[u8]) {
    let Some((&sel, msg)) = data.split_first() else { return };
    let mut ini = prefix(v, sel & 1 == 1);
    let before = *ini.state();
    let unsealed = |name: &str| msg.len() >= 16 && msg[..msg.len() - 16] == v[name][..v[name].len() - 16];
    let ok = match (sel >> 1) % 3 {
        0 => resp_hello(&mut ini, msg).map(|(_, osk)| {
            assert!(unsealed("msg.resp_hello"), "an unauthenticated RespHello was accepted");
            assert!(osk.expose()[..] == v["osk"][..], "{MISMATCH}: OSK");
        }),
        1 => ini.handle_empty_data(msg, 2).map(|()| assert!(unsealed("msg.empty_data"), "a forged EmptyData was accepted")),
        _ => ini.handle_cookie_reply(msg, 2),
    }
    .is_ok();
    if !ok {
        assert_eq!(*ini.state(), before, "initiator: state advanced on error");
    }
}

#[test]
fn fuzz_initiator_input_after_upstreams_prefix() {
    let v = vectors();
    bolero::check!().for_each(|data: &[u8]| fuzz_one(&v, data));
}
