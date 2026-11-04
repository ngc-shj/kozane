//! Initiator behaviour (M9 plan C7 unit tests): a whole exchange with the
//! responder, a deny/allow pair per refusal, each asserting the error and
//! the unchanged state core (I7.3), retransmission timing and the cookie.
//!
//! Kyber is real. McEliece is a stand-in, as the vectors hold no secret key
//! for either party; the McEliece encapsulation itself is pinned by the KAT.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

extern crate std;

use std::vec::Vec;

use rosenpass_wire::{EMPTY_DATA_LEN, INIT_CONF_LEN, INIT_HELLO_LEN, RESP_HELLO_LEN, SCT_LEN};

use crate::crypto;
use crate::initiator_state::*;
use crate::tests::{CountRng, FailRng, SPKM, SPKT, cookie_host, cookie_secret, cv};
use crate::*;

const S: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;
/// I7.3's failure line: a refusal moved the state core.
const ADVANCED: &str = "initiator: state advanced on error";

/// The shared key for a ciphertext to `pk`: KH over its randomness, keyed
/// by the key's head, so only a decapsulation for the same key recovers it
/// and any other yields an unrelated key (McEliece's implicit rejection).
fn fake_shk(pk: &[u8; SPK_LEN], ct: &[u8; SCT_LEN]) -> Secret<SHK_LEN> {
    Secret::from_bytes(crypto::kh_public(pk[..32].try_into().unwrap(), &ct[..32]).unwrap())
}

struct FakeMce;

impl Encaps<SPK_LEN, SCT_LEN> for FakeMce {
    fn encaps<R: Rng>(&mut self, pk: &[u8; SPK_LEN], rng: &mut R) -> Result<([u8; SCT_LEN], Secret<SHK_LEN>), EncapsError> {
        let mut ct = [0u8; SCT_LEN];
        rng.fill(&mut ct[..32]).map_err(|_| EncapsError::Rng)?;
        Ok((ct, fake_shk(pk, &ct)))
    }
}

struct FakeDecaps(&'static [u8; SPK_LEN]);

impl Decaps for FakeDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        Ok(fake_shk(self.0, sct))
    }
}

/// The captured peer: spki is SPKT, the responder SPKM.
const KEYS: InitiatorKeys<'static> = InitiatorKeys { spki: SPKT, spkr: SPKM };

fn initiator() -> Initiator {
    Initiator::new(&KEYS).unwrap()
}

fn start_keys<R: Rng>(
    ini: &mut Initiator,
    keys: &InitiatorKeys<'_>,
    now: u64,
    rng: &mut R,
) -> Result<[u8; INIT_HELLO_LEN], Error> {
    let (mut d, mut k, mut m) = (FakeDecaps(SPKT), Kyber512, FakeMce);
    ini.start(keys, now, &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng })
}

fn start_with<R: Rng>(ini: &mut Initiator, now: u64, rng: &mut R) -> Result<[u8; INIT_HELLO_LEN], Error> {
    start_keys(ini, &KEYS, now, rng)
}

fn start(ini: &mut Initiator, now: u64, seed: u64) -> [u8; INIT_HELLO_LEN] {
    start_with(ini, now, &mut CountRng(seed)).unwrap()
}

fn resp_hello_with<R: Rng>(
    ini: &mut Initiator,
    rh: &[u8],
    now: u64,
    rng: &mut R,
) -> Result<([u8; INIT_CONF_LEN], Osk), Error> {
    let (mut d, mut k, mut m) = (FakeDecaps(SPKT), Kyber512, FakeMce);
    ini.handle_resp_hello(&KEYS, rh, now, &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng })
}

fn resp_hello(ini: &mut Initiator, rh: &[u8], now: u64) -> Result<([u8; INIT_CONF_LEN], Osk), Error> {
    resp_hello_with(ini, rh, now, &mut CountRng(1000))
}

fn responder() -> Responder<'static> {
    let mut r = Responder::new(SPKM, &[SPKT], &mut CountRng(0)).unwrap();
    r.tick(0, &mut CountRng(77)).unwrap();
    r
}

fn respond(r: &mut Responder<'static>, ih: &[u8], now: u64) -> [u8; RESP_HELLO_LEN] {
    let (mut d, mut k, mut m, mut rng) = (FakeDecaps(SPKM), Kyber512, FakeMce, CountRng(5000));
    let mut out = [0u8; RESP_HELLO_LEN];
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    assert_eq!(r.handle_init_hello(ih, now, seams, &mut out), Ok(0));
    out
}

/// The responder's EmptyData and OSK for `ic`, committed.
fn confirm(r: &mut Responder<'static>, ic: &[u8], now: u64) -> ([u8; EMPTY_DATA_LEN], [u8; 32]) {
    let Ok(Conf::Fresh(p)) = r.handle_init_conf(ic, now) else {
        panic!("InitConf refused");
    };
    let osk = *p.psk_install().osk.expose();
    (r.commit_conf(p, now).unwrap(), osk)
}

/// An initiator in SentInitHello at t=0 and the responder's answer.
fn awaiting_resp_hello() -> (Initiator, Responder<'static>, [u8; RESP_HELLO_LEN]) {
    let (mut ini, mut r) = (initiator(), responder());
    let ih = start(&mut ini, 0, 1);
    let rh = respond(&mut r, &ih, 1);
    (ini, r, rh)
}

/// An initiator in SentInitConf at t=2, the EmptyData for it and both OSKs.
fn awaiting_empty_data() -> (Initiator, [u8; EMPTY_DATA_LEN], Osk, [u8; 32]) {
    let (mut ini, mut r, rh) = awaiting_resp_hello();
    let (ic, osk) = resp_hello(&mut ini, &rh, 2).unwrap();
    let (ed, osk_r) = confirm(&mut r, &ic, 3);
    (ini, ed, osk, osk_r)
}

/// Recomputes the envelope mac of a message to the initiator after an edit,
/// so only the edit is tested.
fn reseal(msg: &mut [u8]) {
    let key = mac_key(&Domains::v02().unwrap(), SPKT).unwrap();
    let off = msg.len() - 32;
    let mac = envelope_mac(&key, msg).unwrap();
    msg[off..off + 16].copy_from_slice(&mac);
}

#[test]
fn a_whole_exchange_with_the_responder_yields_equal_osks() {
    let (mut ini, mut r) = (initiator(), responder());
    assert_eq!(ini.state().phase(), Phase::Idle);
    let ih = start(&mut ini, 0, 1);
    assert_eq!(ini.state().phase(), Phase::SentInitHello);
    let rh = respond(&mut r, &ih, 1);
    let (ic, osk_i) = resp_hello(&mut ini, &rh, 2).unwrap();
    assert_eq!(ini.state().phase(), Phase::SentInitConf);
    let (ed, osk_r) = confirm(&mut r, &ic, 3);
    assert_eq!(ini.handle_empty_data(&ed, 4), Ok(()));
    assert_eq!(ini.state().phase(), Phase::Established);
    assert_eq!(osk_i.expose(), &osk_r);
    assert_ne!(osk_r, [0; 32]);
}

#[test]
fn two_handshakes_yield_different_osks() {
    let (_, _, a, _) = awaiting_empty_data();
    let (mut ini, mut r) = (initiator(), responder());
    let ih = start(&mut ini, 0, 2);
    let rh = respond(&mut r, &ih, 1);
    let (_, b) = resp_hello(&mut ini, &rh, 2).unwrap();
    assert_ne!(a.expose(), b.expose());
}

#[test]
fn a_kyber512_key_pair_decapsulates_its_encapsulation() {
    let (pk, sk) = Kyber512.keygen(&mut CountRng(3)).unwrap();
    let (ct, ss) = Encaps::encaps(&mut Kyber512, &pk, &mut CountRng(4)).unwrap();
    assert_eq!(Kyber512.decaps(&sk, &ct).expose(), ss.expose());
    let mut other = ct;
    other[0] ^= 1;
    assert_ne!(Kyber512.decaps(&sk, &other).expose(), ss.expose(), "implicit rejection");
    assert!(Kyber512.keygen(&mut FailRng).is_err());
}

// ---- deny/allow pairs: the error, and the state core unchanged ----

#[test]
fn a_resp_hello_from_another_responder_key_is_refused() {
    let (mut good, _, rh) = awaiting_resp_hello();
    // The same draws, but pinned to SPKT as the responder.
    let pinned = InitiatorKeys { spki: SPKT, spkr: SPKT };
    let mut wrong = Initiator::new(&pinned).unwrap();
    start_keys(&mut wrong, &pinned, 0, &mut CountRng(1)).unwrap();
    let before = *wrong.state();
    assert_eq!(resp_hello(&mut wrong, &rh, 2).err(), Some(Error::Auth));
    assert_eq!(*wrong.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut good, &rh, 2).is_ok());
}

#[test]
fn keys_other_than_the_initiators_own_are_refused() {
    let mut ini = initiator();
    let before = *ini.state();
    let swapped = InitiatorKeys { spki: SPKM, spkr: SPKT };
    for keys in [swapped, InitiatorKeys { spki: SPKM, ..KEYS }, InitiatorKeys { spkr: SPKT, ..KEYS }] {
        assert_eq!(start_keys(&mut ini, &keys, 0, &mut CountRng(1)).err(), Some(Error::Internal));
        assert_eq!(*ini.state(), before, "{ADVANCED}");
    }
    let ih = start(&mut ini, 0, 1);
    let rh = respond(&mut responder(), &ih, 1);
    let before = *ini.state();
    let (mut d, mut k, mut m, mut rng) = (FakeDecaps(SPKT), Kyber512, FakeMce, CountRng(1000));
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    assert_eq!(ini.handle_resp_hello(&swapped, &rh, 2, seams).err(), Some(Error::Internal));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut ini, &rh, 2).is_ok());
}

#[test]
fn a_resp_hello_with_one_byte_flipped_is_refused() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    // ecti, scti, auth, biscuit: everything the mac covers is also authenticated.
    for at in [12, 800, 970, 1000] {
        let mut bad = rh;
        bad[at] ^= 1;
        assert_eq!(resp_hello(&mut ini, &bad, 2).err(), Some(Error::BadMac), "byte {at}");
        assert_eq!(*ini.state(), before, "{ADVANCED}");
        reseal(&mut bad);
        assert_eq!(resp_hello(&mut ini, &bad, 2).err(), Some(Error::Auth), "byte {at} resealed");
        assert_eq!(*ini.state(), before, "{ADVANCED}");
    }
    assert!(resp_hello(&mut ini, &rh, 2).is_ok());
}

#[test]
fn a_replayed_empty_data_is_refused() {
    let (mut ini, ed, _, _) = awaiting_empty_data();
    assert_eq!(ini.handle_empty_data(&ed, 4), Ok(()));
    let before = *ini.state();
    assert_eq!(ini.handle_empty_data(&ed, 5), Err(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert_eq!(before.phase(), Phase::Established);
}

#[test]
fn a_resp_hello_for_an_unknown_session_is_refused() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    let mut other = rh;
    other[8] ^= 1; // sidi
    reseal(&mut other);
    assert_eq!(resp_hello(&mut ini, &other, 2).err(), Some(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut ini, &rh, 2).is_ok());
}

#[test]
fn an_empty_data_for_an_unknown_session_is_refused() {
    let (mut ini, ed, _, _) = awaiting_empty_data();
    let before = *ini.state();
    let mut other = ed;
    other[4] ^= 1; // sid
    reseal(&mut other);
    assert_eq!(ini.handle_empty_data(&other, 4), Err(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert_eq!(ini.handle_empty_data(&ed, 4), Ok(()));
}

#[test]
fn an_empty_data_with_a_wrong_auth_is_refused() {
    let (mut ini, ed, _, _) = awaiting_empty_data();
    let before = *ini.state();
    let mut bad = ed;
    bad[20] ^= 1; // auth
    assert_eq!(ini.handle_empty_data(&bad, 4), Err(Error::BadMac));
    reseal(&mut bad);
    assert_eq!(ini.handle_empty_data(&bad, 4), Err(Error::Auth));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert_eq!(ini.handle_empty_data(&ed, 4), Ok(()));
}

#[test]
fn a_second_resp_hello_releases_no_second_osk() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    assert!(resp_hello(&mut ini, &rh, 2).is_ok());
    let before = *ini.state();
    assert_eq!(resp_hello(&mut ini, &rh, 3).err(), Some(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
}

#[test]
fn an_empty_data_before_the_resp_hello_is_refused() {
    let (mut early, ed, _, _) = awaiting_empty_data();
    let (mut ini, _, _) = awaiting_resp_hello();
    let before = *ini.state();
    assert_eq!(ini.handle_empty_data(&ed, 2), Err(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert_eq!(early.handle_empty_data(&ed, 4), Ok(()));
}

#[test]
fn malformed_messages_are_refused() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    assert_eq!(resp_hello(&mut ini, &rh[..RESP_HELLO_LEN - 1], 2).err(), Some(Error::Malformed));
    let mut ty = rh;
    ty[0] = 0x81;
    assert_eq!(resp_hello(&mut ini, &ty, 2).err(), Some(Error::Malformed));
    assert_eq!(ini.handle_empty_data(&[0x84; EMPTY_DATA_LEN - 1], 2), Err(Error::Malformed));
    assert_eq!(ini.handle_cookie_reply(&rh, 2), Err(Error::Malformed));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
}

#[test]
fn a_failed_draw_in_start_keeps_the_handshake_in_flight() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    assert_eq!(start_with(&mut ini, 5, &mut FailRng).err(), Some(Error::Rng));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut ini, &rh, 6).is_ok(), "the old handshake's secrets are intact");
}

#[test]
fn a_failed_draw_in_handle_resp_hello_changes_nothing() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    assert_eq!(resp_hello_with(&mut ini, &rh, 2, &mut FailRng).err(), Some(Error::Rng));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut ini, &rh, 2).is_ok());
}

#[test]
fn a_resp_hello_after_the_handshake_lifetime_is_refused() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    let before = *ini.state();
    assert_eq!(resp_hello(&mut ini, &rh, REJECT_AFTER_TIME_NS).err(), Some(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(resp_hello(&mut ini, &rh, REJECT_AFTER_TIME_NS - 1).is_ok());
}

// ---- retransmission ----

#[test]
fn timing_constants_are_upstreams() {
    // rosenpass/src/protocol/constants.rs at 9e72f1eb: 0.5, 2.0, 10.0, 0.5, 180.0, 130.0
    // (tools/check-pins P34 holds these to tests/vectors/upstream-constants.txt).
    assert_eq!(RETRANSMIT_DELAY_BEGIN_NS, 500 * MS);
    assert_eq!((RETRANSMIT_DELAY_JITTER_NUM, RETRANSMIT_DELAY_JITTER_DEN), (1, 2));
    assert_eq!(RETRANSMIT_DELAY_GROWTH, 2);
    assert_eq!(RETRANSMIT_DELAY_END_NS, 10 * S);
    assert_eq!(REJECT_AFTER_TIME_NS, 180 * S);
    assert_eq!(REKEY_AFTER_TIME_INITIATOR_NS, 130 * S);
}

/// The gaps between successive retransmissions with every jitter `j`.
fn gaps(j: u8, n: usize) -> Vec<u64> {
    let mut s = InitiatorState::new().start(0, [1, 2, 3, 4], [j; JITTER_LEN]).unwrap();
    let mut last = 0;
    let mut out = Vec::new();
    for _ in 0..n {
        let at = s.deadline().unwrap();
        let (early, t) = s.tick(at - 1).unwrap();
        assert_eq!((early, t), (s, Tick::Nothing));
        let (next, t) = s.tick(at).unwrap();
        assert_eq!(t, Tick::Retransmit);
        out.push(at - last);
        last = at;
        s = next;
    }
    out
}

#[test]
fn retransmission_backs_off_exponentially_to_the_cap() {
    // JITTER · (1 + u) with u = 0: half the base delay.
    assert_eq!(gaps(0, 7), [250, 500, 1000, 2000, 4000, 5000, 5000].map(|g| g * MS));
    // u = 255/256: just under the base delay.
    let full = [500, 1000, 2000, 4000, 8000, 10_000].map(|g| g * MS * 511 / 512);
    assert_eq!(gaps(255, 6), full);
}

#[test]
fn retransmit_delay_saturates_at_the_cap_for_any_count() {
    assert_eq!(retransmit_delay(u32::MAX, 0), Some(5 * S));
    assert_eq!(retransmit_delay(64, 255), Some(10 * S * 511 / 512));
}

#[test]
fn a_handshake_dies_after_its_lifetime() {
    let s = InitiatorState::new().start(7, [1, 2, 3, 4], [0; JITTER_LEN]).unwrap();
    let (_, t) = s.tick(7 + REJECT_AFTER_TIME_NS - 1).unwrap();
    assert_eq!(t, Tick::Retransmit);
    let (dead, t) = s.tick(7 + REJECT_AFTER_TIME_NS).unwrap();
    assert_eq!((dead.phase(), t, dead.deadline()), (Phase::Idle, Tick::Expired, None));
}

#[test]
fn the_initiator_resends_its_stored_messages_until_the_empty_data() {
    let (mut ini, mut r) = (initiator(), responder());
    let ih = start(&mut ini, 0, 1);
    let at = ini.state().deadline().unwrap();
    assert!(ini.tick(at - 1).is_none());
    assert_eq!(ini.tick(at).unwrap().as_bytes(), &ih[..]);
    assert!(ini.tick(at).is_none(), "the next retry is registered");

    let rh = respond(&mut r, &ih, at);
    let (ic, _) = resp_hello(&mut ini, &rh, at).unwrap();
    let at = ini.state().deadline().unwrap();
    assert_eq!(ini.tick(at).unwrap().as_bytes(), &ic[..]);

    let (ed, _) = confirm(&mut r, &ic, at);
    ini.handle_empty_data(&ed, at).unwrap();
    assert_eq!(ini.state().deadline(), None);
    assert!(ini.tick(at + REJECT_AFTER_TIME_NS).is_none());
    assert_eq!(ini.state().rekey_at(), Some(at + REKEY_AFTER_TIME_INITIATOR_NS));
}

#[test]
fn the_initiator_drops_an_expired_handshake() {
    let (mut ini, _, rh) = awaiting_resp_hello();
    assert!(ini.tick(REJECT_AFTER_TIME_NS).is_none());
    assert_eq!(ini.state().phase(), Phase::Idle);
    assert_eq!(resp_hello(&mut ini, &rh, REJECT_AFTER_TIME_NS).err(), Some(Error::UnknownPeer));
}

// ---- the cookie (upstream handle_cookie_reply) ----

fn upstream_reply() -> [u8; cookie::COOKIE_REPLY_LEN] {
    let mut reply = [0u8; cookie::COOKIE_REPLY_LEN];
    reply[0] = rosenpass_wire::MSG_COOKIE_REPLY;
    reply[4..8].copy_from_slice(&cv("cookie.sidi"));
    reply[8..64].copy_from_slice(&cv("cookie.sealed"));
    reply
}

#[test]
fn upstreams_cookie_reply_opens_to_its_cookie_value() {
    let key: [u8; 32] = cv("cookie.key").try_into().unwrap();
    let msg = cv("cookie.msg");
    let mac: [u8; 16] = msg[msg.len() - 32..msg.len() - 16].try_into().unwrap();
    let reply = upstream_reply();
    assert_eq!(cookie::reply_sid(&reply).unwrap().to_vec(), cv("cookie.sidi"));
    let value = cookie::open_cookie_reply(&key, &reply, &mac).unwrap();
    assert_eq!(value.expose().to_vec(), cv("cookie.value"));
    let mut other = mac;
    other[0] ^= 1;
    assert_eq!(cookie::open_cookie_reply(&key, &reply, &other).err(), Some(CryptoError::Auth));
}

#[test]
fn reply_sid_refuses_what_is_not_a_cookie_reply() {
    let reply = upstream_reply();
    assert!(cookie::reply_sid(&reply[..reply.len() - 1]).is_none());
    for at in [0, 1, 3] {
        let mut bad = reply;
        bad[at] ^= 1;
        assert!(cookie::reply_sid(&bad).is_none(), "byte {at}");
    }
}

/// The CookieReply a responder under load sends for the stored `msg`.
fn reply_to(msg: &[u8], sid: [u8; 4]) -> [u8; cookie::COOKIE_REPLY_LEN] {
    let mac: [u8; 16] = msg[msg.len() - 32..msg.len() - 16].try_into().unwrap();
    let value = cookie::cookie_value(&cookie_secret(), &cookie_host());
    let mut out = [0u8; cookie::COOKIE_REPLY_LEN];
    cookie::seal_cookie_reply(&cookie::cookie_key(SPKM), sid, &[0x22; 24], &value, &mac, &mut out).unwrap();
    out
}

#[test]
fn a_cookie_reply_triggers_an_immediate_retransmission_with_a_valid_cookie() {
    let mut ini = initiator();
    let ih = start(&mut ini, 0, 1);
    let secrets = [Some(&cookie_secret()), None];
    assert!(!cookie::cookie_valid(secrets, &cookie_host(), &ih));
    let sid = ini.state().sidi();
    assert_eq!(ini.handle_cookie_reply(&reply_to(&ih, sid), 10), Ok(()));
    let again = ini.tick(10).unwrap();
    assert_eq!(again.as_bytes()[..INIT_HELLO_LEN - 16], ih[..INIT_HELLO_LEN - 16]);
    assert!(cookie::cookie_valid(secrets, &cookie_host(), again.as_bytes()));
}

#[test]
fn a_cookie_reply_for_another_message_or_session_is_refused() {
    let mut ini = initiator();
    let ih = start(&mut ini, 0, 1);
    let sid = ini.state().sidi();
    let before = *ini.state();
    let mut other_mac = ih;
    other_mac[1060] ^= 1;
    assert_eq!(ini.handle_cookie_reply(&reply_to(&other_mac, sid), 10), Err(Error::Auth));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    let mut other_sid = sid;
    other_sid[0] ^= 1;
    assert_eq!(ini.handle_cookie_reply(&reply_to(&ih, other_sid), 10), Err(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
    assert!(ini.tick(10).is_none(), "no retransmission was triggered");
    assert_eq!(ini.handle_cookie_reply(&reply_to(&ih, sid), 10), Ok(()));
}

#[test]
fn a_cookie_reply_after_the_handshake_is_refused() {
    let (mut ini, ed, _, _) = awaiting_empty_data();
    let sent = ini.tick(ini.state().deadline().unwrap()).unwrap();
    ini.handle_empty_data(&ed, 4).unwrap();
    let before = *ini.state();
    assert_eq!(ini.handle_cookie_reply(&reply_to(sent.as_bytes(), before.sidi()), 5), Err(Error::UnknownPeer));
    assert_eq!(*ini.state(), before, "{ADVANCED}");
}
