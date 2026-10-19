//! Responder behaviour (M3 plan C1 unit tests): replay, the known-InitConf
//! cache, the two-phase OSK export, biscuit-key rotation and its failure.
//! The upstream InitHello is replayed through the seams; InitConfs are built
//! from our RespHellos with the test's known biscuit keys, the way an
//! initiator's ICI3/ICI4 would (the golden test pins the chain itself).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

extern crate std;

use std::collections::VecDeque;
use std::vec::Vec;

use rosenpass_wire::{INIT_CONF_LEN, InitConf, RESP_HELLO_LEN, RespHello, TAG_LEN};

use crate::chain::Chain;
use crate::crypto;
use crate::tests::*;
use crate::*;

const KEY_A: [u8; 32] = [0xa1; 32];
const KEY_B: [u8; 32] = [0xb2; 32];

fn keyed(key: [u8; 32]) -> QueueRng {
    QueueRng(VecDeque::from([key.to_vec()]))
}

/// A responder for the captured peer with `key` rotated in at `now`.
fn responder(now: u64, key: [u8; 32]) -> Responder<'static, 1> {
    let mut r = Responder::new(SPKM, [SPKT], &mut CountRng(0)).unwrap();
    r.tick(now, &mut keyed(key)).unwrap();
    r
}

/// The captured InitHello again, drawing from `rng`; also returns how many
/// decapsulations it asked for.
fn hello_with<R: Rng>(r: &mut Responder<'static, 1>, now: u64, rng: &mut R) -> (Result<usize, Error>, usize) {
    let (mut d, mut k, mut m) = (replay_decaps(), replay_kyber(), replay_mceliece());
    let mut out = [0u8; RESP_HELLO_LEN];
    let res = r.handle_init_hello(
        init_hello(),
        now,
        &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng },
        &mut out,
    );
    (res, d.calls)
}

/// The captured InitHello again, with fresh sidr and nonce from `seed`.
fn hello(r: &mut Responder<'static, 1>, now: u64, seed: u64) -> [u8; RESP_HELLO_LEN] {
    let (mut d, mut k, mut m) = (replay_decaps(), replay_kyber(), replay_mceliece());
    let mut rng = CountRng(seed);
    let mut out = [0u8; RESP_HELLO_LEN];
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut rng };
    assert_eq!(r.handle_init_hello(init_hello(), now, seams, &mut out), Ok(0));
    out
}

fn biscuit_slot(rh: &[u8; RESP_HELLO_LEN]) -> u8 {
    RespHello::parse(rh).unwrap().biscuit_ct[0] >> 7
}

/// The InitConf an initiator sends for `rh`: ck from the biscuit (sealed
/// under `key`), then RHR6/RHR7 as the initiator mirrors them, ICI3, ICI4.
fn conf_for(rh: &[u8; RESP_HELLO_LEN], key: [u8; 32]) -> [u8; INIT_CONF_LEN] {
    let d = Domains::v02().unwrap();
    let rh = RespHello::parse(rh).unwrap();
    let ad_m = crypto::kh_public(&d.biscuit_ad, SPKM).unwrap();
    let ad = crypto::kh_public(&crypto::kh_public(&ad_m, &rh.sidi).unwrap(), &rh.sidr).unwrap();
    let mut pt = [0u8; 76];
    crypto::xaead_open(&Secret::from_bytes(key), &ad, &rh.biscuit_ct, &mut pt).unwrap();
    let mut c = Chain::from_ck(Secret::from_bytes(pt[44..].try_into().unwrap()), &d);
    c.mix(&rh.biscuit_ct).unwrap();
    c.check_auth(&rh.auth).unwrap();
    c.mix(&rh.sidi).unwrap().mix(&rh.sidr).unwrap();
    let mut auth = [0u8; TAG_LEN];
    c.auth(&mut auth).unwrap();
    let ic = InitConf { sidi: rh.sidi, sidr: rh.sidr, biscuit_ct: rh.biscuit_ct, auth, mac: [0; 16], cookie: [0; 16] };
    let mut out = [0u8; INIT_CONF_LEN];
    ic.emit(&mut out).unwrap();
    reseal(&mut out);
    out
}

/// Recomputes the envelope mac after an edit, so only the edit is tested.
fn reseal(msg: &mut [u8]) {
    let key = mac_key(&Domains::v02().unwrap(), SPKM).unwrap();
    let off = msg.len() - 32;
    let mac = envelope_mac(&key, msg).unwrap();
    msg[off..off + 16].copy_from_slice(&mac);
}

fn fresh(r: &mut Responder<'static, 1>, ic: &[u8], now: u64) -> PendingExport {
    match r.handle_init_conf(ic, now) {
        Ok(Conf::Fresh(p)) => p,
        Ok(Conf::Retransmission { .. }) => panic!("cached answer where an export was expected"),
        Err(e) => panic!("InitConf refused: {e:?}"),
    }
}

fn outcome(r: &mut Responder<'static, 1>, ic: &[u8], now: u64) -> Result<&'static str, Error> {
    r.handle_init_conf(ic, now).map(|c| match c {
        Conf::Fresh(_) => "fresh",
        Conf::Retransmission { .. } => "retransmission",
    })
}

#[test]
fn an_identical_retransmission_gets_the_cached_empty_data_and_no_export() {
    let mut r = responder(0, KEY_A);
    let ic = conf_for(&hello(&mut r, 1, 7), KEY_A);
    let p = fresh(&mut r, &ic, 2);
    let ed = r.commit_conf(p, 2).unwrap();
    match r.handle_init_conf(&ic, 3) {
        Ok(Conf::Retransmission { peer, response }) => assert_eq!((peer, response), (0, ed)),
        _ => panic!("retransmission not answered from the cache"),
    }
    // The cookie is outside the cached hash, as upstream's.
    let mut other_cookie = ic;
    other_cookie[INIT_CONF_LEN - 1] ^= 1;
    assert_eq!(outcome(&mut r, &other_cookie, 4), Ok("retransmission"));
}

#[test]
fn a_biscuit_number_not_above_biscuit_used_is_refused() {
    let mut r = responder(0, KEY_A);
    let ic1 = conf_for(&hello(&mut r, 1, 1), KEY_A);
    let ic2 = conf_for(&hello(&mut r, 1, 2), KEY_A);
    let p = fresh(&mut r, &ic2, 2);
    r.commit_conf(p, 2).unwrap();
    // Lower number: refused.
    assert_eq!(outcome(&mut r, &ic1, 3), Err(Error::BiscuitReplay));
    // Equal number once the cache has expired: refused, not re-exported.
    assert_eq!(outcome(&mut r, &ic2, 2 + KNOWN_RESPONSE_TTL_NS - 1), Ok("retransmission"));
    assert_eq!(outcome(&mut r, &ic2, 2 + KNOWN_RESPONSE_TTL_NS), Err(Error::BiscuitReplay));
}

#[test]
fn the_same_biscuit_with_another_auth_is_refused_without_export_or_cached_answer() {
    let mut r = responder(0, KEY_A);
    let ic = conf_for(&hello(&mut r, 1, 3), KEY_A);
    let mut forged = ic;
    forged[128] ^= 1;
    reseal(&mut forged);
    assert_eq!(outcome(&mut r, &forged, 2), Err(Error::Auth));
    let p = fresh(&mut r, &ic, 2);
    r.commit_conf(p, 2).unwrap();
    // After the genuine one is cached, the forgery still gets nothing.
    assert_eq!(outcome(&mut r, &forged, 3), Err(Error::Auth));
}

#[test]
fn a_failed_psk_install_leaves_no_trace_and_the_retransmission_succeeds() {
    let mut r = responder(0, KEY_A);
    let ic = conf_for(&hello(&mut r, 1, 4), KEY_A);
    let p = fresh(&mut r, &ic, 2);
    let first_osk: Vec<u8> = p.psk_install().osk.expose().to_vec();
    r.abort_conf(p);
    // No EmptyData was produced, nothing cached, biscuit_used untouched.
    let p = fresh(&mut r, &ic, 3);
    assert_eq!(p.psk_install().osk.expose().to_vec(), first_osk);
    let ed = r.commit_conf(p, 3).unwrap();
    assert_eq!(rosenpass_wire::EmptyData::parse(&ed).unwrap().sid, InitConf::parse(&ic).unwrap().sidi);
    assert_eq!(outcome(&mut r, &ic, 4), Ok("retransmission"));
}

#[test]
fn dropping_a_pending_export_is_an_abort() {
    let mut r = responder(0, KEY_A);
    let ic = conf_for(&hello(&mut r, 1, 5), KEY_A);
    drop(fresh(&mut r, &ic, 2));
    assert_eq!(outcome(&mut r, &ic, 3), Ok("fresh"));
}

#[test]
fn a_commit_never_moves_biscuit_used_backwards() {
    let mut r = responder(0, KEY_A);
    let ic1 = conf_for(&hello(&mut r, 1, 1), KEY_A);
    let ic2 = conf_for(&hello(&mut r, 1, 2), KEY_A);
    let p1 = fresh(&mut r, &ic1, 2);
    let p2 = fresh(&mut r, &ic2, 2);
    r.commit_conf(p2, 2).unwrap();
    assert_eq!(r.commit_conf(p1, 2), Err(Error::BiscuitReplay));
}

#[test]
fn a_rotation_keeps_the_previous_key_for_one_epoch() {
    let mut r = responder(0, KEY_A);
    let rh_a = hello(&mut r, 1, 1);
    let rh_a2 = hello(&mut r, 2, 2);
    assert_eq!(biscuit_slot(&rh_a), 1, "the first key takes slot 1, as upstream's");
    // Within the epoch a tick draws nothing.
    r.tick(BISCUIT_EPOCH_NS - 1, &mut FailRng).unwrap();
    r.tick(BISCUIT_EPOCH_NS, &mut keyed(KEY_B)).unwrap();
    let rh_b = hello(&mut r, BISCUIT_EPOCH_NS + 1, 3);
    assert_eq!(biscuit_slot(&rh_b), 0);
    // The previous key still opens its biscuits for one more epoch ...
    assert_eq!(outcome(&mut r, &conf_for(&rh_a, KEY_A), BISCUIT_EPOCH_NS + 2), Ok("fresh"));
    // ... and not after it.
    assert_eq!(outcome(&mut r, &conf_for(&rh_a2, KEY_A), 2 * BISCUIT_EPOCH_NS), Err(Error::NoBiscuitKey));
    assert_eq!(outcome(&mut r, &conf_for(&rh_b, KEY_B), 2 * BISCUIT_EPOCH_NS), Ok("fresh"));
}

#[test]
fn a_failed_rotation_refuses_hello_and_conf_until_a_good_rotation() {
    let mut r = responder(0, KEY_A);
    let ic_a = conf_for(&hello(&mut r, 1, 1), KEY_A);
    assert_eq!(r.tick(BISCUIT_EPOCH_NS, &mut FailRng), Err(Error::Rng));
    // The still-young previous key is dropped too: nothing stale is used.
    assert_eq!(outcome(&mut r, &ic_a, BISCUIT_EPOCH_NS + 1), Err(Error::NoBiscuitKey));
    let (res, decaps_calls) = hello_with(&mut r, BISCUIT_EPOCH_NS + 1, &mut FailRng);
    assert_eq!((res, decaps_calls), (Err(Error::Rng), 0));
    r.tick(BISCUIT_EPOCH_NS + 2, &mut keyed(KEY_B)).unwrap();
    let ic_b = conf_for(&hello(&mut r, BISCUIT_EPOCH_NS + 3, 2), KEY_B);
    let p = fresh(&mut r, &ic_b, BISCUIT_EPOCH_NS + 4);
    r.commit_conf(p, BISCUIT_EPOCH_NS + 4).unwrap();
}

#[test]
fn the_first_init_hello_rotates_a_key_in_and_fails_closed_without_randomness() {
    let mut r = Responder::new(SPKM, [SPKT], &mut CountRng(0)).unwrap();
    assert_eq!(hello_with(&mut r, 1, &mut FailRng), (Err(Error::Rng), 0));
    assert_eq!(hello_with(&mut r, 1, &mut CountRng(9)), (Ok(0), 1));
}

#[test]
fn an_rng_failure_after_the_decapsulation_aborts_the_handshake() {
    let mut r = responder(0, KEY_A);
    // The key is young, so the first draw is sidr (RHR1).
    assert_eq!(hello_with(&mut r, 1, &mut FailRng), (Err(Error::Rng), 1));
    hello(&mut r, 2, 1);
}

#[test]
fn a_bad_mac_is_refused_before_any_decapsulation() {
    let mut r = responder(0, KEY_A);
    let mut ih = init_hello().to_vec();
    ih[1060] ^= 1;
    let (mut d, mut k, mut m) = (replay_decaps(), replay_kyber(), replay_mceliece());
    let mut out = [0u8; RESP_HELLO_LEN];
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut CountRng(0) };
    assert_eq!(r.handle_init_hello(&ih, 1, seams, &mut out), Err(Error::BadMac));
    ih[1060] ^= 1;
    ih[20] ^= 1;
    assert_eq!(r.handle_init_hello(&ih, 1, seams, &mut out), Err(Error::BadMac));
    assert_eq!(d.calls, 0);
    let mut ic = conf_for(&hello(&mut r, 1, 1), KEY_A);
    ic[150] ^= 1;
    assert_eq!(outcome(&mut r, &ic, 2), Err(Error::BadMac));
}

#[test]
fn malformed_messages_are_refused() {
    let mut r = responder(0, KEY_A);
    let (mut d, mut k, mut m) = (replay_decaps(), replay_kyber(), replay_mceliece());
    let mut out = [0u8; RESP_HELLO_LEN];
    let seams = &mut Seams { decaps: &mut d, kyber: &mut k, mceliece: &mut m, rng: &mut CountRng(0) };
    let ih = init_hello();
    assert_eq!(r.handle_init_hello(&ih[..ih.len() - 1], 1, seams, &mut out), Err(Error::Malformed));
    let ic = conf_for(&hello(&mut r, 1, 1), KEY_A);
    assert_eq!(r.handle_init_hello(&ic, 1, seams, &mut out), Err(Error::Malformed));
    assert_eq!(outcome(&mut r, ih, 2), Err(Error::Malformed));
}

#[test]
fn an_init_hello_from_an_unconfigured_peer_is_refused() {
    // Configured with another key: the decrypted initiator id matches nobody.
    let mut r = Responder::new(SPKM, [SPKM], &mut CountRng(0)).unwrap();
    assert_eq!(hello_with(&mut r, 1, &mut CountRng(1)).0, Err(Error::UnknownPeer));
}

#[test]
fn duplicate_peer_keys_are_refused() {
    assert!(matches!(Responder::new(SPKM, [SPKT, SPKT], &mut CountRng(0)), Err(Error::DuplicatePeer)));
    assert!(matches!(Responder::new(SPKM, [SPKT], &mut FailRng), Err(Error::Rng)));
}

#[test]
fn a_decapsulation_refusal_aborts_the_handshake() {
    struct Limited;
    impl Decaps for Limited {
        fn decaps(&mut self, _: &[u8; rosenpass_wire::SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
            Err(DecapsError::RateLimited)
        }
    }
    let mut r = responder(0, KEY_A);
    let (mut k, mut m) = (replay_kyber(), replay_mceliece());
    let mut out = [0u8; RESP_HELLO_LEN];
    let seams = &mut Seams { decaps: &mut Limited, kyber: &mut k, mceliece: &mut m, rng: &mut CountRng(0) };
    assert_eq!(r.handle_init_hello(init_hello(), 1, seams, &mut out), Err(Error::Decaps(DecapsError::RateLimited)));
}
