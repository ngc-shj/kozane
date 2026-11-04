//! M9 plan C8 acceptance on a simulated clock, against the real
//! `rosenpass-core` responder with real KEMs on both sides.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "../tests/support/mod.rs"]
mod support;

use std::cell::Cell;
use std::rc::Rc;

use rosenpass_core::initiator_state::{Phase, REKEY_AFTER_TIME_INITIATOR_NS};
use rosenpass_wire::{INIT_CONF_LEN, INIT_HELLO_LEN, MSG_INIT_CONF, MSG_INIT_HELLO};

use super::*;
use support::{Gateway, S, client_pair, gateway_pair};

const BOUND: u64 = REJECT_AFTER_TIME_NS;

/// The OS RNG behind a switch: the test seam for an RNG failure.
#[derive(Clone)]
struct SwitchRng(Rc<Cell<bool>>);

impl Rng for SwitchRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        if self.0.get() { OsRng.fill(out) } else { Err(RngError) }
    }
}

fn config() -> Config {
    Config::new("192.0.2.1:9999".parse().unwrap(), &gateway_pair().public[..], [7; 32]).unwrap()
}

fn keys() -> Box<Keys> {
    let p = client_pair();
    Keys::new(&p.public[..], &p.secret_oqs[..]).unwrap()
}

fn client_with(rng: SwitchRng) -> Client<SwitchRng> {
    let (c, first) = Client::with_rng(config(), keys(), rng).unwrap();
    assert!(matches!(first.iter().collect::<Vec<_>>()[..], [Action::Scrub]), "client: send before scrub");
    c
}

fn client() -> Client<SwitchRng> {
    client_with(SwitchRng(Rc::new(Cell::new(true))))
}

fn kinds(actions: &Actions) -> Vec<&'static str> {
    actions
        .iter()
        .map(|a| match a {
            Action::Send(_) => "send",
            Action::InstallPsk(_) => "psk",
            Action::Scrub => "scrub",
        })
        .collect()
}

fn has_scrub(actions: &Actions) -> bool {
    actions.iter().any(|a| matches!(a, Action::Scrub))
}

/// The one datagram in `actions`, of type `ty`.
fn sent(actions: Actions, ty: u8, len: usize) -> Vec<u8> {
    let mut out = None;
    for a in actions {
        if let Action::Send(d) = a {
            assert!(out.is_none(), "two datagrams");
            out = Some(d.as_bytes().to_vec());
        }
    }
    let d = out.expect("no datagram");
    assert_eq!((d[0], d.len()), (ty, len));
    d
}

/// One exchange whose RespHello authenticates at `t`: on_timer starts it
/// (or rekeys), the gateway answers, the EmptyData ends it. Returns the
/// client's and the gateway's PSK.
fn exchange(c: &mut Client<SwitchRng>, gw: &mut Gateway, t: u64) -> ([u8; 32], [u8; 32]) {
    let ih = sent(c.on_timer(t).unwrap(), MSG_INIT_HELLO, INIT_HELLO_LEN);
    let rh = gw.respond(&ih, t);
    let out = c.on_datagram(t, &rh).unwrap();
    assert_eq!(kinds(&out), ["psk", "send"]);
    let mut psk = None;
    let mut ic = None;
    for a in out {
        match a {
            Action::InstallPsk(k) => psk = Some(*k.expose()),
            Action::Send(d) => ic = Some(d.as_bytes().to_vec()),
            Action::Scrub => unreachable!(),
        }
    }
    let ic = ic.unwrap();
    assert_eq!((ic[0], ic.len()), (MSG_INIT_CONF, INIT_CONF_LEN));
    let (ed, osk) = gw.confirm(&ic, t);
    assert!(c.on_datagram(t, &ed).unwrap().is_empty());
    (psk.unwrap(), osk)
}

/// A client whose RespHello authenticated at `t`.
fn established(t: u64) -> Client<SwitchRng> {
    let mut c = client();
    let mut gw = Gateway::new(0);
    exchange(&mut c, &mut gw, t);
    c
}

#[test]
fn the_first_action_is_scrub_and_the_first_send_follows_on_the_timer() {
    let (mut c, first) = Client::new(config(), keys()).unwrap();
    assert_eq!(kinds(&first), ["scrub"], "client: send before scrub");
    assert_eq!(c.next_deadline(), Some(0));
    sent(c.on_timer(0).unwrap(), MSG_INIT_HELLO, INIT_HELLO_LEN);
}

#[test]
fn a_whole_exchange_installs_the_gateways_psk() {
    let mut c = client();
    let mut gw = Gateway::new(0);
    let (psk, osk) = exchange(&mut c, &mut gw, S);
    assert_eq!(psk, osk);
    assert_ne!(psk, [0; 32]);
    assert_eq!(c.ini.state().phase(), Phase::Established);
    assert_eq!(c.next_deadline(), Some(S + REKEY_AFTER_TIME_INITIATOR_NS));
}

#[test]
fn no_scrub_one_tick_before_the_bound() {
    let t0 = S;
    let mut c = established(t0);
    assert!(!has_scrub(&c.on_timer(t0 + BOUND - 1).unwrap()), "client: unexpected scrub");
}

#[test]
fn scrub_at_the_bound() {
    let t0 = S;
    let mut c = established(t0);
    assert_eq!(c.next_deadline(), Some(t0 + REKEY_AFTER_TIME_INITIATOR_NS));
    let out = c.on_timer(t0 + BOUND).unwrap();
    assert_eq!(kinds(&out), ["scrub"], "client: no scrub at bound");
}

#[test]
fn scrub_after_the_bound() {
    let t0 = S;
    let mut c = established(t0);
    let out = c.on_timer(t0 + BOUND + 1).unwrap();
    assert_eq!(kinds(&out), ["scrub"], "client: no scrub at bound");
    // Once scrubbed, nothing is left to bound until the next RespHello.
    assert!(!has_scrub(&c.on_timer(t0 + 2 * BOUND + 2).unwrap()), "client: unexpected scrub");
}

#[test]
fn a_resp_hello_before_the_bound_pushes_the_deadline() {
    let t0 = S;
    let mut c = client();
    let mut gw = Gateway::new(0);
    exchange(&mut c, &mut gw, t0);
    // The rekey: the second RespHello authenticates at t1 < t0 + bound.
    let t1 = t0 + REKEY_AFTER_TIME_INITIATOR_NS;
    let (psk, osk) = exchange(&mut c, &mut gw, t1);
    assert_eq!(psk, osk);
    assert!(!has_scrub(&c.on_timer(t0 + BOUND).unwrap()), "client: unexpected scrub");
    assert!(!has_scrub(&c.on_timer(t1 + BOUND - 1).unwrap()), "client: unexpected scrub");
    assert_eq!(kinds(&c.on_timer(t1 + BOUND).unwrap()), ["scrub"], "client: no scrub at bound");
}

#[test]
fn a_due_scrub_comes_alone_and_drops_the_datagram() {
    let t0 = S;
    let mut c = established(t0);
    assert_eq!(kinds(&c.on_datagram(t0 + BOUND, &[0x82; 8]).unwrap()), ["scrub"]);
    // The same garbage, with no scrub due, is refused.
    assert!(matches!(c.on_datagram(t0 + BOUND, &[0x82; 8]), Err(Error::Protocol(_))));
}

#[test]
fn an_os_rng_failure_is_an_error_and_sends_nothing() {
    let on = Rc::new(Cell::new(true));
    let mut c = client_with(SwitchRng(on.clone()));
    on.set(false);
    assert_eq!(c.on_timer(0).err(), Some(Error::Rng));
    assert_eq!(c.ini.state().phase(), Phase::Idle);
    // The start is still due, and goes out once the RNG works.
    assert_eq!(c.next_deadline(), Some(0));
    on.set(true);
    let ih = sent(c.on_timer(0).unwrap(), MSG_INIT_HELLO, INIT_HELLO_LEN);

    // A RespHello needs a draw too: no PSK and no InitConf without it, and
    // the state is unchanged, so the same RespHello still authenticates.
    let mut gw = Gateway::new(0);
    let rh = gw.respond(&ih, 1);
    on.set(false);
    assert_eq!(c.on_datagram(1, &rh).err(), Some(Error::Rng));
    assert_eq!(c.ini.state().phase(), Phase::SentInitHello);
    on.set(true);
    assert_eq!(kinds(&c.on_datagram(1, &rh).unwrap()), ["psk", "send"]);
}

#[test]
fn a_refused_datagram_changes_nothing() {
    let mut c = client();
    let ih = sent(c.on_timer(0).unwrap(), MSG_INIT_HELLO, INIT_HELLO_LEN);
    let before = *c.ini.state();
    let mut gw = Gateway::new(0);
    let mut rh = gw.respond(&ih, 1);
    rh[100] ^= 1;
    for bad in [&[][..], &[0x99; 64][..], &rh[..]] {
        assert!(matches!(c.on_datagram(1, bad), Err(Error::Protocol(_))));
        assert_eq!(*c.ini.state(), before);
    }
}

#[test]
fn time_never_goes_back() {
    let mut c = client();
    c.on_timer(5).unwrap();
    assert_eq!(c.on_timer(4).err(), Some(Error::Clock));
    assert_eq!(c.on_datagram(4, &[0x84; 64]).err(), Some(Error::Clock));
}

#[test]
fn actions_refuse_a_push_past_capacity() {
    let mut a = Actions::new();
    for _ in 0..MAX_ACTIONS {
        a.push(Action::Scrub).unwrap();
    }
    assert_eq!(a.push(Action::Scrub).err(), Some(Error::Full));
    assert_eq!(a.len(), MAX_ACTIONS);
    assert_eq!(a.into_iter().count(), MAX_ACTIONS);
}

#[test]
fn a_datagram_longer_than_max_is_refused() {
    assert!(Datagram::new(&[0; MAX_DATAGRAM]).is_ok());
    assert_eq!(Datagram::new(&[0; MAX_DATAGRAM + 1]).err(), Some(Error::Full));
}

#[test]
fn keys_and_config_of_the_wrong_length_are_refused() {
    let p = client_pair();
    assert_eq!(Keys::new(&p.public[1..], &p.secret_oqs[..]).err(), Some(Error::InvalidKey));
    assert_eq!(Keys::new(&p.public[..], &p.secret_oqs[1..]).err(), Some(Error::InvalidKey));
    assert_eq!(Config::new("192.0.2.1:1".parse().unwrap(), &[0; 32], [0; 32]).err(), Some(Error::InvalidKey));
}

#[test]
fn keys_hold_the_secret_in_the_round3_layout() {
    let p = client_pair();
    let k = Keys::new(&p.public[..], &p.secret_oqs[..]).unwrap();
    // liboqs drops the leading `delta ‖ c` (40 bytes), which decapsulation
    // never reads; the conversion zeroes it.
    assert_eq!(k.secret().expose()[..40], [0; 40]);
    assert_eq!(k.secret().expose()[40..], p.secret[40..]);
    assert_eq!(k.public(), &*p.public);
}
