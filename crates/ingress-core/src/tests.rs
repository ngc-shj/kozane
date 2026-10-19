#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use core::cell::Cell;
use std::vec::Vec;

use super::*;

const CFG: Config =
    Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], router_mac: [0x52, 0x55, 10, 0, 2, 2], port: 51820 };
const PEER_MAC: Mac = [0x52, 0x55, 10, 0, 2, 2];
const PEER_IP: Ipv4 = [10, 0, 2, 2];
const SRC: Endpoint = Endpoint { ip: PEER_IP, port: 40000 };

/// mac1 is valid iff byte 116 (its first byte) is 0x11.
struct FakeMac1;

impl Mac1 for FakeMac1 {
    fn verify(&self, msg: &[u8; INITIATION_LEN]) -> bool {
        msg[wg_wire::INITIATION_MAC1_OFFSET] == 0x11
    }
}

/// Records every call. mac2 is valid iff its first byte is 0x33.
struct FakeCrypto {
    rotate_ok: bool,
    seal_ok: bool,
    rotates: usize,
    clears: usize,
    mac2_calls: Cell<usize>,
    seals: usize,
}

impl FakeCrypto {
    fn new(rotate_ok: bool) -> Self {
        Self { rotate_ok, seal_ok: true, rotates: 0, clears: 0, mac2_calls: Cell::new(0), seals: 0 }
    }

    fn calls(&self) -> usize {
        self.rotates + self.clears + self.mac2_calls.get() + self.seals
    }
}

impl CookieCrypto for FakeCrypto {
    fn rotate(&mut self) -> bool {
        self.rotates += 1;
        self.rotate_ok
    }

    fn clear(&mut self) {
        self.clears += 1;
    }

    fn mac2_valid(&self, _: Endpoint, msg: &[u8; INITIATION_LEN]) -> bool {
        self.mac2_calls.set(self.mac2_calls.get() + 1);
        msg[wg_wire::INITIATION_MAC2_OFFSET] == 0x33
    }

    fn seal_reply(&mut self, _: Endpoint, _: &[u8; INITIATION_LEN], out: &mut [u8; wg_wire::COOKIE_REPLY_LEN]) -> bool {
        self.seals += 1;
        out.fill(0xcc);
        self.seal_ok
    }
}

fn initiation(mac1_ok: bool) -> Vec<u8> {
    let mut m = std::vec![0u8; INITIATION_LEN];
    m[0] = MSG_INITIATION;
    m[wg_wire::INITIATION_MAC1_OFFSET] = if mac1_ok { 0x11 } else { 0x22 };
    m
}

fn transport(len: usize) -> Vec<u8> {
    let mut m = std::vec![0u8; len];
    m[0] = MSG_TRANSPORT;
    m
}

fn build(f: &Frame<'_>) -> Vec<u8> {
    let mut out = [0u8; wire::MAX_FRAME];
    let n = wire::emit(f, &mut out).unwrap();
    out[..n].to_vec()
}

fn udp_to(dst_mac: Mac, dst_ip: Ipv4, dport: u16, payload: &[u8]) -> Vec<u8> {
    build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: dst_mac },
        body: Body::Udp4(Udp4 { src: PEER_IP, dst: dst_ip, sport: 40000, dport, payload }),
    })
}

fn arp(op: ArpOp, dst_mac: Mac, tpa: Ipv4) -> Vec<u8> {
    build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: dst_mac },
        body: Body::Arp(ArpPacket { op, sha: PEER_MAC, spa: PEER_IP, tha: [0; 6], tpa }),
    })
}

fn run(frame: &[u8]) -> Outcome<'_> {
    respond(
        &CFG,
        &mut Gate::default(),
        &mut FakeCrypto::new(true),
        &FakeMac1,
        &mut Buckets::<4>::default(),
        0,
        0,
        NET_BUFFERS,
        frame,
        &mut [0u8; wire::MAX_FRAME],
        &mut [0u8; wg_wire::COOKIE_REPLY_LEN],
    )
}

fn class(payload: &[u8]) -> Outcome<'_> {
    Rig::idle().send(0, IDLE, TX_FREE, SRC, payload)
}

#[test]
fn valid_initiation_on_the_listen_port_goes_to_hs() {
    let m = initiation(true);
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.port, &m);
    let Outcome::Initiation { src, msg, mac2_checked: false } = run(&f) else { panic!("not forwarded") };
    assert_eq!(src, SRC);
    assert_eq!(&msg[..], &m[..]);
}

#[test]
fn transport_message_goes_to_data() {
    let m = transport(TRANSPORT_MIN_LEN);
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.port, &m);
    assert_eq!(run(&f), Outcome::Transport { src: SRC, msg: &f[f.len() - m.len()..] });
}

#[test]
fn initiation_with_bad_mac1_is_dropped() {
    assert_eq!(class(&initiation(false)), Outcome::BadMac1);
}

#[test]
fn initiation_of_wrong_length_is_bad() {
    let mut m = initiation(true);
    m.push(0);
    assert_eq!(class(&m), Outcome::BadMessage);
    assert_eq!(class(&m[..INITIATION_LEN - 1]), Outcome::BadMessage);
}

#[test]
fn short_transport_is_bad() {
    assert_eq!(class(&transport(TRANSPORT_MIN_LEN - 1)), Outcome::BadMessage);
}

#[test]
fn responses_and_cookie_replies_are_not_accepted_by_a_responder() {
    for kind in [2u8, 3] {
        let mut m = transport(92);
        m[0] = kind;
        assert_eq!(class(&m), Outcome::BadMessage);
    }
}

#[test]
fn nonzero_reserved_bytes_are_bad() {
    let mut m = transport(64);
    m[2] = 1;
    assert_eq!(class(&m), Outcome::BadMessage);
}

#[test]
fn empty_payload_is_bad() {
    assert_eq!(class(&[]), Outcome::BadMessage);
}

#[test]
fn initiations_beyond_the_burst_are_rate_limited_then_refill() {
    let mut r = Rig::idle();
    let m = initiation(true);
    for _ in 0..BURST {
        assert!(matches!(r.send(0, IDLE, TX_FREE, SRC, &m), Outcome::Initiation { .. }));
    }
    assert_eq!(r.send(0, IDLE, TX_FREE, SRC, &m), Outcome::RateLimited);
    assert!(matches!(r.send(INTERVAL_NS, IDLE, TX_FREE, SRC, &m), Outcome::Initiation { .. }));
}

#[test]
fn bad_mac1_does_not_spend_the_budget() {
    // Spending the arrival meter here would put the gate under load.
    let mut r = Rig::idle();
    for _ in 0..100 {
        assert_eq!(r.send(0, IDLE, TX_FREE, SRC, &initiation(false)), Outcome::BadMac1);
    }
    assert!(matches!(r.send(0, IDLE, TX_FREE, SRC, &initiation(true)), Outcome::Initiation { mac2_checked: false, .. }));
    assert_eq!(r.crypto.calls(), 1, "only the boot rotation");
}

#[test]
fn sources_have_separate_budgets() {
    let mut b = Buckets::<4>::default();
    for _ in 0..BURST {
        assert!(b.allow(PEER_IP, 0));
    }
    assert!(!b.allow(PEER_IP, 0));
    assert!(b.allow([10, 0, 2, 3], 0));
}

#[test]
fn a_full_table_evicts_the_least_recently_used_source() {
    let mut b = Buckets::<2>::default();
    for _ in 0..BURST {
        assert!(b.allow([1, 1, 1, 1], 10));
    }
    assert!(b.allow([2, 2, 2, 2], 20));
    // Third source evicts [1,1,1,1] (oldest), which then starts fresh.
    assert!(b.allow([3, 3, 3, 3], 30));
    assert!(b.allow([1, 1, 1, 1], 40));
}

#[test]
fn a_clock_going_backwards_refills_nothing() {
    let mut b = Buckets::<1>::default();
    for _ in 0..BURST {
        assert!(b.allow(PEER_IP, u64::MAX / 2));
    }
    assert!(!b.allow(PEER_IP, 0));
}

#[test]
fn wireguard_on_another_port_is_no_service() {
    assert_eq!(run(&udp_to(CFG.mac, CFG.ipv4, 7, &initiation(true))), Outcome::NoService);
}

#[test]
fn udp_to_other_mac_or_ip_is_not_for_us() {
    let m = transport(32);
    assert_eq!(run(&udp_to(PEER_MAC, CFG.ipv4, CFG.port, &m)), Outcome::NotForUs);
    assert_eq!(run(&udp_to([0xff; 6], CFG.ipv4, CFG.port, &m)), Outcome::NotForUs);
    assert_eq!(run(&udp_to(CFG.mac, [10, 0, 2, 16], CFG.port, &m)), Outcome::NotForUs);
}

#[test]
fn udp_claiming_our_own_source_ip_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: CFG.mac },
        body: Body::Udp4(Udp4 { src: CFG.ipv4, dst: CFG.ipv4, sport: 40000, dport: CFG.port, payload: b"x" }),
    });
    assert_eq!(run(&f), Outcome::Spoofed);
}

#[test]
fn answers_broadcast_arp_request_for_our_ip() {
    let mut out = [0u8; wire::MAX_FRAME];
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    let mut cookie = [0u8; wg_wire::COOKIE_REPLY_LEN];
    let mut crypto = FakeCrypto::new(true);
    let o = respond(&CFG, &mut Gate::default(), &mut crypto, &FakeMac1, &mut Buckets::<1>::default(), 0, 0, 0, &req, &mut out, &mut cookie);
    let Outcome::ArpReplied(n) = o else { panic!("no reply") };
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth.dst, PEER_MAC);
    let Body::Arp(a) = f.body else { panic!("not arp") };
    assert_eq!((a.op, a.sha, a.spa, a.tha, a.tpa), (ArpOp::Reply, CFG.mac, CFG.ipv4, PEER_MAC, PEER_IP));
}

#[test]
fn arp_for_other_ip_is_not_for_us() {
    assert_eq!(run(&arp(ArpOp::Request, [0xff; 6], [10, 0, 2, 16])), Outcome::NotForUs);
}

#[test]
fn arp_reply_to_us_is_no_service() {
    assert_eq!(run(&arp(ArpOp::Reply, CFG.mac, CFG.ipv4)), Outcome::NoService);
}

#[test]
fn arp_with_sender_mac_differing_from_ethernet_source_is_spoofed() {
    let f = build(&Frame {
        eth: EthAddrs { src: PEER_MAC, dst: [0xff; 6] },
        body: Body::Arp(ArpPacket { op: ArpOp::Request, sha: [0x52, 0x55, 1, 2, 3, 4], spa: PEER_IP, tha: [0; 6], tpa: CFG.ipv4 }),
    });
    assert_eq!(run(&f), Outcome::Spoofed);
}

#[test]
fn malformed_frame_reports_parser_reason() {
    assert_eq!(run(&[0u8; 10]), Outcome::Dropped(DropReason::TooShort));
}

#[test]
fn emit_udp_goes_from_the_listen_port_to_the_router() {
    let mut out = [0u8; wire::MAX_FRAME];
    let n = emit_udp(&CFG, SRC, b"resp", &mut out).unwrap();
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth, EthAddrs { src: CFG.mac, dst: CFG.router_mac });
    let Body::Udp4(u) = f.body else { panic!("not udp") };
    assert_eq!((u.src, u.sport, u.dst, u.dport, u.payload), (CFG.ipv4, CFG.port, PEER_IP, 40000, &b"resp"[..]));
}

// ---- Cookie gate (plan C3) ----

const IDLE: usize = 0;
const LOADED: usize = BACKLOG_LOAD;
const TX_FREE: usize = NET_BUFFERS;
const MS: u64 = 1_000_000;
const SEC: u64 = 1_000 * MS;
const REPLY: Outcome<'static> = Outcome::CookieReply { dst: SRC, len: wg_wire::COOKIE_REPLY_LEN };

#[derive(Clone, Copy)]
enum Mac2 {
    Zero,
    Valid,
    Invalid,
}

fn init_mac2(mac2: Mac2) -> Vec<u8> {
    let mut m = initiation(true);
    m[wg_wire::INITIATION_MAC2_OFFSET] = match mac2 {
        Mac2::Zero => 0,
        Mac2::Valid => 0x33,
        Mac2::Invalid => 0x44,
    };
    m
}

fn spoofed(i: u32) -> Endpoint {
    let [_, a, b, c] = i.to_be_bytes();
    Endpoint { ip: [172, a, b, c], port: 1000 }
}

struct Rig {
    gate: Gate,
    crypto: FakeCrypto,
    buckets: Buckets<4>,
    out: [u8; wg_wire::COOKIE_REPLY_LEN],
}

impl Rig {
    /// No secret yet; `rotate` succeeds iff `rotate_ok`.
    fn boot(rotate_ok: bool) -> Self {
        Self { gate: Gate::default(), crypto: FakeCrypto::new(rotate_ok), buckets: Buckets::default(), out: [0; 64] }
    }

    /// A secret born at time 0.
    fn idle() -> Self {
        let mut r = Self::boot(true);
        assert!(r.tick(0, IDLE).rotated);
        r
    }

    fn tick(&mut self, now: u64, backlog: usize) -> TickReport {
        self.gate.tick_if_due(&mut self.crypto, now, backlog)
    }

    fn send<'a>(&mut self, now: u64, backlog: usize, tx_free: usize, src: Endpoint, payload: &'a [u8]) -> Outcome<'a> {
        classify(&mut self.gate, &mut self.crypto, &FakeMac1, &mut self.buckets, now, backlog, tx_free, src, payload, &mut self.out)
    }

    /// Load at `now` without changing the gate.
    fn loaded(&self, now: u64, backlog: usize) -> bool {
        self.gate.clone().observe_load(now, backlog)
    }
}

#[test]
fn backlog_at_threshold_puts_the_gate_under_load() {
    let r = Rig::idle();
    assert!(r.loaded(10 * SEC, BACKLOG_LOAD));
    assert!(!r.loaded(10 * SEC, BACKLOG_LOAD - 1));
}

#[test]
fn arrival_meter_below_half_puts_the_gate_under_load() {
    // Per-source refusals spend arrivals but not the forward bucket, so
    // only the arrival trigger can fire: 5 forwarded, then refused.
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    let half = (ARRIVAL_BURST / 2) as usize;
    for i in 0..half {
        let o = r.send(SEC, IDLE, TX_FREE, SRC, &m);
        assert!(!matches!(o, Outcome::CookieReply { .. }), "arrival {i} not yet below half: {o:?}");
    }
    assert!(!r.gate.forward.below_half(SEC));
    assert_eq!(r.send(SEC, IDLE, TX_FREE, SRC, &m), REPLY);
}

#[test]
fn forward_bucket_below_half_puts_the_gate_under_load() {
    let mut r = Rig::idle();
    let half = ForwardBucket::HALF_NS;
    r.gate.forward = Meter { budget_ns: half, last_ns: SEC };
    assert!(!r.loaded(SEC, IDLE));
    r.gate.forward = Meter { budget_ns: half - 1, last_ns: SEC };
    assert!(r.loaded(SEC, IDLE));
}

#[test]
fn load_lasts_exactly_one_second_after_its_last_trigger() {
    let mut r = Rig::idle();
    let t = 10 * SEC;
    r.tick(t, LOADED);
    assert!(r.loaded(t + UNDER_LOAD_AFTER_NS - 1, IDLE));
    assert!(!r.loaded(t + UNDER_LOAD_AFTER_NS, IDLE));
}

#[test]
fn without_a_trigger_there_is_no_hysteresis() {
    let mut r = Rig::idle();
    let t = 10 * SEC;
    r.tick(t, IDLE);
    assert!(!r.loaded(t + 1, IDLE));
}

#[test]
fn a_flood_keeps_load_on_while_gated_and_load_clears_after_it() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    let (start, step, end) = (SEC, MS, 4 * SEC);
    let (mut entered, mut forwarded, mut now, mut i) = (0, 0, start, 0);
    while now < end {
        assert!(!r.tick(now, IDLE).left_load, "load cleared during the flood at {now}");
        let o = r.send(now, IDLE, TX_FREE, spoofed(i), &m);
        entered += usize::from(r.gate.take_load_entered());
        if matches!(o, Outcome::Initiation { .. }) {
            forwarded += 1;
            assert_eq!(entered, 0, "forwarded while under load");
        }
        now += step;
        i += 1;
    }
    assert_eq!(entered, 1);
    assert!(forwarded <= ARRIVAL_BURST as usize);
    // No-transition side: once the flood stops, load clears a second after
    // the meter climbs back to half.
    let mut cleared = None;
    while now < end + 2 * SEC && cleared.is_none() {
        if r.tick(now, IDLE).left_load {
            cleared = Some(now);
        }
        now += step;
    }
    let refill = ArrivalMeter::HALF_NS;
    let Some(cleared) = cleared else { panic!("load never cleared") };
    assert!((end + UNDER_LOAD_AFTER_NS..=end + UNDER_LOAD_AFTER_NS + refill).contains(&cleared), "cleared at {cleared}");
}

#[test]
fn load_clears_one_second_after_hs_drains_with_no_sends() {
    let mut r = Rig::idle();
    let t = 10 * SEC;
    r.tick(t, LOADED);
    assert!(r.gate.take_load_entered());
    assert!(!r.tick(t + UNDER_LOAD_AFTER_NS - 1, IDLE).left_load);
    assert!(r.tick(t + UNDER_LOAD_AFTER_NS, IDLE).left_load);
    assert!(!r.tick(t + UNDER_LOAD_AFTER_NS + 1, IDLE).left_load, "edge reported once");
}

#[test]
fn load_does_not_clear_while_the_hs_ring_stays_full() {
    let mut r = Rig::idle();
    let mut now = 10 * SEC;
    while now < 15 * SEC {
        assert!(!r.tick(now, NET_BUFFERS).left_load);
        now += 10 * MS;
    }
    assert!(r.loaded(now, NET_BUFFERS));
}

#[test]
fn entering_load_is_reported_once() {
    let mut r = Rig::idle();
    assert!(!r.gate.take_load_entered());
    r.tick(SEC, LOADED);
    assert!(r.gate.take_load_entered());
    r.tick(SEC + 1, LOADED);
    assert!(!r.gate.take_load_entered());
}

#[test]
fn continuous_passes_never_lose_the_secret() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    let mut now = 0;
    while now < 600 * SEC {
        r.tick(now, LOADED);
        assert_eq!(r.send(now, LOADED, TX_FREE, SRC, &m), REPLY, "at {now}");
        now += 50 * MS;
    }
    assert_eq!(r.crypto.rotates, 1 + (600 * SEC / ROTATE_AT_NS) as usize);
}

#[test]
fn rotation_waits_for_rotate_at() {
    let mut r = Rig::idle();
    assert!(!r.tick(ROTATE_AT_NS - 1, IDLE).rotated);
    assert!(r.tick(ROTATE_AT_NS, IDLE).rotated);
    assert_eq!(r.crypto.clears, 0);
}

#[test]
fn a_late_pass_past_max_age_refuses_the_secret() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Valid);
    assert!(matches!(r.send(COOKIE_SECRET_MAX_AGE_NS - 1, LOADED, TX_FREE, SRC, &m), Outcome::Initiation { mac2_checked: true, .. }));
    let calls = r.crypto.calls();
    assert_eq!(r.send(COOKIE_SECRET_MAX_AGE_NS, LOADED, TX_FREE, SRC, &m), Outcome::CookieSecretExpired);
    assert_eq!(r.crypto.calls(), calls, "no crypto with an aged secret");
}

#[test]
fn the_expiry_edge_is_raised_once_per_secret() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    assert_eq!(r.send(COOKIE_SECRET_MAX_AGE_NS - 1, LOADED, TX_FREE, SRC, &m), REPLY);
    assert!(!r.gate.take_expired());
    for _ in 0..3 {
        assert_eq!(r.send(COOKIE_SECRET_MAX_AGE_NS, LOADED, TX_FREE, SRC, &m), Outcome::CookieSecretExpired);
    }
    assert!(r.gate.take_expired());
    assert!(!r.gate.take_expired());
    // A new secret re-arms it.
    let t = 2 * COOKIE_SECRET_MAX_AGE_NS;
    assert!(r.tick(t, LOADED).rotated);
    assert_eq!(r.send(t + COOKIE_SECRET_MAX_AGE_NS, LOADED, TX_FREE, SRC, &m), Outcome::CookieSecretExpired);
    assert!(r.gate.take_expired());
}

#[test]
fn rng_failure_gives_no_secret_until_the_retry_interval() {
    let mut r = Rig::boot(false);
    let m = init_mac2(Mac2::Zero);
    assert!(r.tick(0, LOADED).secret_unavailable);
    assert_eq!(r.send(0, LOADED, TX_FREE, SRC, &m), Outcome::NoCookieSecret);
    r.crypto.rotate_ok = true;
    assert!(!r.tick(RETRY_INTERVAL_NS - 1, LOADED).rotated);
    assert_eq!(r.send(RETRY_INTERVAL_NS - 1, LOADED, TX_FREE, SRC, &m), Outcome::NoCookieSecret);
    assert!(r.tick(RETRY_INTERVAL_NS, LOADED).rotated);
    assert_eq!(r.send(RETRY_INTERVAL_NS, LOADED, TX_FREE, SRC, &m), REPLY);
}

#[test]
fn failed_rotation_leaves_no_secret_and_clears_it() {
    let mut r = Rig::idle();
    r.crypto.rotate_ok = false;
    let report = r.tick(ROTATE_AT_NS, IDLE);
    assert!(!report.rotated && report.secret_unavailable);
    assert_eq!(r.gate.born_ns, None);
    assert_eq!(r.crypto.clears, 1);
}

#[test]
fn successful_rotation_records_the_birth_and_clears_nothing() {
    let r = Rig::idle();
    assert_eq!(r.gate.born_ns, Some(0));
    assert_eq!(r.crypto.clears, 0);
}

#[test]
fn many_passes_within_the_retry_interval_rotate_once() {
    let mut r = Rig::boot(false);
    for t in 0..RETRY_INTERVAL_NS / MS {
        r.tick(t * MS, IDLE);
    }
    assert_eq!(r.crypto.rotates, 1);
    r.tick(RETRY_INTERVAL_NS, IDLE);
    assert_eq!(r.crypto.rotates, 2);
}

#[test]
fn a_thousand_refusals_raise_one_unavailable_edge() {
    let mut r = Rig::boot(false);
    let m = init_mac2(Mac2::Zero);
    let (mut edges, mut refused) = (0, 0);
    for t in 0..1000 {
        edges += usize::from(r.tick(t * MS, LOADED).secret_unavailable);
        refused += usize::from(r.send(t * MS, LOADED, TX_FREE, spoofed(t as u32), &m) == Outcome::NoCookieSecret);
    }
    assert_eq!((edges, refused), (1, 1000));
    assert_eq!(r.crypto.rotates, 10);
}

#[test]
fn recovery_then_a_new_failure_raises_a_second_edge() {
    let mut r = Rig::boot(false);
    assert!(r.tick(0, IDLE).secret_unavailable);
    r.crypto.rotate_ok = true;
    assert!(r.tick(RETRY_INTERVAL_NS, IDLE).rotated);
    r.crypto.rotate_ok = false;
    assert!(r.tick(RETRY_INTERVAL_NS + ROTATE_AT_NS, IDLE).secret_unavailable);
    assert!(!r.tick(2 * RETRY_INTERVAL_NS + ROTATE_AT_NS, IDLE).secret_unavailable);
}

#[test]
fn mac2_is_ignored_outside_load() {
    let mut r = Rig::idle();
    for mac2 in [Mac2::Valid, Mac2::Invalid] {
        let m = init_mac2(mac2);
        assert!(matches!(r.send(SEC, IDLE, TX_FREE, spoofed(1), &m), Outcome::Initiation { mac2_checked: false, .. }));
    }
    assert_eq!(r.crypto.mac2_calls.get(), 0);
}

#[test]
fn a_valid_mac2_under_load_is_forwarded_as_checked() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Valid);
    assert!(matches!(r.send(SEC, LOADED, TX_FREE, SRC, &m), Outcome::Initiation { mac2_checked: true, .. }));
    assert_eq!((r.crypto.mac2_calls.get(), r.crypto.seals), (1, 0));
}

#[test]
fn an_invalid_mac2_under_load_draws_a_cookie_reply() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Invalid);
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &m), REPLY);
    assert_eq!((r.crypto.mac2_calls.get(), r.crypto.seals), (1, 1));
    assert_eq!(r.out, [0xcc; 64]);
}

#[test]
fn a_zero_mac2_skips_its_check_but_still_draws_a_reply() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &m), REPLY);
    assert_eq!((r.crypto.mac2_calls.get(), r.crypto.seals), (0, 1));
}

#[test]
fn the_tx_reserve_refuses_at_exactly_half() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    assert_eq!(r.send(SEC, LOADED, NET_BUFFERS / 2, SRC, &m), Outcome::CookieSuppressed);
    assert_eq!(r.crypto.seals, 0);
    assert_eq!(r.send(SEC, LOADED, NET_BUFFERS / 2 + 1, SRC, &m), REPLY);
}

#[test]
fn a_failed_seal_is_suppressed() {
    let mut r = Rig::idle();
    r.crypto.seal_ok = false;
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &init_mac2(Mac2::Zero)), Outcome::CookieSuppressed);
}

#[test]
fn bad_mac1_under_load_makes_no_crypto_call() {
    let mut r = Rig::idle();
    let mut m = init_mac2(Mac2::Valid);
    m[wg_wire::INITIATION_MAC1_OFFSET] = 0x22;
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &m), Outcome::BadMac1);
    assert_eq!(r.crypto.calls(), 1, "only the boot rotation");
}

#[test]
fn a_valid_mac2_is_still_capped_by_the_forward_bucket() {
    let mut r = Rig::idle();
    r.gate.forward = Meter { budget_ns: FORWARD_INTERVAL_NS - 1, last_ns: SEC };
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &init_mac2(Mac2::Valid)), Outcome::RateLimited);
    r.gate.forward = Meter { budget_ns: FORWARD_INTERVAL_NS, last_ns: SEC };
    assert!(matches!(r.send(SEC, LOADED, TX_FREE, SRC, &init_mac2(Mac2::Valid)), Outcome::Initiation { .. }));
}

#[test]
fn a_valid_mac2_is_still_capped_by_the_source_budget() {
    let mut r = Rig::idle();
    for _ in 0..BURST {
        assert!(r.buckets.allow(SRC.ip, SEC));
    }
    assert_eq!(r.send(SEC, LOADED, TX_FREE, SRC, &init_mac2(Mac2::Valid)), Outcome::RateLimited);
    assert_eq!(r.gate.forward.level_ns(SEC), ForwardBucket::CAPACITY_NS, "forward bucket untouched");
}

#[test]
fn only_initiation_spends_the_forward_bucket() {
    let now = 300 * SEC;
    let transport = transport(TRANSPORT_MIN_LEN);
    let (mut initiations, mut others) = (0, 0);
    for backlog in [IDLE, LOADED] {
        for born in [None, Some(now), Some(now - COOKIE_SECRET_MAX_AGE_NS)] {
            for tx_free in [0, TX_FREE] {
                for exhausted in [false, true] {
                    for forward in [FORWARD_INTERVAL_NS - 1, ForwardBucket::CAPACITY_NS] {
                        let mut payloads = std::vec![transport.clone(), initiation(false), std::vec![1u8; 3]];
                        payloads.extend([Mac2::Zero, Mac2::Valid, Mac2::Invalid].map(init_mac2));
                        for p in &payloads {
                            let mut r = Rig::idle();
                            r.gate.born_ns = born;
                            r.gate.forward = Meter { budget_ns: forward, last_ns: now };
                            if exhausted {
                                for _ in 0..BURST {
                                    r.buckets.allow(SRC.ip, now);
                                }
                            }
                            let before = r.gate.forward.level_ns(now);
                            let o = r.send(now, backlog, tx_free, SRC, p);
                            let spent = (before - r.gate.forward.level_ns(now)) / FORWARD_INTERVAL_NS;
                            if matches!(o, Outcome::Initiation { .. }) {
                                initiations += 1;
                                assert_eq!(spent, 1);
                            } else {
                                others += 1;
                                assert_eq!(spent, 0, "{o:?} spent the forward bucket");
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(initiations > 0 && others > 0);
}

#[test]
fn initiation_has_a_single_constructor() {
    // Member set R42: the PD's only send to `hs` is fed by this outcome.
    assert_eq!(include_str!("lib.rs").matches("Outcome::Initiation {").count(), 1);
}

#[test]
fn pass_plan_continues_when_any_input_moved_k_frames() {
    let k = PASS_FRAMES;
    for counts in [(k, 0, 0), (0, k, 0), (0, 0, k)] {
        assert!(pass_plan(counts.0, counts.1, counts.2).continue_, "{counts:?}");
    }
}

#[test]
fn pass_plan_breaks_when_every_input_moved_fewer_than_k() {
    let k = PASS_FRAMES;
    assert!(!pass_plan(k - 1, k - 1, k - 1).continue_);
    assert!(!pass_plan(0, 0, 0).continue_);
}

#[test]
fn pass_plan_flushes_every_pass_with_work() {
    for counts in [(1, 0, 0), (0, 1, 0), (0, 0, 1), (PASS_FRAMES, PASS_FRAMES, PASS_FRAMES)] {
        assert!(pass_plan(counts.0, counts.1, counts.2).flush, "{counts:?}");
    }
}

#[test]
fn pass_plan_does_not_flush_an_idle_pass() {
    assert_eq!(pass_plan(0, 0, 0), PassActions { flush: false, continue_: false });
}

#[test]
fn pass_plan_decides_after_the_outside_input_ran() {
    // K from `data` alone continues and flushes whatever `from_outside` and
    // the tick then did in the same pass: the decision takes all three.
    for n_outside in [0, 1, PASS_FRAMES] {
        assert_eq!(pass_plan(0, PASS_FRAMES, n_outside), PassActions { flush: true, continue_: true });
    }
}

/// A PD stand-in for `run_passes`: `outside` frames are waiting outside;
/// every call is logged in order.
struct FakePass {
    outside: usize,
    log: std::vec::Vec<&'static str>,
    maxes: std::vec::Vec<usize>,
}

impl PassIo for FakePass {
    fn serve_hs(&mut self, max: usize) -> usize {
        self.log.push("hs");
        self.maxes.push(max);
        0
    }
    fn serve_data(&mut self, max: usize) -> usize {
        self.log.push("data");
        self.maxes.push(max);
        0
    }
    fn tick(&mut self) {
        self.log.push("tick");
    }
    fn serve_outside(&mut self, max: usize) -> usize {
        self.log.push("outside");
        self.maxes.push(max);
        let n = self.outside.min(max);
        self.outside -= n;
        n
    }
    fn end_pass(&mut self) {
        self.log.push("end");
    }
}

#[test]
fn every_pass_of_an_outside_flood_ends_with_notify_and_flush() {
    let mut io = FakePass { outside: 3 * PASS_FRAMES, log: std::vec::Vec::new(), maxes: std::vec::Vec::new() };
    run_passes(&mut io);
    let pass = ["hs", "data", "tick", "outside", "end"];
    // Three full passes, then one that finds the queue empty and breaks.
    assert_eq!(io.log, pass.repeat(4), "each pass must serve every input, tick, then end_pass");
}

#[test]
fn every_input_is_bounded_to_pass_frames() {
    let mut io = FakePass { outside: PASS_FRAMES + 1, log: std::vec::Vec::new(), maxes: std::vec::Vec::new() };
    run_passes(&mut io);
    assert!(io.maxes.iter().all(|&m| m == PASS_FRAMES), "inputs must be capped at PASS_FRAMES: {:?}", io.maxes);
    assert_eq!(io.log.iter().filter(|&&c| c == "end").count(), 2, "a pass below K must break after its end_pass");
}
