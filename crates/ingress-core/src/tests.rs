#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use core::cell::Cell;
use std::vec::Vec;

use super::*;

const CFG: Config = Config {
    mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
    ipv4: [10, 0, 2, 15],
    router_mac: [0x52, 0x55, 10, 0, 2, 2],
    port: 51820,
    rp_port: 9999,
};
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
    run_tx(frame, NET_BUFFERS)
}

fn run_tx(frame: &[u8], tx_free: usize) -> Outcome<'_> {
    respond(
        &CFG,
        &mut Gate::default(),
        &mut FakeCrypto::new(true),
        &FakeMac1,
        &mut Buckets::<4>::default(),
        0,
        0,
        tx_free,
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
    let o = respond(&CFG, &mut Gate::default(), &mut crypto, &FakeMac1, &mut Buckets::<1>::default(), 0, 0, NET_BUFFERS, &req, &mut out, &mut cookie);
    let Outcome::ArpReplied(n) = o else { panic!("no reply") };
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth.dst, PEER_MAC);
    let Body::Arp(a) = f.body else { panic!("not arp") };
    assert_eq!((a.op, a.sha, a.spa, a.tha, a.tpa), (ArpOp::Reply, CFG.mac, CFG.ipv4, PEER_MAC, PEER_IP));
}

#[test]
fn the_tx_reserve_refuses_an_arp_reply_at_exactly_half() {
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    assert_eq!(run_tx(&req, NET_BUFFERS / 2), Outcome::ArpSuppressed, "ARP reply must not use the TX reserve");
}

#[test]
fn an_arp_reply_is_sent_one_buffer_above_the_tx_reserve() {
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    assert!(matches!(run_tx(&req, NET_BUFFERS / 2 + 1), Outcome::ArpReplied(_)));
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
    let n = emit_udp(&CFG, CFG.port, SRC, b"resp", &mut out).unwrap();
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

/// A PD stand-in for `run_passes`: `waiting` messages queue on hs, pq, data
/// and outside; every call is logged in order.
#[derive(Default)]
struct FakePass {
    waiting: [usize; 4],
    log: std::vec::Vec<&'static str>,
    maxes: std::vec::Vec<usize>,
}

impl FakePass {
    fn queued(waiting: [usize; 4]) -> Self {
        Self { waiting, ..Self::default() }
    }

    fn take(&mut self, input: usize, name: &'static str, max: usize) -> usize {
        self.log.push(name);
        self.maxes.push(max);
        let n = self.waiting[input].min(max);
        self.waiting[input] -= n;
        n
    }

    fn passes(&self) -> usize {
        self.log.iter().filter(|&&c| c == "end").count()
    }
}

impl PassIo for FakePass {
    fn serve_hs(&mut self, max: usize) -> usize {
        self.take(0, "hs", max)
    }
    fn serve_pq(&mut self, max: usize) -> usize {
        self.take(1, "pq", max)
    }
    fn serve_data(&mut self, max: usize) -> usize {
        self.take(2, "data", max)
    }
    fn tick(&mut self) {
        self.log.push("tick");
    }
    fn serve_outside(&mut self, max: usize) -> usize {
        self.take(3, "outside", max)
    }
    fn end_pass(&mut self) {
        self.log.push("end");
    }
}

#[test]
fn every_pass_of_an_outside_flood_ends_with_notify_and_flush() {
    let mut io = FakePass::queued([0, 0, 0, 3 * PASS_FRAMES]);
    run_passes(&mut io);
    let pass = ["hs", "pq", "data", "tick", "outside", "end"];
    // Three full passes, then one that finds the queue empty and breaks.
    assert_eq!(io.log, pass.repeat(4), "each pass must end with end_pass, after every input and the tick");
}

#[test]
fn every_input_is_bounded_to_pass_frames() {
    let mut io = FakePass::queued([PASS_FRAMES + 1; 4]);
    run_passes(&mut io);
    assert!(io.maxes.iter().all(|&m| m == PASS_FRAMES), "inputs must be capped at PASS_FRAMES: {:?}", io.maxes);
    assert_eq!(io.passes(), 2, "a pass below K must break after its end_pass");
}

#[test]
fn k_on_any_one_input_runs_another_pass() {
    for input in 0..4 {
        let mut waiting = [0; 4];
        waiting[input] = PASS_FRAMES;
        let mut io = FakePass::queued(waiting);
        run_passes(&mut io);
        assert_eq!(io.passes(), 2, "input {input}");
    }
}

#[test]
fn k_minus_one_on_every_input_is_the_last_pass() {
    let mut io = FakePass::queued([PASS_FRAMES - 1; 4]);
    run_passes(&mut io);
    assert_eq!((io.passes(), io.waiting), (1, [0; 4]));
}

#[test]
fn k_from_data_still_runs_the_tick_and_outside_in_the_same_pass() {
    let mut io = FakePass::queued([0, 0, 2 * PASS_FRAMES, 1]);
    run_passes(&mut io);
    let first = &io.log[..6];
    assert_eq!(first, ["hs", "pq", "data", "tick", "outside", "end"]);
    assert_eq!(io.waiting[3], 0);
}

// ---- Rosenpass (M3 plan C4) ----

/// The mac is valid iff its first byte (32 from the end) is 0x11; counts
/// its calls.
#[derive(Default)]
struct FakeRpMac {
    calls: Cell<usize>,
}

impl RpMac for FakeRpMac {
    fn verify(&self, msg: &[u8]) -> bool {
        self.calls.set(self.calls.get() + 1);
        msg[msg.len() - 32] == 0x11
    }
}

fn rp_msg(kind: u8, len: usize, mac_ok: bool) -> Vec<u8> {
    let mut m = std::vec![0u8; len];
    if len > 0 {
        m[0] = kind;
    }
    if len >= 32 {
        m[len - 32] = if mac_ok { 0x11 } else { 0x22 };
    }
    m
}

fn hello() -> Vec<u8> {
    rp_msg(RP_MSG_INIT_HELLO, RP_INIT_HELLO_LEN, true)
}

fn conf() -> Vec<u8> {
    rp_msg(RP_MSG_INIT_CONF, RP_INIT_CONF_LEN, true)
}

fn src(n: u8) -> Endpoint {
    Endpoint { ip: [10, 0, 3, n], port: 40000 }
}

fn rp<'a>(gate: &mut RpGate<8>, now: u64, from: Endpoint, payload: &'a [u8]) -> RpOutcome<'a> {
    rp_classify(gate, &FakeRpMac::default(), now, from, payload)
}

fn forwarded(o: RpOutcome<'_>) -> bool {
    matches!(o, RpOutcome::ForwardHello { .. } | RpOutcome::ForwardConf { .. })
}

#[test]
fn a_datagram_to_the_rp_port_takes_the_rosenpass_path() {
    let m = hello();
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.rp_port, &m);
    let Outcome::Rosenpass { src, payload } = run(&f) else { panic!("not routed to Rosenpass") };
    assert_eq!(src, SRC);
    assert_eq!(payload, &m[..]);
    // The same bytes on the listen port are WireGuard's (and malformed there).
    assert_eq!(run(&udp_to(CFG.mac, CFG.ipv4, CFG.port, &m)), Outcome::BadMessage);
}

#[test]
fn emit_udp_goes_from_the_given_port() {
    let mut out = [0u8; wire::MAX_FRAME];
    let n = emit_udp(&CFG, CFG.rp_port, SRC, b"resp", &mut out).unwrap();
    let Body::Udp4(u) = wire::parse_frame(&out[..n]).unwrap().body else { panic!("not udp") };
    assert_eq!((u.sport, u.dst, u.dport), (CFG.rp_port, PEER_IP, 40000));
}

#[test]
fn init_hello_and_init_conf_of_exact_length_are_forwarded() {
    let mut g = RpGate::default();
    let (h, c) = (hello(), conf());
    let RpOutcome::ForwardHello { src: s, msg } = rp(&mut g, 0, SRC, &h) else { panic!("hello not forwarded") };
    assert_eq!((s, &msg[..]), (SRC, &h[..]));
    let RpOutcome::ForwardConf { src: s, msg } = rp(&mut g, 0, SRC, &c) else { panic!("conf not forwarded") };
    assert_eq!((s, &msg[..]), (SRC, &c[..]));
}

#[test]
fn every_other_type_or_length_is_dropped_before_the_mac() {
    let cases = [
        rp_msg(0x82, 1132, true), // RespHello
        rp_msg(0x84, 64, true),   // EmptyData
        rp_msg(0x86, 72, true),   // CookieReply
        rp_msg(0x01, RP_INIT_HELLO_LEN, true),
        rp_msg(0x00, RP_INIT_CONF_LEN, true),
        rp_msg(RP_MSG_INIT_HELLO, RP_INIT_HELLO_LEN - 1, true),
        rp_msg(RP_MSG_INIT_HELLO, RP_INIT_HELLO_LEN + 1, true),
        rp_msg(RP_MSG_INIT_HELLO, RP_INIT_CONF_LEN, true),
        rp_msg(RP_MSG_INIT_CONF, RP_INIT_CONF_LEN - 1, true),
        rp_msg(RP_MSG_INIT_CONF, RP_INIT_CONF_LEN + 1, true),
        rp_msg(RP_MSG_INIT_CONF, RP_INIT_HELLO_LEN, true),
        std::vec![],
    ];
    let mut g = RpGate::<8>::default();
    let mac = FakeRpMac::default();
    for m in &cases {
        assert_eq!(rp_classify(&mut g, &mac, 0, SRC, m), RpOutcome::TypeDropped, "len {}", m.len());
    }
    assert_eq!(mac.calls.get(), 0);
    assert_eq!(g, RpGate::default());
}

#[test]
fn a_bad_mac_is_refused_and_spends_nothing() {
    let mut g = RpGate::default();
    for _ in 0..100 {
        assert_eq!(rp(&mut g, 0, SRC, &rp_msg(RP_MSG_INIT_HELLO, RP_INIT_HELLO_LEN, false)), RpOutcome::BadMac);
        assert_eq!(rp(&mut g, 0, SRC, &rp_msg(RP_MSG_INIT_CONF, RP_INIT_CONF_LEN, false)), RpOutcome::BadMac);
    }
    assert_eq!(g, RpGate::default());
    assert!(forwarded(rp(&mut g, 0, SRC, &hello())));
}

/// Sends `msg` from `from` at `now`, retiring every forward first so the
/// ring never decides.
fn rp_drained<'a>(g: &mut RpGate<8>, now: u64, from: Endpoint, msg: &'a [u8]) -> RpOutcome<'a> {
    g.reclaimed(0);
    rp(g, now, from, msg)
}

#[test]
fn a_source_over_its_hello_burst_is_rate_limited_then_refills() {
    let mut g = RpGate::default();
    let h = hello();
    for _ in 0..RP_HELLO_SRC_BURST {
        assert!(forwarded(rp_drained(&mut g, 0, SRC, &h)));
    }
    assert_eq!(rp_drained(&mut g, 0, SRC, &h), RpOutcome::RateLimited);
    // The global meter still had tokens: another source passes.
    assert!(forwarded(rp_drained(&mut g, 0, src(9), &h)));
    assert!(forwarded(rp_drained(&mut g, RP_HELLO_SRC_INTERVAL_NS, SRC, &h)));
}

#[test]
fn hellos_over_the_global_burst_are_rate_limited_then_refill() {
    let mut g = RpGate::default();
    let h = hello();
    for i in 0..RP_HELLO_GLOBAL_BURST as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &h)));
    }
    assert_eq!(rp_drained(&mut g, 0, src(100), &h), RpOutcome::RateLimited);
    assert!(forwarded(rp_drained(&mut g, RP_HELLO_GLOBAL_INTERVAL_NS, src(101), &h)));
}

#[test]
fn a_source_refusal_does_not_spend_the_global_hello_meter() {
    let mut g = RpGate::default();
    let h = hello();
    for _ in 0..RP_HELLO_SRC_BURST {
        assert!(forwarded(rp_drained(&mut g, 0, SRC, &h)));
    }
    for _ in 0..50 {
        assert_eq!(rp_drained(&mut g, 0, SRC, &h), RpOutcome::RateLimited);
    }
    let left = RP_HELLO_GLOBAL_BURST - RP_HELLO_SRC_BURST;
    for i in 0..left as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &h)));
    }
    assert_eq!(rp_drained(&mut g, 0, src(200), &h), RpOutcome::RateLimited);
}

#[test]
fn a_source_over_its_conf_burst_is_rate_limited_then_refills() {
    let mut g = RpGate::default();
    let c = conf();
    for _ in 0..RP_CONF_SRC_BURST {
        assert!(forwarded(rp_drained(&mut g, 0, SRC, &c)));
    }
    assert_eq!(rp_drained(&mut g, 0, SRC, &c), RpOutcome::RateLimited);
    assert!(forwarded(rp_drained(&mut g, 0, src(9), &c)));
    assert!(forwarded(rp_drained(&mut g, RP_CONF_SRC_INTERVAL_NS, SRC, &c)));
}

#[test]
fn confs_over_the_global_burst_are_rate_limited_then_refill() {
    let mut g = RpGate::default();
    let c = conf();
    for i in 0..RP_CONF_GLOBAL_BURST as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &c)));
    }
    assert_eq!(rp_drained(&mut g, 0, src(100), &c), RpOutcome::RateLimited);
    assert!(forwarded(rp_drained(&mut g, RP_CONF_GLOBAL_INTERVAL_NS, src(101), &c)));
}

#[test]
fn hello_and_conf_meters_are_separate() {
    let mut g = RpGate::default();
    let (h, c) = (hello(), conf());
    for i in 0..=RP_HELLO_GLOBAL_BURST as u8 {
        rp_drained(&mut g, 0, src(i), &h);
    }
    assert_eq!(rp_drained(&mut g, 0, src(50), &h), RpOutcome::RateLimited);
    assert!(forwarded(rp_drained(&mut g, 0, src(0), &c)), "an exhausted hello meter refused a conf");
}

#[test]
fn a_full_source_table_evicts_the_least_recently_used_source() {
    let mut m = SourceMeters::<2, RP_HELLO_SRC_BURST, RP_HELLO_SRC_INTERVAL_NS>::default();
    for _ in 0..RP_HELLO_SRC_BURST {
        assert!(m.allow([1, 1, 1, 1], 10));
    }
    assert!(!m.allow([1, 1, 1, 1], 10));
    assert!(m.allow([2, 2, 2, 2], 20));
    assert!(m.allow([3, 3, 3, 3], 30));
    assert!(m.allow([1, 1, 1, 1], 40), "the evicted source starts fresh");
}

/// Forwards `n` messages of one kind, spaced so every meter has refilled,
/// so only the ring can refuse.
fn fill(g: &mut RpGate<8>, t: &mut u64, msg: &[u8], n: usize) {
    for _ in 0..n {
        *t += METERS_REFILLED;
        assert!(forwarded(rp(g, *t, SRC, msg)), "refused at {:?}", (g.in_flight(RpKind::Hello), g.in_flight(RpKind::Conf)));
    }
}

/// Longer than every Rosenpass meter's refill interval.
const METERS_REFILLED: u64 = RP_HELLO_SRC_INTERVAL_NS;
const _: () = assert!(
    METERS_REFILLED >= RP_HELLO_GLOBAL_INTERVAL_NS
        && METERS_REFILLED >= RP_CONF_SRC_INTERVAL_NS
        && METERS_REFILLED >= RP_CONF_GLOBAL_INTERVAL_NS
);

#[test]
fn init_conf_cannot_take_the_share_reserved_for_init_hello() {
    let mut g = RpGate::default();
    let (h, c) = (hello(), conf());
    let mut t = 0;
    fill(&mut g, &mut t, &c, RP_CONF_SHARE);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &c), RpOutcome::RingReserved, "conf past its share");
    assert_eq!(g.in_flight(RpKind::Conf), RP_CONF_SHARE);
    fill(&mut g, &mut t, &h, RP_HELLO_RESERVED);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &h), RpOutcome::RingReserved, "hello past the ring");
}

#[test]
fn init_hello_may_use_the_whole_ring() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &hello(), RP_IN_FLIGHT);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &hello()), RpOutcome::RingReserved);
    // A hello-filled ring leaves no room for conf either.
    assert_eq!(rp(&mut g, t, SRC, &conf()), RpOutcome::RingReserved);
}

#[test]
fn a_ring_refusal_spends_no_meter() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &conf(), RP_CONF_SHARE);
    let before = g.clone();
    assert_eq!(rp(&mut g, t, src(77), &conf()), RpOutcome::RingReserved);
    assert_eq!(g, before);
}

#[test]
fn reclaim_retires_the_oldest_forwards_first() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &conf(), RP_CONF_SHARE);
    fill(&mut g, &mut t, &hello(), 2);
    g.reclaimed(RP_CONF_SHARE + 2 - 1);
    assert_eq!((g.in_flight(RpKind::Conf), g.in_flight(RpKind::Hello)), (RP_CONF_SHARE - 1, 2));
    t += METERS_REFILLED;
    assert!(forwarded(rp(&mut g, t, SRC, &conf())), "a reclaimed conf slot is free again");
    // An outstanding count above ours (a link error) retires nothing.
    g.reclaimed(usize::MAX);
    assert_eq!(g.in_flight(RpKind::Conf), RP_CONF_SHARE);
    g.reclaimed(0);
    assert_eq!((g.in_flight(RpKind::Conf), g.in_flight(RpKind::Hello)), (0, 0));
}

#[test]
fn unsent_takes_back_the_newest_forward() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &conf(), 1);
    fill(&mut g, &mut t, &hello(), 1);
    g.unsent();
    assert_eq!((g.in_flight(RpKind::Conf), g.in_flight(RpKind::Hello)), (1, 0));
}

#[test]
fn a_wireguard_flood_leaves_the_rosenpass_meters_untouched() {
    let mut r = Rig::idle();
    let mut g = RpGate::default();
    let m = initiation(true);
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.port, &m);
    let mut limited = 0;
    for _ in 0..1000 {
        let o = respond(&CFG, &mut r.gate, &mut r.crypto, &FakeMac1, &mut r.buckets, 0, LOADED, TX_FREE, &f, &mut [0u8; wire::MAX_FRAME], &mut r.out);
        limited += usize::from(o != Outcome::Initiation { src: SRC, msg: m[..].try_into().unwrap(), mac2_checked: false });
    }
    assert!(limited > 0 && r.loaded(0, IDLE), "the flood did not load the WireGuard path");
    assert_eq!(g, RpGate::default());
    for i in 0..RP_HELLO_GLOBAL_BURST as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &hello())));
    }
}

#[test]
fn a_rosenpass_flood_leaves_the_wireguard_meters_untouched() {
    let mut r = Rig::idle();
    let mut g = RpGate::default();
    let h = hello();
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.rp_port, &h);
    let mut limited = 0;
    for _ in 0..1000 {
        let o = respond(&CFG, &mut r.gate, &mut r.crypto, &FakeMac1, &mut r.buckets, 0, IDLE, TX_FREE, &f, &mut [0u8; wire::MAX_FRAME], &mut r.out);
        let Outcome::Rosenpass { src, payload } = o else { panic!("{o:?}") };
        limited += usize::from(rp_drained(&mut g, 0, src, payload) == RpOutcome::RateLimited);
    }
    assert!(limited > 0);
    assert!(!r.loaded(0, IDLE), "Rosenpass datagrams spent the WireGuard arrival meter");
    let m = initiation(true);
    for _ in 0..BURST {
        assert!(matches!(r.send(0, IDLE, TX_FREE, SRC, &m), Outcome::Initiation { mac2_checked: false, .. }));
    }
}

#[test]
fn a_rosenpass_reply_may_not_use_the_tx_reserve() {
    assert!(!rp_reply_allowed(NET_BUFFERS / 2));
    assert!(rp_reply_allowed(NET_BUFFERS / 2 + 1));
}

#[test]
fn rosenpass_forwards_have_a_single_constructor_each() {
    // Plan C4: the PD's only send to `pq` is fed by these two outcomes, each
    // built once, in `rp_forward_hello` and `rp_forward_conf`. A tripwire.
    let src = include_str!("lib.rs");
    assert_eq!(src.matches("RpOutcome::ForwardHello {").count(), 1);
    assert_eq!(src.matches("RpOutcome::ForwardConf {").count(), 1);
    let hello_at = src.find("RpOutcome::ForwardHello {").unwrap();
    let conf_at = src.find("RpOutcome::ForwardConf {").unwrap();
    let fn_before = |at: usize| src[..at].rfind("fn ").map(|i| &src[i..i + 20]).unwrap();
    assert!(fn_before(hello_at).starts_with("fn rp_forward_hello"));
    assert!(fn_before(conf_at).starts_with("fn rp_forward_conf"));
}
