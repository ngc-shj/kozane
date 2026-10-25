#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use core::cell::Cell;
use std::vec;
use std::vec::Vec;

use super::*;

const CFG: Config = Config {
    mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
    ipv4: [10, 0, 2, 15],
    router_mac: [0x52, 0x55, 10, 0, 2, 2],
    port: 51820,
    rp_port: 9999,
    https_port: 443,
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
        &mut TcpGate::<4>::default(),
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
    let o = respond(&CFG, &mut Gate::default(), &mut crypto, &FakeMac1, &mut Buckets::<1>::default(), &mut TcpGate::<1>::default(), 0, 0, NET_BUFFERS, &req, &mut out, &mut cookie);
    let Outcome::ArpReplied(n) = o else { panic!("no reply") };
    let f = wire::parse_frame(&out[..n]).unwrap();
    assert_eq!(f.eth.dst, PEER_MAC);
    let Body::Arp(a) = f.body else { panic!("not arp") };
    assert_eq!((a.op, a.sha, a.spa, a.tha, a.tpa), (ArpOp::Reply, CFG.mac, CFG.ipv4, PEER_MAC, PEER_IP));
}

#[test]
fn the_tx_reserve_refuses_an_arp_reply_at_the_unsolicited_tier() {
    // M3b S2: ARP replies are unsolicited, below the Rosenpass answer share.
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    assert_eq!(run_tx(&req, NET_BUFFERS / 2 + RP_ANSWER_SHARE), Outcome::ArpSuppressed, "ARP reply must not use the TX reserve or the answer share");
}

#[test]
fn an_arp_reply_is_sent_one_buffer_above_the_unsolicited_tier() {
    let req = arp(ArpOp::Request, [0xff; 6], CFG.ipv4);
    assert!(matches!(run_tx(&req, NET_BUFFERS / 2 + RP_ANSWER_SHARE + 1), Outcome::ArpReplied(_)));
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
    assert_eq!(r.gate.life.born_ns, None);
    assert_eq!(r.crypto.clears, 1);
}

#[test]
fn successful_rotation_records_the_birth_and_clears_nothing() {
    let r = Rig::idle();
    assert_eq!(r.gate.life.born_ns, Some(0));
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
fn the_tx_reserve_refuses_a_cookie_reply_at_the_unsolicited_tier() {
    let mut r = Rig::idle();
    let m = init_mac2(Mac2::Zero);
    assert_eq!(r.send(SEC, LOADED, NET_BUFFERS / 2 + RP_ANSWER_SHARE, SRC, &m), Outcome::CookieSuppressed);
    assert_eq!(r.crypto.seals, 0);
    assert_eq!(r.send(SEC, LOADED, NET_BUFFERS / 2 + RP_ANSWER_SHARE + 1, SRC, &m), REPLY);
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
                            r.gate.life.born_ns = born;
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
    waiting: [usize; 5],
    log: std::vec::Vec<&'static str>,
    maxes: std::vec::Vec<usize>,
}

impl FakePass {
    fn queued(waiting: [usize; 5]) -> Self {
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
    fn serve_tls(&mut self, max: usize) -> usize {
        self.take(3, "tls", max)
    }
    fn tick(&mut self) {
        self.log.push("tick");
    }
    fn serve_outside(&mut self, max: usize) -> usize {
        self.take(4, "outside", max)
    }
    fn end_pass(&mut self) {
        self.log.push("end");
    }
}

#[test]
fn every_pass_of_an_outside_flood_ends_with_notify_and_flush() {
    let mut io = FakePass::queued([0, 0, 0, 0, 3 * PASS_FRAMES]);
    run_passes(&mut io);
    let pass = ["hs", "pq", "data", "tls", "tick", "outside", "end"];
    // Three full passes, then one that finds the queue empty and breaks.
    assert_eq!(io.log, pass.repeat(4), "each pass must end with end_pass, after every input and the tick");
}

#[test]
fn every_input_is_bounded_to_pass_frames() {
    let mut io = FakePass::queued([PASS_FRAMES + 1; 5]);
    run_passes(&mut io);
    assert!(io.maxes.iter().all(|&m| m == PASS_FRAMES), "inputs must be capped at PASS_FRAMES: {:?}", io.maxes);
    assert_eq!(io.passes(), 2, "a pass below K must break after its end_pass");
}

#[test]
fn k_on_any_one_input_runs_another_pass() {
    for input in 0..5 {
        let mut waiting = [0; 5];
        waiting[input] = PASS_FRAMES;
        let mut io = FakePass::queued(waiting);
        run_passes(&mut io);
        assert_eq!(io.passes(), 2, "input {input}");
    }
}

#[test]
fn k_minus_one_on_every_input_is_the_last_pass() {
    let mut io = FakePass::queued([PASS_FRAMES - 1; 5]);
    run_passes(&mut io);
    assert_eq!((io.passes(), io.waiting), (1, [0; 5]));
}

#[test]
fn k_from_data_still_runs_the_tick_and_outside_in_the_same_pass() {
    let mut io = FakePass::queued([0, 0, 2 * PASS_FRAMES, 0, 1]);
    run_passes(&mut io);
    let first = &io.log[..7];
    assert_eq!(first, ["hs", "pq", "data", "tls", "tick", "outside", "end"]);
    assert_eq!(io.waiting[4], 0);
}

#[test]
fn a_tls_flood_still_runs_the_tick_and_outside_in_the_same_pass() {
    let mut io = FakePass::queued([0, 0, 0, 2 * PASS_FRAMES, 1]);
    run_passes(&mut io);
    assert_eq!(&io.log[..7], ["hs", "pq", "data", "tls", "tick", "outside", "end"]);
    assert_eq!(io.waiting[4], 0);
}

// ---- TCP to the HTTPS endpoint (M6 plan C2) ----

const HTTPS: u16 = 443;

/// An IPv4/TCP datagram without options, checksums right.
fn tcp_packet(src: Ipv4, dst: Ipv4, sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&7u32.to_be_bytes());
    seg.extend_from_slice(&9u32.to_be_bytes());
    seg.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    seg.extend_from_slice(payload);
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, IPPROTO_TCP, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip[2..4].copy_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
    let c = csum(&ip, 0);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let pseudo: Vec<u8> = [&src[..], &dst[..], &[0, IPPROTO_TCP], &(seg.len() as u16).to_be_bytes()].concat();
    let c = csum(&seg, sum16(&pseudo));
    seg[16..18].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&seg);
    ip
}

fn sum16(b: &[u8]) -> u32 {
    b.chunks(2).map(|c| u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0))).sum()
}

fn csum(b: &[u8], start: u32) -> u16 {
    let mut s = start + sum16(b);
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn eth_of(src_mac: Mac, dst_mac: Mac, packet: &[u8]) -> Vec<u8> {
    [&dst_mac[..], &src_mac[..], &wire::ETHERTYPE_IPV4.to_be_bytes(), packet].concat()
}

/// A segment from PEER to us, to `dport`, with `flags`.
fn tcp_to(dport: u16, flags: u8) -> Vec<u8> {
    eth_of(PEER_MAC, CFG.mac, &tcp_packet(PEER_IP, CFG.ipv4, 40000, dport, flags, b"data"))
}

fn admit(gate: &mut TcpGate<4>, now: u64, frame: &[u8]) -> Outcome<'static> {
    // Outcomes are compared by kind here; the packet's bytes by the tests
    // that look at them.
    match gate.admit(&CFG, now, frame) {
        Outcome::Tls { .. } => Outcome::Tls { packet: &[] },
        o => o.into_static(),
    }
}

impl Outcome<'_> {
    /// The outcome without its borrowed bytes, for the kinds TCP yields.
    fn into_static(self) -> Outcome<'static> {
        match self {
            Outcome::Dropped(r) => Outcome::Dropped(r),
            Outcome::NoService => Outcome::NoService,
            Outcome::TcpLimited(l) => Outcome::TcpLimited(l),
            o => panic!("not a TCP outcome: {o:?}"),
        }
    }
}

const TLS: Outcome<'static> = Outcome::Tls { packet: &[] };

#[test]
fn tcp_to_our_https_port_goes_to_tls_as_the_ip_packet() {
    let f = tcp_to(HTTPS, wire::TCP_SYN);
    let o = run(&f);
    assert_eq!(o, Outcome::Tls { packet: &f[wire::ETH_HDR..] });
}

#[test]
fn tcp_to_another_port_or_host_has_no_service() {
    let mut g = TcpGate::<4>::default();
    assert_eq!(admit(&mut g, 0, &tcp_to(HTTPS + 1, wire::TCP_SYN)), Outcome::NoService, "other port");
    let other_ip = eth_of(PEER_MAC, CFG.mac, &tcp_packet(PEER_IP, [10, 0, 2, 16], 40000, HTTPS, wire::TCP_SYN, b""));
    assert_eq!(admit(&mut g, 0, &other_ip), Outcome::NoService, "other address");
    let other_mac = eth_of(PEER_MAC, [0x52, 0x54, 0, 0, 0, 1], &tcp_packet(PEER_IP, CFG.ipv4, 40000, HTTPS, wire::TCP_SYN, b""));
    assert_eq!(admit(&mut g, 0, &other_mac), Outcome::NoService, "other MAC");
    let from_us = eth_of(PEER_MAC, CFG.mac, &tcp_packet(CFG.ipv4, CFG.ipv4, 40000, HTTPS, wire::TCP_SYN, b""));
    assert_eq!(admit(&mut g, 0, &from_us), Outcome::NoService, "source address ours");
    let our_mac = eth_of(CFG.mac, CFG.mac, &tcp_packet(PEER_IP, CFG.ipv4, 40000, HTTPS, wire::TCP_SYN, b""));
    assert_eq!(admit(&mut g, 0, &our_mac), Outcome::NoService, "source MAC ours");
    assert_eq!(admit(&mut g, 0, &tcp_to(HTTPS, wire::TCP_SYN)), TLS, "and the allow side");
}

#[test]
fn a_bad_tcp_header_is_dropped_with_its_reason() {
    let mut f = tcp_to(HTTPS, wire::TCP_SYN | wire::TCP_FIN);
    assert_eq!(run(&f), Outcome::Dropped(DropReason::TcpBadFlags));
    f = tcp_to(HTTPS, wire::TCP_SYN);
    let last = f.len() - 1;
    f[last] ^= 1;
    assert_eq!(run(&f), Outcome::Dropped(DropReason::TcpBadChecksum));
}

#[test]
fn another_protocol_stays_not_udp() {
    let mut p = tcp_packet(PEER_IP, CFG.ipv4, 40000, HTTPS, wire::TCP_SYN, b"");
    p[9] = 47;
    p[10..12].fill(0);
    let c = csum(&p[..20], 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(run(&eth_of(PEER_MAC, CFG.mac, &p)), Outcome::Dropped(DropReason::NotUdp));
}

#[test]
fn a_source_gets_its_syn_burst_and_then_is_limited() {
    let mut g = TcpGate::<4>::default();
    let syn = tcp_to(HTTPS, wire::TCP_SYN);
    for i in 0..SYN_SRC_BURST {
        assert_eq!(admit(&mut g, 0, &syn), TLS, "SYN {i}");
    }
    assert_eq!(admit(&mut g, 0, &syn), Outcome::TcpLimited(TcpLimit::SynSource));
    assert_eq!(admit(&mut g, SYN_SRC_INTERVAL_NS - 1, &syn), Outcome::TcpLimited(TcpLimit::SynSource));
    assert_eq!(admit(&mut g, SYN_SRC_INTERVAL_NS, &syn), TLS, "one more after its interval");
}

#[test]
fn syns_from_many_sources_get_the_global_burst_and_then_are_limited() {
    let mut g = TcpGate::<64>::default();
    let syn_from = |n: u8| eth_of(PEER_MAC, CFG.mac, &tcp_packet([10, 0, 9, n], CFG.ipv4, 40000, HTTPS, wire::TCP_SYN, b""));
    for n in 0..SYN_GLOBAL_BURST as u8 {
        assert!(matches!(g.admit(&CFG, 0, &syn_from(n)), Outcome::Tls { .. }), "source {n}");
    }
    let next = syn_from(200);
    assert_eq!(g.admit(&CFG, 0, &next), Outcome::TcpLimited(TcpLimit::SynGlobal));
    assert_eq!(g.admit(&CFG, SYN_GLOBAL_INTERVAL_NS - 1, &next), Outcome::TcpLimited(TcpLimit::SynGlobal));
    assert!(matches!(g.admit(&CFG, SYN_GLOBAL_INTERVAL_NS, &next), Outcome::Tls { .. }), "one more after its interval");
}

#[test]
fn a_source_over_its_syn_bucket_spends_nothing_globally() {
    let mut g = TcpGate::<4>::default();
    let syn = tcp_to(HTTPS, wire::TCP_SYN);
    for _ in 0..SYN_SRC_BURST + 100 {
        admit(&mut g, 0, &syn);
    }
    assert_eq!(g.syn_global.tokens(0), SYN_GLOBAL_BURST - SYN_SRC_BURST);
}

#[test]
fn segments_other_than_syns_spend_only_the_data_bucket() {
    let mut g = TcpGate::<4>::default();
    let ack = tcp_to(HTTPS, wire::TCP_ACK);
    let synack = tcp_to(HTTPS, wire::TCP_SYN | wire::TCP_ACK);
    for i in 0..TCP_DATA_BURST {
        let f = if i % 2 == 0 { &ack } else { &synack };
        assert_eq!(admit(&mut g, 0, f), TLS, "segment {i}");
    }
    assert_eq!(admit(&mut g, 0, &ack), Outcome::TcpLimited(TcpLimit::Data));
    assert_eq!(admit(&mut g, TCP_DATA_INTERVAL_NS - 1, &ack), Outcome::TcpLimited(TcpLimit::Data));
    assert_eq!(admit(&mut g, TCP_DATA_INTERVAL_NS, &ack), TLS);
    // A data flood leaves new connections their buckets, and vice versa.
    assert_eq!(admit(&mut g, TCP_DATA_INTERVAL_NS, &tcp_to(HTTPS, wire::TCP_SYN)), TLS);
    assert_eq!(g.syn_global.tokens(TCP_DATA_INTERVAL_NS), SYN_GLOBAL_BURST - 1);
}

#[test]
fn the_syn_table_has_its_own_constants_and_the_initiation_table_keeps_its() {
    let mut wg = Buckets::<1>::default();
    let mut syn = Buckets::<1, SYN_SRC_BURST, SYN_SRC_INTERVAL_NS>::default();
    let granted = |b: &mut dyn FnMut() -> bool| (0..20).filter(|_| b()).count() as u64;
    assert_eq!(granted(&mut || wg.allow(PEER_IP, 0)), BURST);
    assert_eq!(granted(&mut || syn.allow(PEER_IP, 0)), SYN_SRC_BURST);
    assert!(!wg.allow(PEER_IP, INTERVAL_NS - 1) && wg.allow(PEER_IP, INTERVAL_NS));
}

// ---- tls_egress (M6 plan C2) ----

/// A segment `tls` would send: from us:443 to PEER, ACK set.
fn from_tls(flags: u8) -> Vec<u8> {
    tcp_packet(CFG.ipv4, PEER_IP, HTTPS, 40000, flags, b"reply")
}

const TX_ROOM: usize = NET_BUFFERS / 2 + TLS_TX_SHARE + 1;

#[test]
fn tls_egress_frames_a_conforming_segment_to_the_router() {
    let p = from_tls(wire::TCP_ACK | wire::TCP_PSH);
    let f = tls_egress(&CFG, &p, TX_ROOM).unwrap();
    assert_eq!(f.eth, EthAddrs { src: CFG.mac, dst: CFG.router_mac });
    let Body::Ipv4(ip) = f.body else { panic!("not ipv4") };
    assert_eq!((ip.src, ip.dst, ip.packet), (CFG.ipv4, PEER_IP, &p[..]));
    let mut out = [0u8; wire::MAX_FRAME];
    assert_eq!(wire::emit(&f, &mut out), Ok(wire::ETH_HDR + p.len()));
}

#[test]
fn tls_egress_allows_syn_ack_fin_and_rst_but_never_a_bare_syn() {
    for flags in [wire::TCP_SYN | wire::TCP_ACK, wire::TCP_FIN | wire::TCP_ACK, wire::TCP_RST, wire::TCP_RST | wire::TCP_ACK] {
        assert!(tls_egress(&CFG, &from_tls(flags), TX_ROOM).is_ok(), "flags {flags:#x}");
    }
    assert_eq!(tls_egress(&CFG, &from_tls(wire::TCP_SYN), TX_ROOM), Err(EgressRefusal::Dropped(DropReason::TcpEgressRefused)));
}

#[test]
fn tls_egress_refuses_every_other_source_port_and_destination() {
    let refused = Err(EgressRefusal::Dropped(DropReason::TcpEgressRefused));
    let ack = wire::TCP_ACK;
    assert_eq!(tls_egress(&CFG, &tcp_packet(PEER_IP, [10, 0, 2, 3], HTTPS, 40000, ack, b""), TX_ROOM), refused, "source not ours");
    assert_eq!(tls_egress(&CFG, &tcp_packet(CFG.ipv4, PEER_IP, HTTPS + 1, 40000, ack, b""), TX_ROOM), refused, "port");
    assert_eq!(tls_egress(&CFG, &tcp_packet(CFG.ipv4, CFG.ipv4, HTTPS, 40000, ack, b""), TX_ROOM), refused, "to us");
    for dst in [[0, 0, 0, 0], [255, 255, 255, 255], [224, 0, 0, 1], [239, 1, 2, 3], [127, 0, 0, 1], [240, 0, 0, 1]] {
        assert_eq!(tls_egress(&CFG, &tcp_packet(CFG.ipv4, dst, HTTPS, 40000, ack, b""), TX_ROOM), refused, "to {dst:?}");
    }
    assert!(tls_egress(&CFG, &tcp_packet(CFG.ipv4, [223, 255, 255, 254], HTTPS, 40000, ack, b""), TX_ROOM).is_ok());
}

#[test]
fn tls_egress_refuses_what_is_not_tcp_or_not_valid() {
    let mut udp = from_tls(wire::TCP_ACK);
    udp[9] = 17;
    udp[10..12].fill(0);
    let c = csum(&udp[..20], 0);
    udp[10..12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(tls_egress(&CFG, &udp, TX_ROOM), Err(EgressRefusal::Dropped(DropReason::TcpEgressRefused)));
    let mut bad = from_tls(wire::TCP_ACK);
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(tls_egress(&CFG, &bad, TX_ROOM), Err(EgressRefusal::Dropped(DropReason::TcpBadChecksum)));
    let mut bad_ip = from_tls(wire::TCP_ACK);
    bad_ip[8] ^= 1;
    assert_eq!(tls_egress(&CFG, &bad_ip, TX_ROOM), Err(EgressRefusal::Dropped(DropReason::Ipv4BadChecksum)));
}

#[test]
fn tls_egress_length_bound_is_1500_bytes() {
    let max = tcp_packet(CFG.ipv4, PEER_IP, HTTPS, 40000, wire::TCP_ACK, &[1; 1460]);
    assert_eq!(max.len(), 1500);
    assert!(tls_egress(&CFG, &max, TX_ROOM).is_ok());
    let mut over = max.clone();
    over.push(0);
    assert_eq!(tls_egress(&CFG, &over, TX_ROOM), Err(EgressRefusal::Dropped(DropReason::TooLong)));
}

#[test]
fn tls_egress_is_refused_at_its_tier_while_data_and_answers_still_pass() {
    let p = from_tls(wire::TCP_ACK);
    let edge = NET_BUFFERS / 2 + TLS_TX_SHARE;
    assert_eq!(tls_egress(&CFG, &p, edge), Err(EgressRefusal::TxReserve));
    assert!(tls_egress(&CFG, &p, edge + 1).is_ok());
    // At that level `hs`/`data` output (no tier) and Rosenpass answers and
    // unsolicited replies still have their buffers.
    assert!(rp_tx_allowed(TxTier::Answer, edge));
    assert!(rp_tx_allowed(TxTier::Unsolicited, edge));
}

/// M6 plan C13 (R2-S4): an abort's bare RST|ACK has no tier of its own; at
/// the TLS tier's edge it is refused like any other `tls` segment (the
/// RST-loss residual).
#[test]
fn a_bare_rst_ack_is_refused_at_the_tls_tier_edge() {
    let rst = tcp_packet(CFG.ipv4, PEER_IP, HTTPS, 40000, wire::TCP_RST | wire::TCP_ACK, b"");
    assert_eq!(tls_egress(&CFG, &rst, NET_BUFFERS / 2 + TLS_TX_SHARE), Err(EgressRefusal::TxReserve));
}

#[test]
fn a_bare_rst_ack_is_admitted_one_buffer_above_the_tls_tier_edge() {
    let rst = tcp_packet(CFG.ipv4, PEER_IP, HTTPS, 40000, wire::TCP_RST | wire::TCP_ACK, b"");
    assert!(tls_egress(&CFG, &rst, NET_BUFFERS / 2 + TLS_TX_SHARE + 1).is_ok());
}

#[test]
fn a_tls_segment_is_never_allowed_where_an_unsolicited_reply_is_refused() {
    for free in 0..=NET_BUFFERS {
        assert!(!rp_tx_allowed(TxTier::Tls, free) || rp_tx_allowed(TxTier::Unsolicited, free), "free {free}");
    }
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

/// The Rosenpass cookie secret, scripted: whether a cookie is valid (and
/// how often that was asked), whether sealing and rotation succeed.
struct FakeCookie {
    valid: bool,
    valid_calls: Cell<usize>,
    seals: usize,
    rotate_ok: bool,
    clears: usize,
}

impl FakeCookie {
    fn invalid() -> Self {
        Self { valid: false, valid_calls: Cell::new(0), seals: 0, rotate_ok: true, clears: 0 }
    }

    fn valid() -> Self {
        Self { valid: true, ..Self::invalid() }
    }
}

impl RpCookieCheck for FakeCookie {
    fn valid(&self, _src: Endpoint, _msg: &[u8; RP_INIT_HELLO_LEN]) -> bool {
        self.valid_calls.set(self.valid_calls.get() + 1);
        self.valid
    }

    fn seal(&mut self, _src: Endpoint, _msg: &[u8; RP_INIT_HELLO_LEN], out: &mut [u8; RP_COOKIE_REPLY_LEN]) -> bool {
        self.seals += 1;
        out[0] = 0x86;
        true
    }

    fn rotate(&mut self) -> bool {
        self.rotate_ok
    }

    fn clear(&mut self) {
        self.clears += 1;
    }
}

/// A gate whose cookie secret was born at time 0.
fn armed() -> RpGate<8> {
    let mut g = RpGate::default();
    assert!(g.tick_if_due(&mut FakeCookie::valid(), 0).rotated);
    g
}

fn rp_with<'a>(g: &mut RpGate<8>, cookie: &mut FakeCookie, now: u64, tx_free: usize, from: Endpoint, payload: &'a [u8]) -> RpOutcome<'a> {
    rp_classify(g, &FakeRpMac::default(), cookie, now, tx_free, from, payload, &mut [0u8; RP_COOKIE_REPLY_LEN])
}

/// Classifies `payload` with a cookie that never validates and room on TX.
fn rp<'a>(gate: &mut RpGate<8>, now: u64, from: Endpoint, payload: &'a [u8]) -> RpOutcome<'a> {
    rp_with(gate, &mut FakeCookie::invalid(), now, TX_FREE, from, payload)
}

/// With a cookie that validates.
fn rp_cookied<'a>(gate: &mut RpGate<8>, now: u64, from: Endpoint, payload: &'a [u8]) -> RpOutcome<'a> {
    rp_with(gate, &mut FakeCookie::valid(), now, TX_FREE, from, payload)
}

fn forwarded(o: RpOutcome<'_>) -> bool {
    matches!(o, RpOutcome::ForwardHello { .. } | RpOutcome::ForwardConf { .. })
}

/// An InitHello with a nonzero cookie field (the all-zero field is invalid
/// without hashing).
fn hello_with_cookie() -> Vec<u8> {
    let mut m = hello();
    m[RP_COOKIE_AT] = 0xc0;
    m
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
    let mut g = armed();
    let (h, c) = (hello(), conf());
    let RpOutcome::ForwardHello { src: s, msg, cookied: false } = rp(&mut g, 0, SRC, &h) else { panic!("hello not forwarded") };
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
    let mut g = armed();
    let before = g.clone();
    let mac = FakeRpMac::default();
    for m in &cases {
        let o = rp_classify(&mut g, &mac, &mut FakeCookie::valid(), 0, TX_FREE, SRC, m, &mut [0u8; RP_COOKIE_REPLY_LEN]);
        assert_eq!(o, RpOutcome::TypeDropped, "len {}", m.len());
    }
    assert_eq!(mac.calls.get(), 0);
    assert_eq!(g, before);
}

#[test]
fn a_bad_mac_is_refused_and_spends_nothing() {
    let mut g = armed();
    let before = g.clone();
    for _ in 0..100 {
        assert_eq!(rp(&mut g, 0, SRC, &rp_msg(RP_MSG_INIT_HELLO, RP_INIT_HELLO_LEN, false)), RpOutcome::BadMac);
        assert_eq!(rp(&mut g, 0, SRC, &rp_msg(RP_MSG_INIT_CONF, RP_INIT_CONF_LEN, false)), RpOutcome::BadMac);
    }
    assert_eq!(g, before);
    assert!(forwarded(rp(&mut g, 0, SRC, &hello())));
}

/// Classifies `msg` without sending it: nothing is recorded in flight
/// (only `sent` does that), so only the meters decide.
fn rp_drained<'a>(g: &mut RpGate<8>, now: u64, from: Endpoint, msg: &'a [u8]) -> RpOutcome<'a> {
    rp(g, now, from, msg)
}

// -- the off-load lane (M3a's meters) and the load trigger --

#[test]
fn a_source_over_its_hello_burst_is_refused_and_that_engages_the_gate() {
    // S-3: the victim's own InitHello finds its per-IP token spent.
    let mut g = armed();
    let h = hello();
    for _ in 0..RP_HELLO_SRC_BURST {
        assert!(forwarded(rp_drained(&mut g, 0, SRC, &h)));
    }
    assert!(!g.take_load_entered(), "a forward is no trigger");
    assert_eq!(rp_drained(&mut g, 0, SRC, &h), RpOutcome::RateLimited);
    assert!(g.take_load_entered(), "the refusal engages the gate");
    // Now another source needs a cookie too.
    assert!(matches!(rp_drained(&mut g, 0, src(9), &h), RpOutcome::CookieReply { .. }));
}

#[test]
fn draining_the_global_hello_meter_engages_the_gate() {
    // From distinct sources (no per-IP refusal): off load the unproven
    // floor is reached at half the burst, and that refusal is the trigger.
    let mut g = armed();
    let h = hello();
    for i in 0..(RP_HELLO_GLOBAL_BURST - RP_HELLO_PROVEN_RESERVE) as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &h)), "source {i}");
    }
    assert!(!g.take_load_entered());
    assert_eq!(rp_drained(&mut g, 0, src(100), &h), RpOutcome::RateLimited);
    assert!(g.take_load_entered());
    assert!(matches!(rp_drained(&mut g, 0, src(101), &h), RpOutcome::CookieReply { .. }));
}

#[test]
fn the_global_hello_meter_below_half_holds_the_gate_on_its_own() {
    // Past the hold deadline, a meter below half still holds the gate at
    // the tick; once it has refilled to half and the hold has run out, the
    // gate clears.
    let mut g = loaded();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    prove(&mut g, e, 0, 1);
    drain_global_to(&mut g, 1, RP_HELLO_PROVEN_RESERVE);
    assert!(forwarded(rp_cookied(&mut g, 1, e, &hello_with_cookie())), "a proven spend below the reserve");
    assert!(g.hello_global.below_half(1));
    g.under_load_until_ns = 0;
    assert!(!g.tick_if_due(&mut FakeCookie::valid(), 1).left_load, "below half holds");
    // Refilled to half by `refilled`, and the hold renewed at 1 runs out.
    let refilled = 1 + RP_HELLO_GLOBAL_INTERVAL_NS;
    let clear = (1 + RP_UNDER_LOAD_AFTER_NS).max(refilled);
    assert!(!g.hello_global.below_half(clear));
    assert!(g.tick_if_due(&mut FakeCookie::valid(), clear).left_load);
}

#[test]
fn load_holds_for_rp_under_load_after_ns_after_its_last_trigger() {
    let mut g = armed();
    let h = hello();
    rp_drained(&mut g, 0, SRC, &h);
    assert_eq!(rp_drained(&mut g, 0, SRC, &h), RpOutcome::RateLimited); // trigger at 0
    let t = RP_UNDER_LOAD_AFTER_NS;
    assert!(!g.tick_if_due(&mut FakeCookie::valid(), t - 1).left_load);
    let r = g.tick_if_due(&mut FakeCookie::valid(), t);
    assert!(r.left_load, "load clears at exactly the hold");
    assert!(forwarded(rp_drained(&mut g, t, src(7), &h)), "off load again: no cookie needed");
}

#[test]
fn a_source_over_its_conf_burst_is_rate_limited_then_refills() {
    let mut g = armed();
    let c = conf();
    for _ in 0..RP_CONF_SRC_BURST {
        assert!(forwarded(rp_drained(&mut g, 0, SRC, &c)));
    }
    assert_eq!(rp_drained(&mut g, 0, SRC, &c), RpOutcome::RateLimited);
    assert!(forwarded(rp_drained(&mut g, 0, src(9), &c)));
    assert!(forwarded(rp_drained(&mut g, RP_CONF_SRC_INTERVAL_NS, SRC, &c)));
}

#[test]
fn unmatched_confs_stop_at_the_awaited_reserve_of_the_global_meter() {
    let mut g = armed();
    let c = conf();
    let open = RP_CONF_GLOBAL_BURST - RP_CONF_AWAITED_RESERVED as u64;
    for i in 0..open as u8 {
        assert!(forwarded(rp_drained(&mut g, 0, src(i), &c)), "source {i}");
    }
    // The last unmatched forward above found RESERVED + 1 tokens; this one
    // finds RESERVED and is refused without spending.
    assert_eq!(g.conf_global.tokens(0), RP_CONF_AWAITED_RESERVED as u64);
    assert_eq!(rp_drained(&mut g, 0, src(100), &c), RpOutcome::RateLimited, "the reserve");
    assert_eq!(g.conf_global.tokens(0), RP_CONF_AWAITED_RESERVED as u64);
    assert!(forwarded(rp_drained(&mut g, RP_CONF_GLOBAL_INTERVAL_NS, src(101), &c)));
}

#[test]
fn hello_and_conf_meters_are_separate() {
    let mut g = armed();
    let c = conf();
    for i in 0..=RP_HELLO_GLOBAL_BURST as u8 {
        rp_cookied(&mut g, 0, src(i), &hello_with_cookie());
    }
    assert!(rp_cookied(&mut g, 0, src(50), &hello_with_cookie()) == RpOutcome::RateLimited);
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

/// A gate under load (engaged by a per-IP refusal at time 0).
fn loaded() -> RpGate<8> {
    let mut g = armed();
    rp_drained(&mut g, 0, src(200), &hello());
    assert_eq!(rp_drained(&mut g, 0, src(200), &hello()), RpOutcome::RateLimited);
    g
}

// -- I1, I2: the cookie under load, and never off load --

#[test]
fn under_load_an_init_hello_without_a_valid_cookie_spends_nothing() {
    let mut g = loaded();
    let before = g.clone();
    let mut cookie = FakeCookie::invalid();
    let m = hello_with_cookie();
    for i in 0..50u8 {
        let o = rp_with(&mut g, &mut cookie, 1, TX_FREE, src(i), &m);
        assert_eq!(o, RpOutcome::CookieReply { dst: src(i) });
    }
    assert_eq!(cookie.seals, 50);
    // No meter, nothing in flight, and the load deadline unmoved.
    assert_eq!(g, before);
    // The allow side: a valid cookie is forwarded.
    assert!(forwarded(rp_cookied(&mut g, 1, src(9), &hello_with_cookie())));
}

#[test]
fn an_old_clients_uncookied_retransmits_do_not_hold_the_gate() {
    let mut g = loaded();
    let mut cookie = FakeCookie::invalid();
    let m = hello();
    let last = RP_UNDER_LOAD_AFTER_NS - 1;
    assert!(matches!(rp_with(&mut g, &mut cookie, last, TX_FREE, SRC, &m), RpOutcome::CookieReply { .. }));
    let o = rp_with(&mut g, &mut cookie, RP_UNDER_LOAD_AFTER_NS, TX_FREE, SRC, &m);
    assert!(forwarded(o), "load did not clear: {o:?}");
}

#[test]
fn a_spoofer_at_the_source_rate_gets_one_init_hello_to_pq_per_clearance() {
    // Load engaged at 0; one uncookied InitHello per 20 s for 10 minutes.
    let mut g = loaded();
    let m = hello();
    let span = 600_000_000_000;
    let mut forwards = Vec::new();
    let mut at = RP_HELLO_SRC_INTERVAL_NS;
    while at <= span {
        if forwarded(rp(&mut g, at, SRC, &m)) {
            forwards.push(at);
        }
        at += RP_HELLO_SRC_INTERVAL_NS;
    }
    // Without the probe re-arming load, every spoof from 60 s on would be
    // forwarded (one per source period).
    assert!(forwards.len() as u64 <= span / RP_UNDER_LOAD_AFTER_NS, "{forwards:?}");
    assert!(forwards.windows(2).all(|w| w[1] - w[0] >= RP_UNDER_LOAD_AFTER_NS), "{forwards:?}");
    // The allow side: each clearance still lets one through (VE13).
    assert!(!forwards.is_empty());
}

#[test]
fn before_any_load_an_uncookied_forward_does_not_arm_the_gate() {
    let mut g = armed();
    assert!(forwarded(rp(&mut g, 1, SRC, &hello())));
    assert!(!g.take_load_entered());
}

#[test]
fn an_uncookied_forward_past_the_probe_window_does_not_rearm_the_gate() {
    let mut g = loaded();
    let past = RP_UNDER_LOAD_AFTER_NS + RP_LEGACY_PROBE_NS;
    assert!(g.take_load_entered());
    g.tick_if_due(&mut FakeCookie::invalid(), past);
    assert!(forwarded(rp(&mut g, past, SRC, &hello())));
    assert!(!g.take_load_entered(), "re-armed past the window");
    // One ns earlier it would have.
    let mut g = loaded();
    g.take_load_entered();
    g.tick_if_due(&mut FakeCookie::invalid(), past - 1);
    assert!(forwarded(rp(&mut g, past - 1, SRC, &hello())));
    assert!(g.take_load_entered(), "the probe did not re-arm");
}

#[test]
fn off_load_the_cookie_is_never_asked() {
    let mut g = armed();
    let cookie = FakeCookie::valid();
    let mut cookie = cookie;
    assert!(forwarded(rp_with(&mut g, &mut cookie, 0, TX_FREE, SRC, &hello_with_cookie())));
    assert_eq!(cookie.valid_calls.get(), 0);
    // Under load it is asked exactly once.
    let mut g = loaded();
    let mut cookie = FakeCookie::valid();
    assert!(forwarded(rp_with(&mut g, &mut cookie, 1, TX_FREE, SRC, &hello_with_cookie())));
    assert_eq!(cookie.valid_calls.get(), 1);
}

#[test]
fn an_all_zero_cookie_field_is_invalid_without_asking() {
    let mut g = loaded();
    let mut cookie = FakeCookie::valid();
    assert!(matches!(rp_with(&mut g, &mut cookie, 1, TX_FREE, SRC, &hello()), RpOutcome::CookieReply { .. }));
    assert_eq!(cookie.valid_calls.get(), 0);
}

#[test]
fn without_a_secret_or_past_its_age_no_cookie_is_valid_or_sent() {
    // T17: missing secret.
    let mut g = RpGate::<8>::default();
    rp_drained(&mut g, 0, src(200), &hello());
    rp_drained(&mut g, 0, src(200), &hello());
    let mut cookie = FakeCookie::valid();
    assert_eq!(rp_with(&mut g, &mut cookie, 1, TX_FREE, SRC, &hello_with_cookie()), RpOutcome::NoCookieSecret);
    assert_eq!(cookie.valid_calls.get(), 0);
    // Expired: the backstop, its edge raised once.
    let mut g = loaded();
    let at = COOKIE_SECRET_MAX_AGE_NS;
    g.refresh_load(at);
    assert_eq!(rp_with(&mut g, &mut FakeCookie::valid(), at, TX_FREE, SRC, &hello_with_cookie()), RpOutcome::CookieSecretExpired);
    assert!(g.take_expired());
    assert_eq!(rp_with(&mut g, &mut FakeCookie::valid(), at, TX_FREE, SRC, &hello_with_cookie()), RpOutcome::CookieSecretExpired);
    assert!(!g.take_expired(), "the edge is raised once");
    // The allow side: one ns before the age, a valid cookie forwards.
    let mut g = loaded();
    assert!(forwarded(rp_cookied(&mut g, at - 1, SRC, &hello_with_cookie())));
}

#[test]
fn a_cookie_reply_takes_only_an_unsolicited_tx_buffer() {
    let mut g = loaded();
    let edge = NET_BUFFERS / 2 + RP_ANSWER_SHARE;
    assert_eq!(rp_with(&mut g, &mut FakeCookie::invalid(), 1, edge, SRC, &hello_with_cookie()), RpOutcome::CookieSuppressed);
    assert!(matches!(rp_with(&mut g, &mut FakeCookie::invalid(), 1, edge + 1, SRC, &hello_with_cookie()), RpOutcome::CookieReply { .. }));
}

// -- F3: peers behind one address --

#[test]
fn every_peer_behind_one_address_gets_through_with_its_cookie() {
    // All at once, as after a reboot: the per-IP cap admits every
    // configured peer behind one address and refuses one more. The global
    // meter is refilled before each try so only the cap decides.
    let mut g = loaded();
    for port in 0..RP_MAX_PEERS as u16 {
        let ep = Endpoint { ip: [192, 0, 2, 7], port: 50000 + port };
        g.hello_global = Meter::full_at(1);
        assert!(forwarded(rp_cookied(&mut g, 1, ep, &hello_with_cookie())), "peer {port}");
    }
    g.hello_global = Meter::full_at(1);
    let one_more = Endpoint { ip: [192, 0, 2, 7], port: 50100 };
    assert_eq!(rp_cookied(&mut g, 1, one_more, &hello_with_cookie()), RpOutcome::RateLimited, "the per-IP cap");
    // Another address is not affected.
    assert!(forwarded(rp_cookied(&mut g, 1, src(9), &hello_with_cookie())));
}

#[test]
fn the_cookied_lane_does_not_share_the_off_load_per_ip_token() {
    // The off-load token of the address is spent, yet a cookied endpoint
    // behind it starts with its own per-endpoint meter (F13).
    let mut g = loaded();
    assert!(forwarded(rp_cookied(&mut g, 1, src(200), &hello_with_cookie())));
}

// -- I3: the proven reserve --

/// Drains the global meter with cookied InitHellos from distinct addresses
/// until `left` tokens remain.
fn drain_global_to(g: &mut RpGate<8>, now: u64, left: u64) {
    let mut i = 0u8;
    while g.hello_global.tokens(now) > left {
        assert!(forwarded(rp_cookied(g, now, Endpoint { ip: [198, 51, 100, i], port: 1 }, &hello_with_cookie())));
        i += 1;
    }
}

fn prove(g: &mut RpGate<8>, ep: Endpoint, peer: u8, now: u64) {
    let sidi = [1, 2, 3, peer];
    let sidr = [9, 9, 9, peer];
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&sidr);
    resp[8..12].copy_from_slice(&sidi);
    g.replied(RpKind::Hello, ep, None, &resp, now);
    let mut c = conf();
    c[4..8].copy_from_slice(&sidi);
    c[8..12].copy_from_slice(&sidr);
    assert!(forwarded(rp(g, now, ep, &c)), "the matched InitConf");
    let mut empty = std::vec![0x84u8; RP_EMPTY_DATA_LEN];
    empty[4..8].copy_from_slice(&sidi);
    g.replied(RpKind::Conf, ep, Some(peer), &empty, now);
    assert!(g.proven_slot(ep, now).is_some(), "proven");
}

#[test]
fn an_unproven_endpoint_stops_at_the_reserve_and_a_proven_one_goes_on() {
    let mut g = loaded();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    prove(&mut g, e, 0, 1);
    drain_global_to(&mut g, 1, RP_HELLO_PROVEN_RESERVE + 1);
    // At 5 tokens an unproven endpoint still passes (the boundary + 1)...
    assert!(forwarded(rp_cookied(&mut g, 1, src(1), &hello_with_cookie())));
    // ...at exactly the reserve it is refused.
    assert_eq!(rp_cookied(&mut g, 1, src(2), &hello_with_cookie()), RpOutcome::RateLimited);
    // The proven endpoint takes a reserved token, within its credit.
    assert!(forwarded(rp_cookied(&mut g, 1, e, &hello_with_cookie())));
}

#[test]
fn a_proven_endpoint_stops_at_the_reserve_once_its_credit_is_spent() {
    let mut g = loaded();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    prove(&mut g, e, 0, 1);
    let mut t = 1;
    for _ in 0..RP_PROVEN_CREDIT_BURST {
        drain_global_to(&mut g, t, RP_HELLO_PROVEN_RESERVE);
        assert!(forwarded(rp_cookied(&mut g, t, e, &hello_with_cookie())));
        // Past the per-endpoint interval, so only the credit decides.
        t += RP_HELLO_SRC_INTERVAL_NS;
    }
    drain_global_to(&mut g, t, RP_HELLO_PROVEN_RESERVE);
    assert_eq!(rp_cookied(&mut g, t, e, &hello_with_cookie()), RpOutcome::RateLimited, "credit spent");
}

#[test]
fn proven_priority_needs_the_cookie() {
    // Off load (no cookie) a proven endpoint is treated as unproven: the
    // endpoint alone proves nothing.
    let mut g = armed();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    prove(&mut g, e, 0, 0);
    assert!(g.admit_hello(false, 0, e).is_ok());
    let mut g2 = armed();
    prove(&mut g2, e, 0, 0);
    g2.hello_global = Meter::full_at(0);
    for _ in 0..(RP_HELLO_GLOBAL_BURST - RP_HELLO_PROVEN_RESERVE) {
        g2.hello_global.allow(0);
    }
    assert_eq!(g2.admit_hello(false, 0, e), Err(RpOutcome::RateLimited));
}

// -- I6: proven only through the session ids --

#[test]
fn a_replayed_init_conf_from_a_spoofed_endpoint_proves_nobody() {
    let mut g = loaded();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    let x = Endpoint { ip: [198, 18, 0, 1], port: 666 };
    // While E's own EmptyData is still owed, its awaited entry is live and
    // seen: only the endpoint check keeps X's EmptyData from claiming it.
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&[9; 4]);
    resp[8..12].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Hello, e, None, &resp, 1);
    let mut c = conf();
    c[4..8].copy_from_slice(&[1; 4]);
    c[8..12].copy_from_slice(&[9; 4]);
    assert!(forwarded(rp(&mut g, 1, e, &c)));
    let mut owed = std::vec![0x84u8; RP_EMPTY_DATA_LEN];
    owed[4..8].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Conf, x, Some(1), &owed, 2);
    assert!(g.proven_slot(x, 2).is_none(), "X claimed E's awaited entry");
    g.replied(RpKind::Conf, e, Some(1), &owed, 2);
    assert!(g.proven_slot(e, 2).is_some(), "E's own EmptyData no longer proves it");
    // After E is proven, a cache replay to X proves nobody either.
    let mut g = loaded();
    prove(&mut g, e, 0, 1);
    // `pq`'s cache answers the replay from X with the same EmptyData.
    let mut empty = std::vec![0x84u8; RP_EMPTY_DATA_LEN];
    empty[4..8].copy_from_slice(&[1, 2, 3, 0]);
    g.replied(RpKind::Conf, x, Some(0), &empty, 2);
    assert!(g.proven_slot(x, 2).is_none(), "X has no awaited entry with E's ids");
    assert!(g.proven_slot(e, 2).is_some(), "E stays proven");
}

#[test]
fn an_empty_data_after_a_suppressed_one_still_proves() {
    // The matched InitConf was forwarded; the first EmptyData never went
    // out (no `replied`), the retransmission's did.
    let mut g = loaded();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&[9; 4]);
    resp[8..12].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Hello, e, None, &resp, 1);
    let mut c = conf();
    c[4..8].copy_from_slice(&[1; 4]);
    c[8..12].copy_from_slice(&[9; 4]);
    assert!(forwarded(rp(&mut g, 1, e, &c)));
    assert!(forwarded(rp(&mut g, 1 + RP_CONF_SRC_INTERVAL_NS, e, &c)), "the retransmission");
    let mut empty = std::vec![0x84u8; RP_EMPTY_DATA_LEN];
    empty[4..8].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Conf, e, Some(3), &empty, 2);
    assert!(g.proven_slot(e, 2).is_some());
}

#[test]
fn an_index_out_of_range_or_another_peer_changes_no_slot() {
    let mut g = loaded();
    let e0 = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    let e1 = Endpoint { ip: [203, 0, 113, 6], port: 7000 };
    prove(&mut g, e0, 0, 1);
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&[8; 4]);
    resp[8..12].copy_from_slice(&[7; 4]);
    g.replied(RpKind::Hello, e1, None, &resp, 1);
    let mut c = conf();
    c[4..8].copy_from_slice(&[7; 4]);
    c[8..12].copy_from_slice(&[8; 4]);
    assert!(forwarded(rp(&mut g, 1, e1, &c)));
    let mut empty = std::vec![0x84u8; RP_EMPTY_DATA_LEN];
    empty[4..8].copy_from_slice(&[7; 4]);
    let before = g.proven;
    g.replied(RpKind::Conf, e1, Some(RP_MAX_PEERS as u8), &empty, 2);
    assert_eq!(g.proven, before, "index out of range");
    // Peer 1's EmptyData lands in slot 1 only; slot 0 keeps e0.
    g.replied(RpKind::Conf, e1, Some(1), &empty, 2);
    assert_eq!(g.proven[0].map(|p| p.ep), Some(e0));
    assert_eq!(g.proven[1].map(|p| p.ep), Some(e1));
}

#[test]
fn a_full_awaited_table_records_nothing_and_never_evicts_a_live_entry() {
    let mut g = loaded();
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    for i in 0..RP_AWAIT_SLOTS as u8 {
        resp[4..8].copy_from_slice(&[i; 4]);
        g.replied(RpKind::Hello, src(i), None, &resp, 1);
    }
    let before = g.awaited;
    resp[4..8].copy_from_slice(&[0xee; 4]);
    g.replied(RpKind::Hello, src(0xee), None, &resp, 1);
    assert_eq!(g.awaited, before);
    // Once the entries age out, a slot is free again.
    g.replied(RpKind::Hello, src(0xee), None, &resp, 1 + RP_AWAIT_CONF_NS);
    assert!(g.awaited.iter().any(|a| a.is_some_and(|a| a.ep == src(0xee))));
}

// -- I5: the awaited reserve on the link --

#[test]
fn only_a_matched_init_conf_takes_a_reserved_slot_one_per_endpoint() {
    let mut g = armed();
    let mut t = 0;
    let open = RP_CONF_IN_FLIGHT - RP_CONF_AWAITED_RESERVED;
    for i in 0..open as u8 {
        t += METERS_REFILLED;
        assert!(forwarded(rp(&mut g, t, src(i), &conf())));
        g.sent(RpKind::Conf, src(i));
    }
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, src(50), &conf()), RpOutcome::RingReserved, "unmatched: the reserve");
    // A matched one takes a reserved slot...
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&[9; 4]);
    resp[8..12].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Hello, e, None, &resp, t);
    let mut c = conf();
    c[4..8].copy_from_slice(&[1; 4]);
    c[8..12].copy_from_slice(&[9; 4]);
    assert!(forwarded(rp(&mut g, t, e, &c)));
    g.sent(RpKind::Conf, e);
    // ...but not a second one while its first is in flight.
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, e, &c), RpOutcome::RingReserved);
    // A wrong sidr does not match.
    let mut wrong = c.clone();
    wrong[8] ^= 1;
    let f = Endpoint { ip: [203, 0, 113, 6], port: 7000 };
    assert_eq!(rp(&mut g, t, f, &wrong), RpOutcome::RingReserved);
}

#[test]
fn a_matched_entry_forwards_at_most_its_budget() {
    let mut g = armed();
    let e = Endpoint { ip: [203, 0, 113, 5], port: 7000 };
    let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
    resp[4..8].copy_from_slice(&[9; 4]);
    resp[8..12].copy_from_slice(&[1; 4]);
    g.replied(RpKind::Hello, e, None, &resp, 0);
    let i = g.awaited.iter().position(|a| a.is_some_and(|a| a.ep == e)).unwrap();
    let mut c = conf();
    c[4..8].copy_from_slice(&[1; 4]);
    c[8..12].copy_from_slice(&[9; 4]);
    let mut t = 0;
    for _ in 0..RP_CONF_SRC_BURST {
        // Within the awaited window; the per-source meter refills.
        t += RP_CONF_SRC_INTERVAL_NS;
        assert!(forwarded(rp(&mut g, t, e, &c)));
    }
    assert_eq!(g.awaited[i].unwrap().conf_budget, 0);
    // The budget spent, the next one is unmatched and takes only open slots.
    t += RP_CONF_SRC_INTERVAL_NS;
    assert!(forwarded(rp(&mut g, t, e, &c)));
    assert_eq!(g.awaited[i].unwrap().conf_budget, 0);
}

// -- I8: TX tiers --

#[test]
fn an_answer_is_allowed_wherever_an_unsolicited_reply_is() {
    let reserve = NET_BUFFERS / 2;
    assert!(!rp_tx_allowed(TxTier::Answer, reserve));
    assert!(rp_tx_allowed(TxTier::Answer, reserve + 1));
    assert!(!rp_tx_allowed(TxTier::Unsolicited, reserve + RP_ANSWER_SHARE));
    assert!(rp_tx_allowed(TxTier::Unsolicited, reserve + RP_ANSWER_SHARE + 1));
    for free in 0..=NET_BUFFERS {
        assert!(!rp_tx_allowed(TxTier::Unsolicited, free) || rp_tx_allowed(TxTier::Answer, free));
    }
}

#[test]
fn a_failed_rotation_clears_both_secrets_and_reports_once() {
    let mut g = RpGate::<8>::default();
    let mut c = FakeCookie::valid();
    c.rotate_ok = false;
    let r = g.tick_if_due(&mut c, 0);
    assert!(r.secret_unavailable && !r.rotated);
    assert_eq!(c.clears, 1);
    let r = g.tick_if_due(&mut c, RETRY_INTERVAL_NS);
    assert!(!r.secret_unavailable, "reported once");
    c.rotate_ok = true;
    assert!(g.tick_if_due(&mut c, 2 * RETRY_INTERVAL_NS).rotated);
}

/// Forwards `n` messages of one kind from `from`, spaced so every meter has
/// refilled (only the ring can refuse), and records each as sent.
fn fill_from(g: &mut RpGate<8>, t: &mut u64, from: Endpoint, msg: &[u8], n: usize) {
    for _ in 0..n {
        *t += METERS_REFILLED;
        let o = rp(g, *t, from, msg);
        let kind = match o {
            RpOutcome::ForwardHello { .. } => RpKind::Hello,
            RpOutcome::ForwardConf { .. } => RpKind::Conf,
            _ => panic!("refused at {:?}: {o:?}", (g.in_flight(RpKind::Hello), g.in_flight(RpKind::Conf))),
        };
        g.sent(kind, from);
    }
}

fn fill(g: &mut RpGate<8>, t: &mut u64, msg: &[u8], n: usize) {
    fill_from(g, t, SRC, msg, n);
}

/// Fills every InitConf slot: the open share with unmatched InitConfs from
/// one source, the reserve with matched ones from distinct awaited
/// endpoints (one reserved slot each).
fn fill_confs(g: &mut RpGate<8>, t: &mut u64) {
    fill(g, t, &conf(), RP_CONF_IN_FLIGHT - RP_CONF_AWAITED_RESERVED);
    for i in 0..RP_CONF_AWAITED_RESERVED as u8 {
        let ep = Endpoint { ip: [203, 0, 113, i], port: 7000 };
        let mut resp = std::vec![0x82u8; RP_RESP_HELLO_LEN];
        resp[4..8].copy_from_slice(&[0x90 + i; 4]);
        resp[8..12].copy_from_slice(&[0x10 + i; 4]);
        *t += METERS_REFILLED;
        g.replied(RpKind::Hello, ep, None, &resp, *t);
        let mut c = conf();
        c[4..8].copy_from_slice(&[0x10 + i; 4]);
        c[8..12].copy_from_slice(&[0x90 + i; 4]);
        fill_from(g, t, ep, &c, 1);
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
fn init_conf_cannot_take_init_hello_slots() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill_confs(&mut g, &mut t);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &conf()), RpOutcome::RingReserved, "conf past its slots");
    fill(&mut g, &mut t, &hello(), RP_HELLO_IN_FLIGHT);
}

#[test]
fn an_init_hello_flood_leaves_the_init_conf_slots_free() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &hello(), RP_HELLO_IN_FLIGHT);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &hello()), RpOutcome::RingReserved, "hello past its slots");
    fill_confs(&mut g, &mut t);
}

#[test]
fn the_hello_being_processed_counts_against_the_cap() {
    // S14: `pq` holds the buffer of the InitHello it is working on, so one
    // processing and one queued fill a cap of two.
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &hello(), 1); // `pq` took this one and holds it
    fill(&mut g, &mut t, &hello(), 1); // queued behind it
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &hello()), RpOutcome::RingReserved);
    assert_eq!(g.in_flight(RpKind::Hello), RP_HELLO_IN_FLIGHT);
}

#[test]
fn the_link_holds_rp_in_flight_and_no_more() {
    let mut g = RpGate::default();
    let mut t = 0;
    fill(&mut g, &mut t, &hello(), RP_HELLO_IN_FLIGHT);
    fill_confs(&mut g, &mut t);
    assert_eq!(g.in_flight(RpKind::Hello) + g.in_flight(RpKind::Conf), RP_IN_FLIGHT);
    t += METERS_REFILLED;
    assert_eq!(rp(&mut g, t, SRC, &hello()), RpOutcome::RingReserved);
    assert_eq!(rp(&mut g, t, SRC, &conf()), RpOutcome::RingReserved);
    assert!(!g.pq_dead());
    // A forward recorded past the capacity cannot be paired: the path stops.
    g.sent(RpKind::Conf, SRC);
    assert!(g.pq_dead());
}

#[test]
fn a_ring_refusal_spends_no_meter() {
    let mut g = armed();
    let mut t = 0;
    fill_confs(&mut g, &mut t);
    let before = g.clone();
    assert_eq!(rp(&mut g, t, src(77), &conf()), RpOutcome::RingReserved);
    assert_eq!(g, before);
}

#[test]
fn a_forward_is_counted_only_once_sent() {
    // A failed send leaves no entry: classification alone records nothing.
    let mut g = RpGate::default();
    assert!(forwarded(rp(&mut g, 0, SRC, &hello())));
    assert_eq!(g.in_flight(RpKind::Hello), 0);
    g.sent(RpKind::Hello, SRC);
    assert_eq!(g.in_flight(RpKind::Hello), 1);
}

// ---- the completion protocol (M3b plan C2, I9a-I9c) ----

const E1: Endpoint = Endpoint { ip: [10, 0, 3, 1], port: 41001 };
const E2: Endpoint = Endpoint { ip: [10, 0, 3, 2], port: 41002 };
const PEERS: usize = 3;

fn record(r: msgs::RpReply<'_>) -> Vec<u8> {
    let mut out = [0u8; RP_RECORD_MAX];
    let n = r.encode(&mut out).unwrap();
    out[..n].to_vec()
}

fn resp_hello_record(tag: u8) -> Vec<u8> {
    let msg = [tag; RP_RESP_HELLO_LEN];
    record(msgs::RpReply::Reply { index: msgs::RP_NO_PEER, msg: &msg })
}

fn empty_data_record(index: u8) -> Vec<u8> {
    let msg = [0x84; RP_EMPTY_DATA_LEN];
    record(msgs::RpReply::Reply { index, msg: &msg })
}

fn no_reply_record() -> Vec<u8> {
    record(msgs::RpReply::NoReply)
}

/// The PD side of a sync, scripted: how many buffers `pq` still holds, the
/// records it queued, and what went out.
struct FakePq {
    outstanding: Option<usize>,
    records: std::collections::VecDeque<Option<Vec<u8>>>,
    tx_ok: bool,
    sent: Vec<(Endpoint, Vec<u8>)>,
    reads: usize,
}

impl FakePq {
    fn new(outstanding: usize, records: Vec<Vec<u8>>) -> Self {
        Self { outstanding: Some(outstanding), records: records.into_iter().map(Some).collect(), tx_ok: true, sent: Vec::new(), reads: 0 }
    }

    fn sent_to(&self) -> Vec<Endpoint> {
        self.sent.iter().map(|(e, _)| *e).collect()
    }
}

impl PqSync for FakePq {
    fn outstanding(&mut self) -> Option<usize> {
        self.outstanding
    }

    fn next_record(&mut self, out: &mut [u8; RP_RECORD_MAX]) -> Option<Option<usize>> {
        self.reads += 1;
        let r = self.records.pop_front()?;
        Some(r.and_then(|b| {
            out.get_mut(..b.len())?.copy_from_slice(&b);
            Some(b.len())
        }))
    }

    fn transmit(&mut self, dst: Endpoint, reply: &[u8]) -> bool {
        if self.tx_ok {
            self.sent.push((dst, reply.to_vec()));
        }
        self.tx_ok
    }
}

fn gate_with(forwards: &[(RpKind, Endpoint)]) -> RpGate<8> {
    let mut g = RpGate::default();
    for (k, e) in forwards {
        g.sent(*k, *e);
    }
    g
}

#[test]
fn records_drained_in_one_sync_are_paired_in_order() {
    // F16: `pq` answered two forwards before `ingress` synced once.
    let mut g = gate_with(&[(RpKind::Hello, E1), (RpKind::Hello, E2)]);
    let mut pq = FakePq::new(0, vec![resp_hello_record(1), resp_hello_record(2)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 2 });
    assert_eq!(pq.sent_to(), [E1, E2]);
    assert_eq!((pq.sent[0].1[0], pq.sent[1].1[0]), (1, 2));
    assert_eq!(g.in_flight(RpKind::Hello), 0);
}

#[test]
fn a_refused_request_does_not_take_the_next_reply() {
    // `pq` refused E1's InitHello (NoReply) and answered E2's: E2's reply
    // goes to E2, never to E1.
    let mut g = gate_with(&[(RpKind::Hello, E1), (RpKind::Hello, E2)]);
    let mut pq = FakePq::new(0, vec![no_reply_record(), resp_hello_record(2)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 1 });
    assert_eq!(pq.sent_to(), [E2]);
}

#[test]
fn a_reply_goes_to_the_stored_source_and_nowhere_else() {
    // T19: the EmptyData names peer 1, whose WireGuard endpoint is not E2;
    // only the forward's stored source is a destination.
    let peer_1_wireguard = Endpoint { ip: [192, 0, 2, 1], port: 51820 };
    assert_ne!(peer_1_wireguard, E2);
    let mut g = gate_with(&[(RpKind::Conf, E2)]);
    let mut pq = FakePq::new(0, vec![empty_data_record(1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 1 });
    assert_eq!(pq.sent_to(), [E2]);
}

#[test]
fn a_record_seen_before_its_return_is_retired_by_the_next_sync() {
    // The record is published before the return; a sync between the two
    // relays it and retires nothing, the next one retires it.
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(1, vec![resp_hello_record(1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 1 });
    assert_eq!(g.in_flight(RpKind::Hello), 1);
    pq.outstanding = Some(0);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 0 });
    assert_eq!(g.in_flight(RpKind::Hello), 0);
    assert_eq!(pq.sent_to(), [E1]);
}

#[test]
fn every_order_of_record_and_return_completes_the_forward() {
    // I9c: whenever the sync's snapshot, drain and retire fall relative to
    // `pq`'s "enqueue record j, then return j", record j is relayed once
    // and the forward is retired without the path dying.
    for sync_after in 0..3 {
        let mut g = gate_with(&[(RpKind::Hello, E1)]);
        let mut pq = FakePq::new(1, vec![]);
        // Events of an honest pq: 1 = record enqueued, 2 = buffer returned.
        for step in 1..=2 {
            if step == 1 {
                pq.records.push_back(Some(resp_hello_record(7)));
            } else {
                pq.outstanding = Some(0);
            }
            if step == sync_after {
                assert!(matches!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { .. }), "sync after step {step}");
            }
        }
        assert!(matches!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { .. }));
        assert_eq!(pq.sent_to(), [E1], "sync after step {sync_after}");
        assert_eq!(g.in_flight(RpKind::Hello), 0);
    }
}

#[test]
fn a_return_without_its_record_stops_the_path() {
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(0, vec![]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert!(g.pq_dead());
    // Nothing was guessed: the entry is still there.
    assert_eq!(g.in_flight(RpKind::Hello), 1);
}

#[test]
fn an_extra_or_duplicate_record_stops_the_path() {
    let mut g = RpGate::<8>::default();
    assert_eq!(sync_pq(&mut g, &mut FakePq::new(0, vec![no_reply_record()]), PEERS, 0), SyncOutcome::DiedNow);
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(0, vec![resp_hello_record(1), resp_hello_record(1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert_eq!(pq.sent_to(), [E1], "the duplicate was not relayed");
}

#[test]
fn a_reply_of_the_other_kind_stops_the_path() {
    let mut g = gate_with(&[(RpKind::Conf, E1)]);
    let mut pq = FakePq::new(0, vec![resp_hello_record(1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert!(pq.sent.is_empty());
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(0, vec![empty_data_record(0)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert!(pq.sent.is_empty());
}

#[test]
fn a_malformed_record_or_a_bad_index_stops_the_path() {
    let msg = [0u8; RP_RESP_HELLO_LEN];
    let cases: Vec<(RpKind, Option<Vec<u8>>)> = vec![
        (RpKind::Conf, Some(empty_data_record(PEERS as u8))), // index = peers
        (RpKind::Conf, Some(empty_data_record(msgs::RP_NO_PEER))),
        (RpKind::Hello, Some(record(msgs::RpReply::Reply { index: 0, msg: &msg }))),
        (RpKind::Hello, Some(vec![9])),
        (RpKind::Hello, None), // unreadable
    ];
    for (kind, r) in cases {
        let mut g = gate_with(&[(kind, E1)]);
        let mut pq = FakePq::new(0, vec![]);
        pq.records.push_back(r.clone());
        assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow, "{kind:?} {r:?}");
        assert!(pq.sent.is_empty());
    }
    // The allow side: the last configured peer's EmptyData is accepted.
    let mut g = gate_with(&[(RpKind::Conf, E1)]);
    let mut pq = FakePq::new(0, vec![empty_data_record(PEERS as u8 - 1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 1 });
}

#[test]
fn a_snapshot_above_the_fifo_or_a_link_error_stops_the_path() {
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    assert_eq!(sync_pq(&mut g, &mut FakePq::new(2, vec![]), PEERS, 0), SyncOutcome::DiedNow);
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(0, vec![]);
    pq.outstanding = None;
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    // The boundary: outstanding == len retires nothing and is fine.
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    assert_eq!(sync_pq(&mut g, &mut FakePq::new(1, vec![]), PEERS, 0), SyncOutcome::Synced { relayed: 0 });
}

#[test]
fn an_endless_record_stream_stops_the_path_within_the_drain_cap() {
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(0, (0..200).map(|_| no_reply_record()).collect());
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert!(pq.reads <= PASS_FRAMES + 1);
}

#[test]
fn a_reply_tx_refuses_still_spends_its_credit() {
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    let mut pq = FakePq::new(1, vec![resp_hello_record(1)]);
    pq.tx_ok = false;
    // Not a protocol violation: the record is consumed and nothing resent.
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Synced { relayed: 0 });
    assert!(!g.pq_dead());
    // A resent copy finds no waiting entry.
    pq.tx_ok = true;
    pq.records.push_back(Some(resp_hello_record(1)));
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::DiedNow);
    assert!(pq.sent.is_empty());
}

#[test]
fn a_dead_path_forwards_relays_and_retires_nothing() {
    let mut g = gate_with(&[(RpKind::Hello, E1)]);
    assert_eq!(sync_pq(&mut g, &mut FakePq::new(0, vec![]), PEERS, 0), SyncOutcome::DiedNow);
    // Sticky: an honest record later is not relayed, nothing is retired.
    let mut pq = FakePq::new(0, vec![resp_hello_record(1)]);
    assert_eq!(sync_pq(&mut g, &mut pq, PEERS, 0), SyncOutcome::Dead);
    assert!(pq.sent.is_empty() && pq.reads == 0);
    assert_eq!(g.in_flight(RpKind::Hello), 1);
    assert_eq!(rp(&mut g, METERS_REFILLED, src(5), &conf()), RpOutcome::PqDown);
    assert_eq!(rp(&mut g, METERS_REFILLED, src(6), &hello()), RpOutcome::PqDown);
}

#[test]
fn a_rosenpass_flood_leaves_the_wireguard_meters_untouched() {
    let mut r = Rig::idle();
    let mut g = RpGate::default();
    let h = hello();
    let f = udp_to(CFG.mac, CFG.ipv4, CFG.rp_port, &h);
    let mut limited = 0;
    for _ in 0..1000 {
        let o = respond(&CFG, &mut r.gate, &mut r.crypto, &FakeMac1, &mut r.buckets, &mut TcpGate::<4>::default(), 0, IDLE, TX_FREE, &f, &mut [0u8; wire::MAX_FRAME], &mut r.out);
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
    assert!(!rp_tx_allowed(TxTier::Answer, NET_BUFFERS / 2));
    assert!(rp_tx_allowed(TxTier::Answer, NET_BUFFERS / 2 + 1));
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
