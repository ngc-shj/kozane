//! Kani harnesses for `ingress-core`. Run with `cargo kani -p ingress-core`.

use core::cell::Cell;

use super::*;

struct AnyMac1;

impl Mac1 for AnyMac1 {
    fn verify(&self, _: &[u8; INITIATION_LEN]) -> bool {
        kani::any()
    }
}

const CFG: Config = Config {
    mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
    ipv4: [10, 0, 2, 15],
    router_mac: [0x52, 0x55, 10, 0, 2, 2],
    port: 51820,
    rp_port: 9999,
};

/// `respond` never panics and never claims more bytes than `out` holds;
/// invariant (e) holds for ARP replies too [code review S1].
#[kani::proof]
#[kani::unwind(66)]
fn respond_is_total_and_bounded() {
    let buf: [u8; 64] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 64);
    let tx_free: usize = kani::any();
    let mut out = [0u8; 64];
    let mut buckets = Buckets::<2>::default();
    let mut cookie = [0u8; COOKIE_REPLY_LEN];
    let o = respond(
        &CFG,
        &mut Gate::default(),
        &mut Stub::default(),
        &AnyMac1,
        &mut buckets,
        kani::any(),
        kani::any(),
        tx_free,
        buf.get(..len).unwrap_or(&[]),
        &mut out,
        &mut cookie,
    );
    if let Outcome::ArpReplied(n) = o {
        assert!(n <= out.len());
        // (e) The TX reserve.
        assert!(tx_free > NET_BUFFERS / 2);
    }
    kani::cover!(matches!(o, Outcome::ArpReplied(_)));
    kani::cover!(o == Outcome::ArpSuppressed);
    // A transport frame needs 74 bytes; `classify` covers it.
    kani::cover!(o == Outcome::NotForUs);
    kani::cover!(o == Outcome::NoService);
    kani::cover!(o == Outcome::Spoofed);
    kani::cover!(o == Outcome::BadMessage);
    kani::cover!(matches!(o, Outcome::Rosenpass { .. }));
}

/// Only an exactly-sized type-1 message with a valid mac1 and budget is
/// handed to `hs`; transport messages have at least header + tag.
#[kani::proof]
#[kani::unwind(150)]
fn classify_forwards_only_well_formed_messages() {
    let payload: [u8; INITIATION_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= payload.len());
    // An already exhausted bucket for this source makes RateLimited reachable.
    let mut buckets = Buckets::<2>::default();
    let src = Endpoint { ip: kani::any(), port: kani::any() };
    let now: u64 = kani::any();
    if kani::any() {
        for _ in 0..BURST {
            buckets.allow(src.ip, now);
        }
    }
    let mut out = [0u8; COOKIE_REPLY_LEN];
    let o = classify(
        &mut Gate::default(),
        &mut Stub::default(),
        &AnyMac1,
        &mut buckets,
        now,
        kani::any(),
        kani::any(),
        src,
        payload.get(..len).unwrap_or(&[]),
        &mut out,
    );
    match o {
        Outcome::Initiation { msg, .. } => assert!(len == INITIATION_LEN && msg[0] == MSG_INITIATION),
        Outcome::Transport { msg, .. } => assert!(msg.len() >= TRANSPORT_MIN_LEN && msg[0] == MSG_TRANSPORT),
        _ => {}
    }
    kani::cover!(matches!(o, Outcome::Initiation { .. }));
    kani::cover!(matches!(o, Outcome::Transport { .. }));
    kani::cover!(o == Outcome::BadMac1);
    kani::cover!(o == Outcome::RateLimited);
}

/// A fresh source gets exactly BURST initiations at one instant, and a
/// further source arriving at any time on the full table does not panic.
#[kani::proof]
#[kani::unwind(10)]
fn bucket_never_exceeds_burst() {
    let mut buckets = Buckets::<2>::default();
    let now: u64 = kani::any();
    let mut granted = 0u64;
    for _ in 0..(BURST + 2) {
        if buckets.allow([10, 0, 0, 1], now) {
            granted += 1;
        }
    }
    assert!(granted == BURST);
    let other: u8 = kani::any();
    let _ = buckets.allow([10, 0, 0, other], kani::any());
}

// ---- Cookie gate (plan C3) ----

/// Records every call; each answer is nondeterministic.
#[derive(Default)]
struct Stub {
    rotates: u32,
    clears: u32,
    mac2_calls: Cell<u32>,
    mac2_true: Cell<bool>,
    seals: u32,
    sealed: bool,
}

impl Stub {
    fn calls(&self) -> u32 {
        self.rotates + self.clears + self.mac2_calls.get() + self.seals
    }
}

impl CookieCrypto for Stub {
    fn rotate(&mut self) -> bool {
        self.rotates += 1;
        kani::any()
    }

    fn clear(&mut self) {
        self.clears += 1;
    }

    fn mac2_valid(&self, _: Endpoint, _: &[u8; INITIATION_LEN]) -> bool {
        self.mac2_calls.set(self.mac2_calls.get() + 1);
        let ok: bool = kani::any();
        self.mac2_true.set(self.mac2_true.get() || ok);
        ok
    }

    fn seal_reply(&mut self, _: Endpoint, _: &[u8; INITIATION_LEN], out: &mut [u8; COOKIE_REPLY_LEN]) -> bool {
        self.seals += 1;
        self.sealed = kani::any();
        if self.sealed {
            *out = kani::any();
        }
        self.sealed
    }
}

/// Records whether mac1 was checked and its answer.
#[derive(Default)]
struct RecMac1 {
    result: Cell<Option<bool>>,
}

impl Mac1 for RecMac1 {
    fn verify(&self, _: &[u8; INITIATION_LEN]) -> bool {
        let ok: bool = kani::any();
        self.result.set(Some(ok));
        ok
    }
}

fn any_meter<const B: u64, const I: u64>() -> Meter<B, I> {
    let budget_ns: u64 = kani::any();
    kani::assume(budget_ns <= B * I);
    Meter { budget_ns, last_ns: kani::any() }
}

/// Any reachable-or-not state: meters at any level within capacity, any
/// hysteresis deadline, a secret absent, fresh or aged, any retry time and
/// any edge flags.
fn any_gate() -> Gate {
    Gate {
        arrivals: any_meter(),
        forward: any_meter(),
        under_load_until_ns: kani::any(),
        born_ns: kani::any(),
        entered_load: kani::any(),
        last_retry_ns: kani::any(),
        expired_reported: kani::any(),
        unavailable_reported: kani::any(),
        in_load: kani::any(),
        expired_edge: kani::any(),
    }
}

/// The meter level, written from the plan rather than taken from the code.
fn spec_level<const B: u64, const I: u64>(m: &Meter<B, I>, now: u64) -> u64 {
    let refill = if now > m.last_ns { now - m.last_ns } else { 0 };
    (m.budget_ns as u128 + refill as u128).min((B * I) as u128) as u64
}

fn spec_below_half<const B: u64, const I: u64>(m: &Meter<B, I>, now: u64) -> bool {
    2 * spec_level(m, now) < B * I
}

/// Plan, "Under load": a trigger holds, or one held less than
/// UNDER_LOAD_AFTER ago.
fn spec_loaded(g: &Gate, now: u64, backlog: usize) -> bool {
    spec_below_half(&g.forward, now)
        || spec_below_half(&g.arrivals, now)
        || backlog >= BACKLOG_LOAD
        || now < g.under_load_until_ns
}

fn spec_secret_usable(g: &Gate, now: u64) -> bool {
    matches!(g.born_ns, Some(b) if now >= b && now - b < COOKIE_SECRET_MAX_AGE_NS)
}

/// One `classify` call from any Gate state: invariants (a), (b) one-step,
/// (c), (d) and (e) of plan C3.
#[kani::proof]
#[kani::unwind(20)]
fn classify_gate_invariants() {
    let mut gate = any_gate();
    let before = gate.clone();
    let mut stub = Stub::default();
    let mac1 = RecMac1::default();
    let mut buckets = Buckets::<1>::default();
    let now: u64 = kani::any();
    let backlog: usize = kani::any();
    let tx_free: usize = kani::any();
    let src = Endpoint { ip: kani::any(), port: kani::any() };
    let payload: [u8; INITIATION_LEN] = kani::any();
    let mut out = [0u8; COOKIE_REPLY_LEN];
    let o = classify(&mut gate, &mut stub, &mac1, &mut buckets, now, backlog, tx_free, src, &payload, &mut out);

    // The arrival meter is spent before load is computed.
    let mut arrived = before.clone();
    if spec_level(&arrived.arrivals, now) >= ARRIVAL_INTERVAL_NS {
        arrived.arrivals = Meter { budget_ns: spec_level(&before.arrivals, now) - ARRIVAL_INTERVAL_NS, last_ns: now };
    } else {
        arrived.arrivals = Meter { budget_ns: spec_level(&before.arrivals, now), last_ns: now };
    }
    let loaded = spec_loaded(&arrived, now, backlog);
    let mac2_zero = payload[INITIATION_MAC2_OFFSET..].iter().all(|&b| b == 0);

    // (d) No crypto before mac1 passed; no mac2 MAC on an all-zero mac2.
    if mac1.result.get() != Some(true) {
        assert!(stub.calls() == 0);
    }
    if mac2_zero {
        assert!(stub.mac2_calls.get() == 0);
    }
    assert!(stub.rotates == 0 && stub.clears == 0);
    // (c) No secret use when absent or aged.
    if !spec_secret_usable(&before, now) {
        assert!(stub.mac2_calls.get() == 0 && stub.seals == 0);
    }
    // (e) The TX reserve.
    if tx_free <= NET_BUFFERS / 2 {
        assert!(stub.seals == 0);
    }
    // (a) Under load only a valid mac2 is forwarded; outside it is ignored.
    if let Outcome::Initiation { mac2_checked, .. } = o {
        assert!(mac2_checked == loaded);
        if loaded {
            assert!(stub.mac2_true.get());
        } else {
            assert!(stub.mac2_calls.get() == 0);
        }
    }
    // (b) one step: a forward spends exactly one token it had; nothing
    // else touches the forward bucket.
    let had = spec_level(&before.forward, now);
    if matches!(o, Outcome::Initiation { .. }) {
        assert!(had >= FORWARD_INTERVAL_NS);
        assert!(spec_level(&gate.forward, now) == had - FORWARD_INTERVAL_NS);
    } else {
        assert!(spec_level(&gate.forward, now) == had);
    }
    if let Outcome::CookieReply { dst, len } = o {
        assert!(dst == src && len == COOKIE_REPLY_LEN && stub.seals == 1 && stub.sealed);
    }

    kani::cover!(matches!(o, Outcome::CookieReply { .. }));
    kani::cover!(matches!(o, Outcome::CookieReply { .. }) && mac2_zero);
    kani::cover!(o == Outcome::CookieSuppressed);
    kani::cover!(o == Outcome::CookieSecretExpired);
    kani::cover!(o == Outcome::NoCookieSecret);
    kani::cover!(matches!(o, Outcome::Initiation { mac2_checked: true, .. }));
    kani::cover!(matches!(o, Outcome::Initiation { mac2_checked: false, .. }));
    // The source bucket is fresh, so this refusal is the forward bucket's.
    kani::cover!(o == Outcome::RateLimited && loaded);
}

/// (f) Under load is exactly its definition, so a forward bucket below half
/// (and therefore an empty one) means under load.
#[kani::proof]
fn under_load_is_computed_from_its_triggers() {
    let mut gate = any_gate();
    let before = gate.clone();
    let now: u64 = kani::any();
    let backlog: usize = kani::any();
    let loaded = gate.observe_load(now, backlog);
    assert!(loaded == spec_loaded(&before, now, backlog));
    if spec_below_half(&before.forward, now) {
        assert!(loaded);
    }
    if loaded && !before.in_load {
        assert!(gate.entered_load);
    }
    kani::cover!(loaded && !spec_below_half(&before.forward, now));
    kani::cover!(!loaded);
}

/// (b) on the bucket type: from a full forward bucket at one instant,
/// exactly FORWARD_BURST forwards.
#[kani::proof]
#[kani::unwind(20)]
fn forward_bucket_never_exceeds_burst() {
    let mut forward = ForwardBucket::default();
    let now: u64 = kani::any();
    kani::assume(now >= forward.last_ns);
    let mut granted = 0u64;
    for _ in 0..(FORWARD_BURST + 2) {
        if forward.allow(now) {
            granted += 1;
        }
    }
    assert!(granted == FORWARD_BURST);
}

/// (b) over time: from any level, forwards never exceed that level plus the
/// time elapsed, in tokens.
#[kani::proof]
fn forward_bucket_never_exceeds_allowance() {
    let mut forward: ForwardBucket = any_meter();
    let start = forward;
    let t1: u64 = kani::any();
    let t2: u64 = kani::any();
    let t3: u64 = kani::any();
    kani::assume(start.last_ns <= t1 && t1 <= t2 && t2 <= t3);
    let granted = u64::from(forward.allow(t1)) + u64::from(forward.allow(t2)) + u64::from(forward.allow(t3));
    assert!((granted as u128) * (FORWARD_INTERVAL_NS as u128) <= start.budget_ns as u128 + (t3 - start.last_ns) as u128);
    kani::cover!(granted == 3);
}

/// One tick from any state: rotation happens exactly when due, a failure
/// clears and leaves no secret, and edges are reported once.
#[kani::proof]
fn tick_rotates_only_when_due() {
    let mut gate = any_gate();
    let before = gate.clone();
    let mut stub = Stub::default();
    let now: u64 = kani::any();
    let r = gate.tick_if_due(&mut stub, now, kani::any());
    let due = match before.born_ns {
        Some(b) => now < b || now - b >= ROTATE_AT_NS,
        None => match before.last_retry_ns {
            None => true,
            Some(t) => now >= t && now - t >= RETRY_INTERVAL_NS,
        },
    };
    assert!(stub.rotates == u32::from(due));
    assert!(stub.mac2_calls.get() == 0 && stub.seals == 0);
    if r.rotated {
        assert!(gate.born_ns == Some(now) && stub.clears == 0 && !r.secret_unavailable);
    } else if due {
        assert!(gate.born_ns.is_none() && stub.clears == 1);
        assert!(r.secret_unavailable == !before.unavailable_reported);
    } else {
        assert!(gate.born_ns == before.born_ns && stub.clears == 0 && !r.secret_unavailable);
    }
    if r.left_load {
        assert!(before.in_load && !gate.in_load);
    }
    kani::cover!(r.rotated);
    kani::cover!(due && !r.rotated);
    kani::cover!(r.left_load);
}

/// (g) Two ticks less than RETRY_INTERVAL apart call `rotate` at most once,
/// from any state (so in particular while no secret is held).
#[kani::proof]
fn rotate_at_most_once_per_retry_interval() {
    let mut gate = any_gate();
    let mut stub = Stub::default();
    let t1: u64 = kani::any();
    let gap: u64 = kani::any();
    kani::assume(gap < RETRY_INTERVAL_NS);
    let t2 = t1.saturating_add(gap);
    let no_secret = gate.born_ns.is_none();
    gate.tick_if_due(&mut stub, t1, kani::any());
    gate.tick_if_due(&mut stub, t2, kani::any());
    assert!(stub.rotates <= 1);
    kani::cover!(no_secret && stub.rotates == 1);
}

// ---- Rosenpass (M3 plan C4), with the production constants ----

/// Answers nondeterministically; records whether it was called.
#[derive(Default)]
struct AnyRpMac {
    called: Cell<bool>,
}

impl RpMac for AnyRpMac {
    fn verify(&self, _: &[u8]) -> bool {
        self.called.set(true);
        kani::any()
    }
}

fn any_kind() -> RpKind {
    if kani::any() { RpKind::Hello } else { RpKind::Conf }
}

fn any_sources<const B: u64, const I: u64>() -> SourceMeters<2, B, I> {
    let slot = || if kani::any() { Some((kani::any(), any_meter::<B, I>())) } else { None };
    SourceMeters { slots: [slot(), slot()] }
}

/// Any state: meters at any level within capacity, any source table and
/// any ring accounting within its bounds. InitConf within its share is the
/// invariant the harnesses below show is kept.
fn any_rp_gate() -> RpGate<2> {
    let in_flight = InFlight { kinds: core::array::from_fn(|_| any_kind()), head: kani::any(), len: kani::any() };
    kani::assume(in_flight.head < RP_IN_FLIGHT && in_flight.len <= RP_IN_FLIGHT);
    RpGate {
        hello_src: any_sources(),
        hello_global: any_meter(),
        conf_src: any_sources(),
        conf_global: any_meter(),
        in_flight,
    }
}

/// Classification is total: a forward is an InitHello or InitConf of its
/// exact length; everything else of another type or length is dropped
/// before the mac. Every outcome is reachable.
#[kani::proof]
#[kani::unwind(20)]
fn rp_classify_is_total_and_typed() {
    let payload: [u8; RP_INIT_HELLO_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= payload.len());
    let msg = payload.get(..len).unwrap_or(&[]);
    let mut gate = any_rp_gate();
    let mac = AnyRpMac::default();
    let o = rp_classify(&mut gate, &mac, kani::any(), Endpoint { ip: kani::any(), port: kani::any() }, msg);
    let typed = (len == RP_INIT_HELLO_LEN && payload[0] == RP_MSG_INIT_HELLO)
        || (len == RP_INIT_CONF_LEN && payload[0] == RP_MSG_INIT_CONF);
    match o {
        RpOutcome::ForwardHello { msg, .. } => assert!(len == RP_INIT_HELLO_LEN && msg[0] == RP_MSG_INIT_HELLO),
        RpOutcome::ForwardConf { msg, .. } => assert!(len == RP_INIT_CONF_LEN && msg[0] == RP_MSG_INIT_CONF),
        RpOutcome::TypeDropped => assert!(!typed && !mac.called.get()),
        _ => assert!(typed && mac.called.get()),
    }
    kani::cover!(matches!(o, RpOutcome::ForwardHello { .. }));
    kani::cover!(matches!(o, RpOutcome::ForwardConf { .. }));
    kani::cover!(o == RpOutcome::TypeDropped);
    kani::cover!(o == RpOutcome::BadMac);
    kani::cover!(o == RpOutcome::RateLimited);
    kani::cover!(o == RpOutcome::RingReserved);
}

/// A failed mac, or a type that is dropped, leaves every meter and the
/// ring accounting exactly as they were.
#[kani::proof]
#[kani::unwind(20)]
fn rp_refusals_before_admission_spend_nothing() {
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len == RP_INIT_HELLO_LEN || len == RP_INIT_CONF_LEN || len < 4);
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let o = rp_classify(&mut gate, &AnyRpMac::default(), kani::any(), Endpoint { ip: kani::any(), port: kani::any() }, payload.get(..len).unwrap_or(&[]));
    if matches!(o, RpOutcome::BadMac | RpOutcome::TypeDropped | RpOutcome::RingReserved) {
        assert!(gate == before);
    }
    kani::cover!(o == RpOutcome::BadMac);
    kani::cover!(o == RpOutcome::TypeDropped);
    kani::cover!(o == RpOutcome::RingReserved);
}

/// A forward went through its type's constructor: it spent exactly one
/// token of its type's global meter, went through its type's per-source
/// table (a spend, or a new slot that is then spent, changes it), touched
/// no meter of the other type, and was counted once as in flight under its
/// type.
#[kani::proof]
#[kani::unwind(20)]
fn rp_forward_spends_its_own_meters_once() {
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let hello: bool = kani::any();
    let msg = if hello { &payload[..] } else { &payload[..RP_INIT_CONF_LEN] };
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let now: u64 = kani::any();
    let o = rp_classify(&mut gate, &AnyRpMac::default(), now, Endpoint { ip: kani::any(), port: kani::any() }, msg);
    match o {
        RpOutcome::ForwardHello { .. } => {
            assert!(spec_level(&gate.hello_global, now) + RP_HELLO_GLOBAL_INTERVAL_NS == spec_level(&before.hello_global, now));
            assert!(gate.hello_src != before.hello_src);
            assert!(gate.conf_global == before.conf_global && gate.conf_src == before.conf_src);
            assert!(gate.in_flight.count(RpKind::Hello) == before.in_flight.count(RpKind::Hello) + 1);
            assert!(gate.in_flight.count(RpKind::Conf) == before.in_flight.count(RpKind::Conf));
        }
        RpOutcome::ForwardConf { .. } => {
            assert!(spec_level(&gate.conf_global, now) + RP_CONF_GLOBAL_INTERVAL_NS == spec_level(&before.conf_global, now));
            assert!(gate.conf_src != before.conf_src);
            assert!(gate.hello_global == before.hello_global && gate.hello_src == before.hello_src);
            assert!(gate.in_flight.count(RpKind::Conf) == before.in_flight.count(RpKind::Conf) + 1);
            assert!(gate.in_flight.count(RpKind::Hello) == before.in_flight.count(RpKind::Hello));
        }
        _ => assert!(gate.in_flight == before.in_flight),
    }
    kani::cover!(matches!(o, RpOutcome::ForwardHello { .. }));
    kani::cover!(matches!(o, RpOutcome::ForwardConf { .. }));
}

/// From any state with InitConf within its share, one datagram, a reclaim
/// or an unsent keeps it there and keeps the ring within RP_IN_FLIGHT; and
/// while the ring has room, an InitHello is never refused for the ring.
#[kani::proof]
#[kani::unwind(20)]
fn rp_init_conf_never_exceeds_its_share() {
    let mut gate = any_rp_gate();
    kani::assume(gate.in_flight.count(RpKind::Conf) <= RP_CONF_SHARE);
    let room = gate.in_flight.len < RP_IN_FLIGHT;
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let hello: bool = kani::any();
    let msg = if hello { &payload[..] } else { &payload[..RP_INIT_CONF_LEN] };
    let o = match kani::any::<u8>() {
        0 => {
            gate.reclaimed(kani::any());
            None
        }
        1 => {
            gate.unsent();
            None
        }
        _ => Some(rp_classify(&mut gate, &AnyRpMac::default(), kani::any(), Endpoint { ip: kani::any(), port: kani::any() }, msg)),
    };
    assert!(gate.in_flight.count(RpKind::Conf) <= RP_CONF_SHARE);
    assert!(gate.in_flight.len <= RP_IN_FLIGHT);
    if hello && room {
        assert!(o != Some(RpOutcome::RingReserved));
    }
    kani::cover!(o == Some(RpOutcome::RingReserved) && !hello && room);
    kani::cover!(matches!(o, Some(RpOutcome::ForwardConf { .. })) && gate.in_flight.count(RpKind::Conf) == RP_CONF_SHARE);
}
