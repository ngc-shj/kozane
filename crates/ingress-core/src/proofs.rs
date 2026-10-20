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
        // (e) The TX reserve and the Rosenpass answer share (M3b S2).
        assert!(tx_free > NET_BUFFERS / 2 + RP_ANSWER_SHARE);
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
        entered_load: kani::any(),
        in_load: kani::any(),
        life: SecretLife {
            born_ns: kani::any(),
            last_retry_ns: kani::any(),
            expired_reported: kani::any(),
            unavailable_reported: kani::any(),
            expired_edge: kani::any(),
        },
    }
}

/// The meter level, written from the plan rather than taken from the code.
fn spec_level<const B: u64, const I: u64>(m: &Meter<B, I>, now: u64) -> u64 {
    let refill = if now > m.last_ns { now - m.last_ns } else { 0 };
    (m.budget_ns as u128 + refill as u128).min((B * I) as u128) as u64
}

/// The level of `ip`'s slot in a per-source table; a source without a slot
/// is full (a new slot starts full).
fn spec_src_level<const N: usize, const B: u64, const I: u64>(t: &SourceMeters<N, B, I>, ip: Ipv4, now: u64) -> u64 {
    t.slots.iter().flatten().find(|(i, _)| *i == ip).map_or(B * I, |(_, m)| spec_level(m, now))
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
    matches!(g.life.born_ns, Some(b) if now >= b && now - b < COOKIE_SECRET_MAX_AGE_NS)
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
    // (e) The TX reserve and the Rosenpass answer share (M3b S2).
    if tx_free <= NET_BUFFERS / 2 + RP_ANSWER_SHARE {
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
    let due = match before.life.born_ns {
        Some(b) => now < b || now - b >= ROTATE_AT_NS,
        None => match before.life.last_retry_ns {
            None => true,
            Some(t) => now >= t && now - t >= RETRY_INTERVAL_NS,
        },
    };
    assert!(stub.rotates == u32::from(due));
    assert!(stub.mac2_calls.get() == 0 && stub.seals == 0);
    if r.rotated {
        assert!(gate.life.born_ns == Some(now) && stub.clears == 0 && !r.secret_unavailable);
    } else if due {
        assert!(gate.life.born_ns.is_none() && stub.clears == 1);
        assert!(r.secret_unavailable == !before.life.unavailable_reported);
    } else {
        assert!(gate.life.born_ns == before.life.born_ns && stub.clears == 0 && !r.secret_unavailable);
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
    let no_secret = gate.life.born_ns.is_none();
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

fn any_entry() -> Entry {
    let state = match kani::any::<u8>() % 3 {
        0 => EntryState::AwaitingRecord,
        1 => EntryState::CompletedReply,
        _ => EntryState::CompletedNoReply,
    };
    Entry { kind: any_kind(), src: Endpoint { ip: kani::any(), port: kani::any() }, state }
}

fn any_sources<const B: u64, const I: u64>() -> SourceMeters<2, B, I> {
    let slot = || if kani::any() { Some((kani::any(), any_meter::<B, I>())) } else { None };
    SourceMeters { slots: [slot(), slot()] }
}

fn any_endpoint() -> Endpoint {
    Endpoint { ip: kani::any(), port: kani::any() }
}

fn any_endpoint_sources<const B: u64, const I: u64>() -> SourceMeters<2, B, I, Endpoint> {
    let slot = || if kani::any() { Some((any_endpoint(), any_meter::<B, I>())) } else { None };
    SourceMeters { slots: [slot(), slot()] }
}

/// One arbitrary awaited entry in slot 0, the rest empty (bounded state).
fn any_awaited() -> [Option<Awaited>; RP_AWAIT_SLOTS] {
    let mut a = [None; RP_AWAIT_SLOTS];
    if kani::any() {
        a[0] = Some(Awaited {
            ep: any_endpoint(),
            sidi: kani::any(),
            sidr: kani::any(),
            at: kani::any(),
            conf_budget: kani::any(),
            conf_seen: kani::any(),
        });
    }
    a
}

/// One arbitrary proven slot (peer 0), the rest empty.
fn any_proven() -> [Option<Proven>; RP_MAX_PEERS] {
    let mut p = [None; RP_MAX_PEERS];
    if kani::any() {
        p[0] = Some(Proven { ep: any_endpoint(), at: kani::any(), credit: any_meter() });
    }
    p
}

/// A Rosenpass cookie secret answering anything, counting what it was
/// asked.
#[derive(Default)]
struct AnyRpCookie {
    valid_calls: Cell<u32>,
    seals: u32,
}

impl RpCookieCheck for AnyRpCookie {
    fn valid(&self, _: Endpoint, _: &[u8; RP_INIT_HELLO_LEN]) -> bool {
        self.valid_calls.set(self.valid_calls.get() + 1);
        kani::any()
    }

    fn seal(&mut self, _: Endpoint, _: &[u8; RP_INIT_HELLO_LEN], _: &mut [u8; RP_COOKIE_REPLY_LEN]) -> bool {
        self.seals += 1;
        kani::any()
    }

    fn rotate(&mut self) -> bool {
        kani::any()
    }

    fn clear(&mut self) {}
}

/// `rp_classify` with any cookie answers, any TX level and a fresh buffer.
fn classify_any<'a>(gate: &mut RpGate<2>, mac: &AnyRpMac, cookie: &mut AnyRpCookie, now: u64, src: Endpoint, msg: &'a [u8]) -> RpOutcome<'a> {
    rp_classify(gate, mac, cookie, now, kani::any(), src, msg, &mut [0u8; RP_COOKIE_REPLY_LEN])
}

/// Any state: meters at any level within capacity, any source table, any
/// FIFO within its bounds and either `pq` state. Each kind within its slots
/// is the invariant the harnesses below show is kept.
fn any_rp_gate() -> RpGate<2> {
    let in_flight = InFlight { entries: core::array::from_fn(|_| any_entry()), head: kani::any(), len: kani::any() };
    kani::assume(in_flight.head < RP_IN_FLIGHT && in_flight.len <= RP_IN_FLIGHT);
    RpGate {
        hello_src: any_sources(),
        hello_global: any_meter(),
        conf_src: any_sources(),
        conf_global: any_meter(),
        in_flight,
        pq_dead: kani::any(),
        hello_cookied_ep: any_endpoint_sources(),
        hello_cookied_ip: any_sources(),
        awaited: any_awaited(),
        proven: any_proven(),
        under_load_until_ns: kani::any(),
        in_load: kani::any(),
        entered_load: kani::any(),
        life: SecretLife {
            born_ns: kani::any(),
            last_retry_ns: kani::any(),
            expired_reported: kani::any(),
            unavailable_reported: kani::any(),
            expired_edge: kani::any(),
        },
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
    let o = classify_any(&mut gate, &mac, &mut AnyRpCookie::default(), kani::any(), Endpoint { ip: kani::any(), port: kani::any() }, msg);
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
    let o = classify_any(&mut gate, &AnyRpMac::default(), &mut AnyRpCookie::default(), kani::any(), Endpoint { ip: kani::any(), port: kani::any() }, payload.get(..len).unwrap_or(&[]));
    if matches!(o, RpOutcome::BadMac | RpOutcome::TypeDropped | RpOutcome::RingReserved) {
        assert!(gate == before);
    }
    kani::cover!(o == RpOutcome::BadMac);
    kani::cover!(o == RpOutcome::TypeDropped);
    kani::cover!(o == RpOutcome::RingReserved);
}

/// A forward went through its type's constructor: it spent exactly one
/// token of its type's global meter and exactly one of the source's own
/// slot in its type's per-source table (a new source's slot starts full),
/// touched no meter of the other type, and recorded nothing in flight
/// (only `sent` does, after the PD's send succeeded).
#[kani::proof]
#[kani::unwind(20)]
fn rp_forward_spends_its_own_meters_once() {
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let hello: bool = kani::any();
    let msg = if hello { &payload[..] } else { &payload[..RP_INIT_CONF_LEN] };
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let now: u64 = kani::any();
    let ip: Ipv4 = kani::any();
    let o = classify_any(&mut gate, &AnyRpMac::default(), &mut AnyRpCookie::default(), now, Endpoint { ip, port: kani::any() }, msg);
    match o {
        RpOutcome::ForwardHello { .. } => {
            assert!(spec_level(&gate.hello_global, now) + RP_HELLO_GLOBAL_INTERVAL_NS == spec_level(&before.hello_global, now));
            assert!(
                spec_src_level(&gate.hello_src, ip, now) + RP_HELLO_SRC_INTERVAL_NS == spec_src_level(&before.hello_src, ip, now)
            );
            assert!(gate.conf_global == before.conf_global && gate.conf_src == before.conf_src);
        }
        RpOutcome::ForwardConf { .. } => {
            assert!(spec_level(&gate.conf_global, now) + RP_CONF_GLOBAL_INTERVAL_NS == spec_level(&before.conf_global, now));
            assert!(
                spec_src_level(&gate.conf_src, ip, now) + RP_CONF_SRC_INTERVAL_NS == spec_src_level(&before.conf_src, ip, now)
            );
            assert!(gate.hello_global == before.hello_global && gate.hello_src == before.hello_src);
        }
        _ => {}
    }
    assert!(gate.in_flight == before.in_flight && gate.pq_dead == before.pq_dead);
    kani::cover!(matches!(o, RpOutcome::ForwardHello { .. }));
    kani::cover!(matches!(o, RpOutcome::ForwardConf { .. }));
}

/// From any state with each kind within its slots (S14: the one `pq` is
/// working on counted), one datagram (recorded as sent if forwarded) or a
/// retirement keeps each kind within its slots and the FIFO within
/// RP_IN_FLIGHT; and while a kind has room and the path is up, it is never
/// refused for the ring.
#[kani::proof]
#[kani::unwind(20)]
fn rp_shares_stay_disjoint_and_bounded() {
    let mut gate = any_rp_gate();
    kani::assume(gate.in_flight.count(RpKind::Hello) <= RP_HELLO_IN_FLIGHT);
    kani::assume(gate.in_flight.count(RpKind::Conf) <= RP_CONF_IN_FLIGHT);
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let hello: bool = kani::any();
    let kind = if hello { RpKind::Hello } else { RpKind::Conf };
    let cap = if hello { RP_HELLO_IN_FLIGHT } else { RP_CONF_IN_FLIGHT };
    let room = !gate.pq_dead && gate.in_flight.count(kind) < cap;
    let msg = if hello { &payload[..] } else { &payload[..RP_INIT_CONF_LEN] };
    let src = Endpoint { ip: kani::any(), port: kani::any() };
    let o = if kani::any() {
        let _ = gate.retire(kani::any());
        None
    } else {
        let o = classify_any(&mut gate, &AnyRpMac::default(), &mut AnyRpCookie::default(), kani::any(), src, msg);
        if matches!(o, RpOutcome::ForwardHello { .. } | RpOutcome::ForwardConf { .. }) {
            gate.sent(kind, src);
        }
        Some(o)
    };
    assert!(gate.in_flight.count(RpKind::Hello) <= RP_HELLO_IN_FLIGHT);
    assert!(gate.in_flight.count(RpKind::Conf) <= RP_CONF_IN_FLIGHT);
    assert!(gate.in_flight.len <= RP_IN_FLIGHT);
    if room {
        assert!(o != Some(RpOutcome::RingReserved));
    }
    kani::cover!(o == Some(RpOutcome::RingReserved) && !room);
    kani::cover!(matches!(o, Some(RpOutcome::ForwardConf { .. })) && gate.in_flight.count(RpKind::Conf) == RP_CONF_IN_FLIGHT);
}

/// The completion protocol (I9a-I9c) against any FIFO, any snapshot and any
/// sequence of up to three records of any shape: every reply goes to the
/// stored source of the entry it was paired with, in FIFO order; no entry
/// takes two records; a sync that did not die retired exactly the observed
/// returns, each completed; and a dead path does nothing at all.
#[kani::proof]
#[kani::unwind(12)]
fn rp_sync_relays_only_to_stored_sources_in_order() {
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let mut pq = AnyPq { outstanding: kani::any(), left: kani::any(), sent: [None; 3], n_sent: 0, n_ok: 0 };
    kani::assume(pq.left <= 3);
    let o = sync_pq(&mut gate, &mut pq, 2, kani::any());
    // Each reply went to the source of a distinct entry, oldest first.
    let mut cursor = 0usize;
    for dst in pq.sent.iter().take(pq.n_sent).flatten() {
        let mut found = false;
        while cursor < before.in_flight.len {
            let e = before.in_flight.get(cursor);
            cursor += 1;
            if e.is_some_and(|e| e.src == *dst && e.state == EntryState::AwaitingRecord) {
                found = true;
                break;
            }
        }
        assert!(found);
    }
    match o {
        SyncOutcome::Dead => assert!(before.pq_dead && gate == before && pq.n_sent == 0),
        SyncOutcome::DiedNow => assert!(gate.pq_dead),
        SyncOutcome::Synced { relayed } => {
            assert!(!gate.pq_dead && relayed == pq.n_ok);
            let r = before.in_flight.len - pq.outstanding.unwrap_or(0);
            assert!(gate.in_flight.len == before.in_flight.len - r);
        }
    }
    kani::cover!(matches!(o, SyncOutcome::Synced { relayed: 2 }));
    kani::cover!(o == SyncOutcome::DiedNow);
}

/// A scripted `pq`: any snapshot, then `left` records, each a NoReply, a
/// RespHello or an EmptyData for any index, or unreadable.
struct AnyPq {
    outstanding: Option<usize>,
    left: u8,
    sent: [Option<Endpoint>; 3],
    n_sent: usize,
    /// Sends that went out (`transmit` returned true).
    n_ok: usize,
}

impl PqSync for AnyPq {
    fn outstanding(&mut self) -> Option<usize> {
        self.outstanding
    }

    fn next_record(&mut self, out: &mut [u8; RP_RECORD_MAX]) -> Option<Option<usize>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let index: u8 = kani::any();
        let r = match kani::any::<u8>() % 4 {
            0 => msgs::RpReply::NoReply,
            1 => msgs::RpReply::Reply { index, msg: &[0x82; RP_RESP_HELLO_LEN] },
            2 => msgs::RpReply::Reply { index, msg: &[0x84; RP_EMPTY_DATA_LEN] },
            _ => return Some(None),
        };
        Some(r.encode(out))
    }

    fn transmit(&mut self, dst: Endpoint, _reply: &[u8]) -> bool {
        if let Some(s) = self.sent.get_mut(self.n_sent) {
            *s = Some(dst);
        }
        self.n_sent += 1;
        let ok: bool = kani::any();
        self.n_ok += usize::from(ok);
        ok
    }
}

/// The tokens a meter holds, from the plan rather than the code.
fn spec_tokens<const B: u64, const I: u64>(m: &Meter<B, I>, now: u64) -> u64 {
    spec_level(m, now) / I
}

/// I1: under load, an InitHello without a valid cookie (any outcome but a
/// forward, after the mac passed) spends no meter and records nothing: only
/// the load deadline and its edge, and the expiry edge, may change.
/// I2: off load the cookie is never asked.
#[kani::proof]
#[kani::unwind(20)]
fn rp_cookie_lane_spends_nothing_and_is_never_asked_off_load() {
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let now: u64 = kani::any();
    let mut cookie = AnyRpCookie::default();
    let o = classify_any(&mut gate, &AnyRpMac::default(), &mut cookie, now, any_endpoint(), &payload);
    let loaded_before = spec_below_half(&before.hello_global, now) || now < before.under_load_until_ns;
    if !loaded_before {
        assert!(cookie.valid_calls.get() == 0);
    }
    if matches!(
        o,
        RpOutcome::CookieReply { .. } | RpOutcome::CookieSuppressed | RpOutcome::NoCookieSecret | RpOutcome::CookieSecretExpired
    ) {
        assert!(loaded_before);
        assert!(gate.hello_src == before.hello_src && gate.hello_cookied_ep == before.hello_cookied_ep);
        assert!(gate.hello_cookied_ip == before.hello_cookied_ip && gate.hello_global == before.hello_global);
        assert!(gate.conf_src == before.conf_src && gate.conf_global == before.conf_global);
        assert!(gate.in_flight == before.in_flight && gate.awaited == before.awaited && gate.proven == before.proven);
    }
    kani::cover!(matches!(o, RpOutcome::CookieReply { .. }));
    kani::cover!(matches!(o, RpOutcome::ForwardHello { .. }) && cookie.valid_calls.get() == 1);
}

/// I3: an InitHello forwarded for an endpoint that held no live proven
/// slot found more than RP_HELLO_PROVEN_RESERVE global tokens; any forward
/// spent exactly one (I7, which keeps the C2 key-bucket assertion).
#[kani::proof]
#[kani::unwind(20)]
fn rp_unproven_never_takes_the_proven_reserve() {
    let payload: [u8; RP_INIT_HELLO_LEN] = kani::any();
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let now: u64 = kani::any();
    let src = any_endpoint();
    let o = classify_any(&mut gate, &AnyRpMac::default(), &mut AnyRpCookie::default(), now, src, &payload);
    if matches!(o, RpOutcome::ForwardHello { .. }) {
        assert!(spec_level(&gate.hello_global, now) + RP_HELLO_GLOBAL_INTERVAL_NS == spec_level(&before.hello_global, now));
        let proven = before.proven.iter().flatten().any(|p| p.ep == src && now >= p.at && now - p.at < RP_PROVEN_NS);
        if !proven {
            assert!(spec_tokens(&before.hello_global, now) > RP_HELLO_PROVEN_RESERVE);
        }
    }
    kani::cover!(matches!(o, RpOutcome::ForwardHello { .. }) && spec_tokens(&before.hello_global, now) <= RP_HELLO_PROVEN_RESERVE);
}

/// I5: an InitConf forwarded while the open share of InitConf slots was
/// full matched a live awaited entry of its endpoint, whose budget it
/// spent; and an unmatched one found more than the reserved conf tokens.
#[kani::proof]
#[kani::unwind(20)]
fn rp_only_a_matched_init_conf_takes_the_awaited_reserve() {
    let payload: [u8; RP_INIT_CONF_LEN] = kani::any();
    let mut gate = any_rp_gate();
    kani::assume(gate.in_flight.count(RpKind::Conf) <= RP_CONF_IN_FLIGHT);
    let before = gate.clone();
    let now: u64 = kani::any();
    let src = any_endpoint();
    let o = classify_any(&mut gate, &AnyRpMac::default(), &mut AnyRpCookie::default(), now, src, &payload);
    if matches!(o, RpOutcome::ForwardConf { .. }) {
        let matched = before.awaited[0].is_some_and(|a| {
            a.ep == src
                && payload[4..8] == a.sidi
                && payload[8..12] == a.sidr
                && a.conf_budget > 0
                && now >= a.at
                && now - a.at < RP_AWAIT_CONF_NS
        });
        if before.in_flight.count(RpKind::Conf) >= RP_CONF_IN_FLIGHT - RP_CONF_AWAITED_RESERVED {
            assert!(matched);
        }
        if !matched {
            assert!(spec_tokens(&before.conf_global, now) > RP_CONF_AWAITED_RESERVED as u64);
        } else {
            assert!(gate.awaited[0].is_some_and(|a| a.conf_seen && a.conf_budget + 1 == before.awaited[0].map_or(0, |b| b.conf_budget)));
        }
    }
    kani::cover!(matches!(o, RpOutcome::ForwardConf { .. }) && before.in_flight.count(RpKind::Conf) == RP_CONF_IN_FLIGHT - 1);
}

/// I6: a proven slot changes only on an EmptyData to an endpoint with a
/// `conf_seen` awaited entry whose sidi is the EmptyData's sid, and only the
/// named peer's slot, with an index below RP_MAX_PEERS.
#[kani::proof]
#[kani::unwind(20)]
fn rp_proven_changes_only_through_the_session_ids() {
    let mut gate = any_rp_gate();
    let before = gate.clone();
    let msg: [u8; 12] = kani::any();
    let dst = any_endpoint();
    let peer: Option<u8> = kani::any();
    let kind = any_kind();
    gate.replied(kind, dst, peer, &msg, kani::any());
    if gate.proven != before.proven {
        assert!(kind == RpKind::Conf);
        let a = before.awaited[0].unwrap();
        assert!(a.ep == dst && a.conf_seen && msg[4..8] == a.sidi);
        let i = usize::from(peer.unwrap());
        assert!(i < RP_MAX_PEERS);
        for j in 0..RP_MAX_PEERS {
            if j != i {
                assert!(gate.proven[j] == before.proven[j]);
            }
        }
        assert!(gate.proven[i].is_some_and(|p| p.ep == dst));
    }
    kani::cover!(gate.proven != before.proven);
}

/// I8: an unsolicited reply is never allowed where an answer is refused.
#[kani::proof]
fn rp_tx_tiers_are_ordered() {
    let free: usize = kani::any();
    if rp_tx_allowed(TxTier::Unsolicited, free) {
        assert!(rp_tx_allowed(TxTier::Answer, free));
    }
    kani::cover!(rp_tx_allowed(TxTier::Answer, free) && !rp_tx_allowed(TxTier::Unsolicited, free));
}
