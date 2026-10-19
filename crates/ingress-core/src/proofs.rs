//! Kani harnesses for `ingress-core`. Run with `cargo kani -p ingress-core`.

use core::cell::Cell;

use super::*;

struct AnyMac1;

impl Mac1 for AnyMac1 {
    fn verify(&self, _: &[u8; INITIATION_LEN]) -> bool {
        kani::any()
    }
}

const CFG: Config =
    Config { mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], router_mac: [0x52, 0x55, 10, 0, 2, 2], port: 51820 };

/// `respond` never panics and never claims more bytes than `out` holds.
#[kani::proof]
#[kani::unwind(66)]
fn respond_is_total_and_bounded() {
    let buf: [u8; 64] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 64);
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
        kani::any(),
        buf.get(..len).unwrap_or(&[]),
        &mut out,
        &mut cookie,
    );
    if let Outcome::ArpReplied(n) = o {
        assert!(n <= out.len());
    }
    kani::cover!(matches!(o, Outcome::ArpReplied(_)));
    // A transport frame needs 74 bytes; `classify` covers it.
    kani::cover!(o == Outcome::NotForUs);
    kani::cover!(o == Outcome::NoService);
    kani::cover!(o == Outcome::Spoofed);
    kani::cover!(o == Outcome::BadMessage);
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
