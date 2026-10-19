//! `ingress` v2 decision logic (plan C14, M2.5 C3): answer ARP for the
//! outside address and classify WireGuard datagrams on the listen port.
//! Only a well-formed initiation with a valid mac1, past the cookie gate
//! and within the per-source and forward budgets, reaches `hs`; only a
//! transport message of plausible size reaches `data`; everything else is
//! dropped with a reason. Pure and total, so it is unit-tested and proved
//! on the host; the PD only moves bytes.
//!
//! mac1 and the cookie MACs need BLAKE2s and XChaCha20-Poly1305, so they
//! are reached through the `Mac1` and `CookieCrypto` traits: the PD plugs in
//! wg-core and holds the cookie secret, the proofs plug in stubs. The core
//! keeps only the secret's birth time and decides when crypto may run.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wg_wire::{COOKIE_REPLY_LEN, INITIATION_LEN, INITIATION_MAC2_OFFSET, MSG_INITIATION, MSG_TRANSPORT, TRANSPORT_MIN_LEN};
use wire::{ArpOp, ArpPacket, Body, DropReason, EmitError, EthAddrs, Frame, Ipv4, Mac, Udp4};

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub mac: Mac,
    pub ipv4: Ipv4,
    /// Next hop for every outbound datagram (static, law L6).
    pub router_mac: Mac,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: Ipv4,
    pub port: u16,
}

/// Verifies an initiation's mac1 against the gateway's static public key.
pub trait Mac1 {
    fn verify(&self, msg: &[u8; INITIATION_LEN]) -> bool;
}

/// The cookie secret's operations (plan C1, C3). The PD's adapter owns the
/// secret itself, so it never enters this crate [M7]; the Gate only decides
/// when each call may happen.
pub trait CookieCrypto {
    /// Replaces the secret with a fresh random one; false if the RNG failed.
    fn rotate(&mut self) -> bool;
    /// Zeroizes the secret.
    fn clear(&mut self);
    /// Whether `msg`'s mac2 is valid for a cookie bound to `src`.
    fn mac2_valid(&self, src: Endpoint, msg: &[u8; INITIATION_LEN]) -> bool;
    /// Writes the cookie reply to `msg` from `src` into `out`.
    fn seal_reply(&mut self, src: Endpoint, msg: &[u8; INITIATION_LEN], out: &mut [u8; COOKIE_REPLY_LEN]) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// Reply of this many bytes was written to `out`.
    ArpReplied(usize),
    /// An ARP reply was due but the TX reserve was reached.
    ArpSuppressed,
    /// The only outcome the PD sends to `hs`. `mac2_checked` is true when it
    /// passed under load with a valid mac2 (audited as `WgMac2Accepted`).
    Initiation { src: Endpoint, msg: &'a [u8; INITIATION_LEN], mac2_checked: bool },
    Transport { src: Endpoint, msg: &'a [u8] },
    /// Cookie reply of `len` bytes for `dst` was written to the cookie buffer.
    CookieReply { dst: Endpoint, len: usize },
    /// A reply was due but the TX reserve was reached or sealing failed.
    CookieSuppressed,
    /// A reply was due but the secret is at or past its maximum age.
    CookieSecretExpired,
    /// A reply was due but no secret is held (RNG failure).
    NoCookieSecret,
    Dropped(DropReason),
    NotForUs,
    /// Valid frame for us that no service handles (other port, ARP reply).
    NoService,
    /// Source claims to be us, or ARP sender differs from the Ethernet source.
    Spoofed,
    /// WireGuard type/length combination a responder does not accept.
    BadMessage,
    BadMac1,
    /// Over the source's budget or, after any cookie check, the forward cap.
    RateLimited,
}

const BROADCAST: Mac = [0xff; 6];

#[allow(clippy::too_many_arguments)] // each argument is an independent input the PD reads per frame (state, crypto, levels, frame); bundling them would only rename the list
pub fn respond<'a, C: CookieCrypto, M: Mac1, const N: usize>(
    cfg: &Config,
    gate: &mut Gate,
    crypto: &mut C,
    mac1: &M,
    buckets: &mut Buckets<N>,
    now_ns: u64,
    backlog: usize,
    tx_free: usize,
    frame: &'a [u8],
    out: &mut [u8],
    cookie: &mut [u8; COOKIE_REPLY_LEN],
) -> Outcome<'a> {
    let f = match wire::parse_frame(frame) {
        Ok(f) => f,
        Err(r) => return Outcome::Dropped(r),
    };
    match f.body {
        Body::Arp(a) => arp(cfg, &f.eth, &a, tx_free, out),
        Body::Udp4(u) => {
            if f.eth.dst != cfg.mac || u.dst != cfg.ipv4 {
                return Outcome::NotForUs;
            }
            if u.src == cfg.ipv4 || f.eth.src == cfg.mac {
                return Outcome::Spoofed;
            }
            if u.dport != cfg.port {
                return Outcome::NoService;
            }
            let src = Endpoint { ip: u.src, port: u.sport };
            classify(gate, crypto, mac1, buckets, now_ns, backlog, tx_free, src, u.payload, cookie)
        }
        // `parse_frame` (outside NIC) never yields it.
        Body::Ipv4(_) => Outcome::Dropped(DropReason::NotUdp),
    }
}

fn arp<'a>(cfg: &Config, eth: &EthAddrs, a: &ArpPacket, tx_free: usize, out: &mut [u8]) -> Outcome<'a> {
    if (eth.dst != cfg.mac && eth.dst != BROADCAST) || a.tpa != cfg.ipv4 {
        return Outcome::NotForUs;
    }
    if a.sha != eth.src || eth.src == cfg.mac || a.spa == cfg.ipv4 {
        return Outcome::Spoofed;
    }
    if a.op != ArpOp::Request {
        return Outcome::NoService;
    }
    // Requests are attacker-paced and cheaper than initiations, so their
    // replies stay out of the reserve too [code review S1].
    if tx_free <= TX_RESERVE {
        return Outcome::ArpSuppressed;
    }
    // Reply to the frame's sender (equal to sha, checked above), so a
    // forged sha cannot aim the reply at a third party.
    let reply = Frame {
        eth: EthAddrs { src: cfg.mac, dst: eth.src },
        body: Body::Arp(ArpPacket { op: ArpOp::Reply, sha: cfg.mac, spa: cfg.ipv4, tha: a.sha, tpa: a.spa }),
    };
    match wire::emit(&reply, out) {
        Ok(n) => Outcome::ArpReplied(n),
        // `out` too small: treat as no service rather than panic.
        Err(_) => Outcome::NoService,
    }
}

/// WireGuard-level checks on a datagram addressed to the listen port.
/// Nothing reaches crypto or spends a budget before length and mac1 pass.
/// mac1 needs only the public key compiled into the image (law L6), so it
/// is no authentication; under load the cookie gate below requires a mac2
/// bound to the source address, and the forward bucket caps what reaches
/// `hs` in every case (plan, "Load, caps and the key budget").
///
/// `backlog` is the number of `to_hs` buffers `hs` has not returned and
/// `tx_free` the free `to_driver` buffers, both read fresh by the PD. A
/// cookie reply goes to `out`.
#[allow(clippy::too_many_arguments)] // each argument is an independent input the PD reads per frame (state, crypto, levels, frame); bundling them would only rename the list
pub fn classify<'a, C: CookieCrypto, M: Mac1, const N: usize>(
    gate: &mut Gate,
    crypto: &mut C,
    mac1: &M,
    buckets: &mut Buckets<N>,
    now_ns: u64,
    backlog: usize,
    tx_free: usize,
    src: Endpoint,
    payload: &'a [u8],
    out: &mut [u8; COOKIE_REPLY_LEN],
) -> Outcome<'a> {
    let Some(&[kind, r0, r1, r2]) = payload.first_chunk::<4>() else {
        return Outcome::BadMessage;
    };
    if [r0, r1, r2] != [0; 3] {
        return Outcome::BadMessage;
    }
    match kind {
        MSG_INITIATION => {
            let Ok(msg) = <&[u8; INITIATION_LEN]>::try_from(payload) else {
                return Outcome::BadMessage;
            };
            if !mac1.verify(msg) {
                return Outcome::BadMac1;
            }
            gate.initiation(crypto, buckets, now_ns, backlog, tx_free, src, msg, out)
        }
        MSG_TRANSPORT if payload.len() >= TRANSPORT_MIN_LEN => Outcome::Transport { src, msg: payload },
        _ => Outcome::BadMessage,
    }
}

/// Builds an outbound datagram from the listen port to `dst` via the router.
pub fn emit_udp(cfg: &Config, dst: Endpoint, payload: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    wire::emit(
        &Frame {
            eth: EthAddrs { src: cfg.mac, dst: cfg.router_mac },
            body: Body::Udp4(Udp4 { src: cfg.ipv4, dst: dst.ip, sport: cfg.port, dport: dst.port, payload }),
        },
        out,
    )
}

/// Initiations each source may send: a burst of `BURST`, refilled at one
/// per `INTERVAL_NS` (the shape of wireguard-go's per-IP limiter).
pub const BURST: u64 = 5;
pub const INTERVAL_NS: u64 = 1_000_000_000 / 20;
const CAPACITY_NS: u64 = BURST * INTERVAL_NS;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    ip: Ipv4,
    /// Budget in nanoseconds of refill time; one initiation costs INTERVAL_NS.
    budget_ns: u64,
    last_ns: u64,
}

/// Per-source token buckets in a fixed table. A new source takes a free
/// slot or evicts the least recently used one, so a spoofed-source flood
/// churns budgets rather than exhausting memory; the forward bucket and the
/// cookie gate bound that case, with `key`'s quota as the audited backstop
/// (M2.5 plan C3, C5).
#[derive(Debug, Clone)]
pub struct Buckets<const N: usize> {
    slots: [Option<Bucket>; N],
}

impl<const N: usize> Default for Buckets<N> {
    fn default() -> Self {
        Self { slots: [None; N] }
    }
}

impl<const N: usize> Buckets<N> {
    pub fn allow(&mut self, ip: Ipv4, now_ns: u64) -> bool {
        let slot = match self.slots.iter().position(|s| s.is_some_and(|b| b.ip == ip)) {
            Some(i) => i,
            None => {
                // Free slots sort first (key 0), then the oldest.
                let victim = self
                    .slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.map_or(0, |b| b.last_ns.saturating_add(1)))
                    .map_or(0, |(i, _)| i);
                if let Some(s) = self.slots.get_mut(victim) {
                    *s = Some(Bucket { ip, budget_ns: CAPACITY_NS, last_ns: now_ns });
                }
                victim
            }
        };
        let Some(Some(b)) = self.slots.get_mut(slot) else {
            return false;
        };
        // A clock that goes backwards refills nothing.
        let elapsed = now_ns.saturating_sub(b.last_ns);
        b.budget_ns = b.budget_ns.saturating_add(elapsed).min(CAPACITY_NS);
        b.last_ns = b.last_ns.max(now_ns);
        if b.budget_ns < INTERVAL_NS {
            return false;
        }
        b.budget_ns = b.budget_ns.saturating_sub(INTERVAL_NS);
        true
    }
}

/// Buffers per network ring. Equal to `layout::NET_BUFFERS`, which this
/// crate does not depend on; hs-core's tests and the ingress PD assert the
/// two equal.
pub const NET_BUFFERS: usize = 64;

/// Arrival meter: offered load, spent by every mac1-valid initiation.
pub const ARRIVAL_BURST: u64 = 16;
pub const ARRIVAL_INTERVAL_NS: u64 = 5_000_000;
/// Forward bucket: the hard cap on initiations handed to `hs` (plan C5).
pub const FORWARD_BURST: u64 = 16;
pub const FORWARD_INTERVAL_NS: u64 = 5_000_000;
/// Load persists this long after its last trigger held.
pub const UNDER_LOAD_AFTER_NS: u64 = 1_000_000_000;
/// `to_hs` buffers outstanding at which `ingress` counts as under load.
pub const BACKLOG_LOAD: usize = NET_BUFFERS / 8;
/// Age at which `tick_if_due` rotates the cookie secret: MAX_AGE − 2 ticks.
pub const ROTATE_AT_NS: u64 = 118_000_000_000;
/// Age from which `classify` refuses to use the secret (the backstop).
pub const COOKIE_SECRET_MAX_AGE_NS: u64 = 120_000_000_000;
/// Frames each input may move per handler-loop pass (K).
pub const PASS_FRAMES: usize = NET_BUFFERS;
/// Minimum spacing of `rotate` calls while no secret is held, so the RNG is
/// never read at attacker-driven rate [R3-F-F5].
pub const RETRY_INTERVAL_NS: u64 = 100_000_000;
/// Cookie and ARP replies may use only the TX buffers above this; the rest
/// stays for `hs` and `data` [R2-F-F4].
const TX_RESERVE: usize = NET_BUFFERS / 2;

// Load must begin on arrivals no later than on forwards (plan, "Ordering of
// the arrival constants").
const _: () = assert!(ARRIVAL_INTERVAL_NS >= FORWARD_INTERVAL_NS, "ARRIVAL_INTERVAL_NS below FORWARD_INTERVAL_NS");
const _: () = assert!(ARRIVAL_BURST <= FORWARD_BURST, "ARRIVAL_BURST above FORWARD_BURST");
const _: () = assert!(ROTATE_AT_NS < COOKIE_SECRET_MAX_AGE_NS, "ROTATE_AT_NS not below COOKIE_SECRET_MAX_AGE_NS");

/// One global token bucket (the shape of `Bucket`): a burst of `BURST`,
/// refilled at one per `INTERVAL_NS`, starting full. `Buckets` keeps its own
/// per-slot copy of the same arithmetic: it is M2 code with its own Kani
/// proofs, and adopting `Meter` there would change proved code for no
/// behavioural gain.
#[derive(Debug, Clone, Copy)]
pub struct Meter<const BURST: u64, const INTERVAL_NS: u64> {
    /// Budget in nanoseconds of refill time; one token costs INTERVAL_NS.
    budget_ns: u64,
    last_ns: u64,
}

pub type ArrivalMeter = Meter<ARRIVAL_BURST, ARRIVAL_INTERVAL_NS>;
pub type ForwardBucket = Meter<FORWARD_BURST, FORWARD_INTERVAL_NS>;

impl<const BURST: u64, const INTERVAL_NS: u64> Default for Meter<BURST, INTERVAL_NS> {
    fn default() -> Self {
        Self { budget_ns: Self::CAPACITY_NS, last_ns: 0 }
    }
}

impl<const BURST: u64, const INTERVAL_NS: u64> Meter<BURST, INTERVAL_NS> {
    const CAPACITY_NS: u64 = BURST.saturating_mul(INTERVAL_NS);
    const HALF_NS: u64 = Self::CAPACITY_NS / 2;

    /// Budget at `now_ns`, refilled but not spent. A clock that goes
    /// backwards refills nothing.
    fn level_ns(&self, now_ns: u64) -> u64 {
        self.budget_ns.saturating_add(now_ns.saturating_sub(self.last_ns)).min(Self::CAPACITY_NS)
    }

    pub fn below_half(&self, now_ns: u64) -> bool {
        self.level_ns(now_ns) < Self::HALF_NS
    }

    /// Spends one token if there is one.
    pub fn allow(&mut self, now_ns: u64) -> bool {
        self.budget_ns = self.level_ns(now_ns);
        self.last_ns = self.last_ns.max(now_ns);
        if self.budget_ns < INTERVAL_NS {
            return false;
        }
        self.budget_ns = self.budget_ns.saturating_sub(INTERVAL_NS);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secret {
    Missing,
    /// At or past MAX_AGE, or born in the future (a clock that went back).
    Expired,
    Usable,
}

/// State edges from `tick_if_due`, each for one never-coalesced audit
/// event (plan C4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    /// `rotate` was called and succeeded.
    pub rotated: bool,
    /// The secret became unavailable (`CookieSecretUnavailable`): first
    /// failed `rotate` since a successful one.
    pub secret_unavailable: bool,
    /// Load left (`WgLoadCleared`).
    pub left_load: bool,
}

/// The cookie gate's state (plan C3). Under load is not stored but computed
/// on every call from the meters, the PD's backlog and
/// `under_load_until_ns`; only its announced edges are remembered.
///
/// The PD calls `take_load_entered` and `take_expired` after every
/// `classify` and after every `tick_if_due`, and emits `WgUnderLoad` before
/// that tick's `left_load`, so load events alternate.
#[derive(Debug, Clone, Default)]
pub struct Gate {
    arrivals: ArrivalMeter,
    forward: ForwardBucket,
    /// Load holds while `now` is before this: the last time a trigger held,
    /// plus UNDER_LOAD_AFTER_NS.
    under_load_until_ns: u64,
    born_ns: Option<u64>,
    /// Load entered and not yet taken by the PD.
    entered_load: bool,
    last_retry_ns: Option<u64>,
    /// The expiry backstop fired since the last successful rotation.
    expired_reported: bool,
    /// A failed rotation was reported since the last successful one.
    unavailable_reported: bool,
    /// Load as last announced by an edge, so `WgUnderLoad` and
    /// `WgLoadCleared` alternate. Needed beyond the plan's field list:
    /// `entered_load` is cleared when taken, so it cannot tell `tick_if_due`
    /// that a leaving edge is due.
    in_load: bool,
    /// Expiry edge raised by `classify` and not yet taken by the PD; the
    /// counterpart of `entered_load` for `CookieSecretExpired`.
    expired_edge: bool,
}

impl Gate {
    /// Whether load holds at `now_ns`, extending the hysteresis while a
    /// trigger holds and raising the entered edge. Does not refill or spend.
    fn observe_load(&mut self, now_ns: u64, backlog: usize) -> bool {
        let triggered = self.forward.below_half(now_ns) || self.arrivals.below_half(now_ns) || backlog >= BACKLOG_LOAD;
        if triggered {
            self.under_load_until_ns = self.under_load_until_ns.max(now_ns.saturating_add(UNDER_LOAD_AFTER_NS));
        }
        let loaded = triggered || now_ns < self.under_load_until_ns;
        if loaded && !self.in_load {
            self.in_load = true;
            self.entered_load = true;
        }
        loaded
    }

    fn secret(&self, now_ns: u64) -> Secret {
        match self.born_ns.map(|b| now_ns.checked_sub(b)) {
            None => Secret::Missing,
            Some(Some(age)) if age < COOKIE_SECRET_MAX_AGE_NS => Secret::Usable,
            Some(_) => Secret::Expired,
        }
    }

    /// The gate after mac1 passed (plan, "Under load").
    #[allow(clippy::too_many_arguments)] // each argument is an independent input the PD reads per frame (state, crypto, levels, frame); bundling them would only rename the list
    fn initiation<'a, C: CookieCrypto, const N: usize>(
        &mut self,
        crypto: &mut C,
        buckets: &mut Buckets<N>,
        now_ns: u64,
        backlog: usize,
        tx_free: usize,
        src: Endpoint,
        msg: &'a [u8; INITIATION_LEN],
        out: &mut [u8; COOKIE_REPLY_LEN],
    ) -> Outcome<'a> {
        // Measures offered load whether or not it has a token, so gating
        // cannot switch load off while a flood continues [M2].
        self.arrivals.allow(now_ns);
        if !self.observe_load(now_ns, backlog) {
            return self.forward(buckets, now_ns, src, msg, false);
        }
        // An all-zero mac2 is invalid by definition; skip its MAC [R2-S-N3].
        let mac2_zero = msg.get(INITIATION_MAC2_OFFSET..).is_none_or(|m| m.iter().all(|&b| b == 0));
        let secret = self.secret(now_ns);
        if !mac2_zero && secret == Secret::Usable && crypto.mac2_valid(src, msg) {
            return self.forward(buckets, now_ns, src, msg, true);
        }
        match secret {
            Secret::Missing => Outcome::NoCookieSecret,
            Secret::Expired => {
                if !self.expired_reported {
                    self.expired_reported = true;
                    self.expired_edge = true;
                }
                Outcome::CookieSecretExpired
            }
            Secret::Usable if tx_free > TX_RESERVE && crypto.seal_reply(src, msg, out) => {
                Outcome::CookieReply { dst: src, len: COOKIE_REPLY_LEN }
            }
            Secret::Usable => Outcome::CookieSuppressed,
        }
    }

    /// The single constructor of the outcome sent to `hs` (member set R42).
    /// The forward bucket is spent only when the source's budget allowed.
    fn forward<'a, const N: usize>(
        &mut self,
        buckets: &mut Buckets<N>,
        now_ns: u64,
        src: Endpoint,
        msg: &'a [u8; INITIATION_LEN],
        mac2_checked: bool,
    ) -> Outcome<'a> {
        if !buckets.allow(src.ip, now_ns) || !self.forward.allow(now_ns) {
            return Outcome::RateLimited;
        }
        Outcome::Initiation { src, msg, mac2_checked }
    }

    /// Runs on every handler-loop pass and on the timer tick, so a flood
    /// cannot postpone it. Rotates the secret once it reaches ROTATE_AT, or
    /// while none is held at most once per RETRY_INTERVAL; rotation is the
    /// only clearing. Also notices load leaving with no initiation arriving.
    pub fn tick_if_due<C: CookieCrypto>(&mut self, crypto: &mut C, now_ns: u64, backlog: usize) -> TickReport {
        let mut report = TickReport::default();
        let due = match self.born_ns {
            // A birth in the future (clock went back) rotates too.
            Some(b) => now_ns.checked_sub(b).is_none_or(|age| age >= ROTATE_AT_NS),
            None => self.last_retry_ns.is_none_or(|t| now_ns.saturating_sub(t) >= RETRY_INTERVAL_NS),
        };
        if due {
            self.last_retry_ns = Some(now_ns);
            if crypto.rotate() {
                self.born_ns = Some(now_ns);
                self.unavailable_reported = false;
                self.expired_reported = false;
                report.rotated = true;
            } else {
                self.born_ns = None;
                crypto.clear();
                report.secret_unavailable = !core::mem::replace(&mut self.unavailable_reported, true);
            }
        }
        if !self.observe_load(now_ns, backlog) && self.in_load {
            self.in_load = false;
            report.left_load = true;
        }
        report
    }

    /// Whether load was entered since the last call (`WgUnderLoad`).
    pub fn take_load_entered(&mut self) -> bool {
        core::mem::take(&mut self.entered_load)
    }

    /// Whether the expiry backstop fired for the first time since a valid
    /// secret, since the last call (`CookieSecretExpired`, never coalesced).
    pub fn take_expired(&mut self) -> bool {
        core::mem::take(&mut self.expired_edge)
    }
}

/// The PD's side of one handler-loop pass. Each input moves at most `max`
/// messages, through `ring::pass::drain`, and returns how many it moved.
pub trait PassIo {
    fn serve_hs(&mut self, max: usize) -> usize;
    fn serve_data(&mut self, max: usize) -> usize;
    fn tick(&mut self);
    fn serve_outside(&mut self, max: usize) -> usize;
    /// Notifies every peer this pass gave work to and flushes audit.
    fn end_pass(&mut self);
}

/// `ingress`'s pass order (plan, "Handler loop") for `ring::pass`.
struct Order<'a, T>(&'a mut T);

impl<T: PassIo> ring::pass::Pass for Order<'_, T> {
    fn serve(&mut self) -> bool {
        let n_hs = self.0.serve_hs(PASS_FRAMES);
        let n_data = self.0.serve_data(PASS_FRAMES);
        self.0.tick();
        let n_outside = self.0.serve_outside(PASS_FRAMES);
        ring::pass::any_full(&[n_hs, n_data, n_outside], PASS_FRAMES)
    }

    fn end_pass(&mut self) {
        self.0.end_pass();
    }
}

/// The handler loop (plan, "Handler loop"): every pass serves all three
/// inputs, at most PASS_FRAMES each, runs the tick between `serve_data` and
/// `serve_outside`, and ends with `end_pass`, so a flood on any input starves
/// neither the others, nor the tick, nor the peers waiting to be notified.
pub fn run_passes(io: &mut impl PassIo) {
    ring::pass::run_passes(&mut Order(io));
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
