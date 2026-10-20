//! `ingress` v2 decision logic (plan C14, M2.5 C3, M3 C4): answer ARP for
//! the outside address, classify WireGuard datagrams on the listen port and
//! Rosenpass datagrams on the Rosenpass port.
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
//! The Rosenpass envelope mac is reached the same way, through `RpMac`, so
//! this crate stays free of BLAKE2b and the KEMs.

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
    /// WireGuard's listen port.
    pub port: u16,
    /// Rosenpass's port; nonzero and distinct from `port` (config-validated).
    pub rp_port: u16,
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
    /// A datagram to the Rosenpass port, not yet vetted: the PD hands it to
    /// `rp_classify`, whose state is apart from the WireGuard path's.
    Rosenpass { src: Endpoint, payload: &'a [u8] },
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
            let src = Endpoint { ip: u.src, port: u.sport };
            if u.dport == cfg.port {
                classify(gate, crypto, mac1, buckets, now_ns, backlog, tx_free, src, u.payload, cookie)
            } else if u.dport == cfg.rp_port {
                Outcome::Rosenpass { src, payload: u.payload }
            } else {
                Outcome::NoService
            }
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

/// Builds an outbound datagram from our port `sport` (`cfg.port` or
/// `cfg.rp_port`) to `dst` via the router.
pub fn emit_udp(cfg: &Config, sport: u16, dst: Endpoint, payload: &[u8], out: &mut [u8]) -> Result<usize, EmitError> {
    wire::emit(
        &Frame {
            eth: EthAddrs { src: cfg.mac, dst: cfg.router_mac },
            body: Body::Udp4(Udp4 { src: cfg.ipv4, dst: dst.ip, sport, dport: dst.port, payload }),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Full, as of `now_ns`.
    fn full_at(now_ns: u64) -> Self {
        Self { budget_ns: Self::CAPACITY_NS, last_ns: now_ns }
    }

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
    /// Load entered and not yet taken by the PD.
    entered_load: bool,
    /// Load as last announced by an edge, so `WgUnderLoad` and
    /// `WgLoadCleared` alternate. Needed beyond the plan's field list:
    /// `entered_load` is cleared when taken, so it cannot tell `tick_if_due`
    /// that a leaving edge is due.
    in_load: bool,
    /// The cookie secret's age and edges, shared with `RpGate` (M3b C5).
    life: SecretLife,
}

/// When a cookie secret is born, due, usable and reported, shared by the
/// WireGuard and the Rosenpass gates (M3b plan C5). Holds no secret: each
/// gate's PD adapter does, and `tick_if_due` only says when to call it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretLife {
    born_ns: Option<u64>,
    last_retry_ns: Option<u64>,
    /// The expiry backstop fired since the last successful rotation.
    expired_reported: bool,
    /// A failed rotation was reported since the last successful one.
    unavailable_reported: bool,
    /// Expiry edge raised by a classification and not yet taken by the PD;
    /// the counterpart of `entered_load` for `CookieSecretExpired`.
    expired_edge: bool,
}

impl SecretLife {
    fn secret(&self, now_ns: u64) -> Secret {
        match self.born_ns.map(|b| now_ns.checked_sub(b)) {
            None => Secret::Missing,
            Some(Some(age)) if age < COOKIE_SECRET_MAX_AGE_NS => Secret::Usable,
            Some(_) => Secret::Expired,
        }
    }

    /// The expiry backstop fired; raises the edge the first time since a
    /// valid secret.
    fn note_expired(&mut self) {
        if !self.expired_reported {
            self.expired_reported = true;
            self.expired_edge = true;
        }
    }

    /// Rotates once the secret reaches ROTATE_AT, or while none is held at
    /// most once per RETRY_INTERVAL; a birth in the future (clock went back)
    /// rotates too. `rotate` refills the PD's secret; on failure `clear`
    /// zeroizes it. Returns (rotated, unavailable edge).
    fn tick(&mut self, now_ns: u64, rotate: impl FnOnce() -> bool, clear: impl FnOnce()) -> (bool, bool) {
        let due = match self.born_ns {
            Some(b) => now_ns.checked_sub(b).is_none_or(|age| age >= ROTATE_AT_NS),
            None => self.last_retry_ns.is_none_or(|t| now_ns.saturating_sub(t) >= RETRY_INTERVAL_NS),
        };
        if !due {
            return (false, false);
        }
        self.last_retry_ns = Some(now_ns);
        if rotate() {
            self.born_ns = Some(now_ns);
            self.unavailable_reported = false;
            self.expired_reported = false;
            (true, false)
        } else {
            self.born_ns = None;
            clear();
            (false, !core::mem::replace(&mut self.unavailable_reported, true))
        }
    }

    fn take_expired(&mut self) -> bool {
        core::mem::take(&mut self.expired_edge)
    }
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
        let secret = self.life.secret(now_ns);
        if !mac2_zero && secret == Secret::Usable && crypto.mac2_valid(src, msg) {
            return self.forward(buckets, now_ns, src, msg, true);
        }
        match secret {
            Secret::Missing => Outcome::NoCookieSecret,
            Secret::Expired => {
                self.life.note_expired();
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
        let crypto = core::cell::RefCell::new(crypto);
        (report.rotated, report.secret_unavailable) =
            self.life.tick(now_ns, || crypto.borrow_mut().rotate(), || crypto.borrow_mut().clear());
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
        self.life.take_expired()
    }
}

// ---- Rosenpass (M3 plan C4) ----

/// The Rosenpass messages a responder accepts, with their wire lengths
/// (rosenpass-wire's values, which this crate does not depend on; the PD
/// asserts the two agree). Every other type is dropped [F7, S5].
pub const RP_MSG_INIT_HELLO: u8 = 0x81;
pub const RP_INIT_HELLO_LEN: usize = 1092;
pub const RP_MSG_INIT_CONF: u8 = 0x83;
pub const RP_INIT_CONF_LEN: usize = 176;

/// Verifies a Rosenpass envelope mac under the gateway's build-time key
/// `lhash("mac", spkm)`. Like mac1 it needs only public data, so it is no
/// authentication, but it keeps blind floods from spending any meter.
pub trait RpMac {
    fn verify(&self, msg: &[u8]) -> bool;
}

// Rosenpass meters (plan C4, "Buckets"), sized from the measured cost
// (deviation log, MCE-COST): an InitHello costs `pq` 8.5 s median, 16.1 s
// max of wall time at its committed budget under TCG, an InitConf under
// 1 ms. One InitHello per source per 20 s, since an initiator's
// retransmissions of one InitHello need only one answer and each would
// otherwise cost another decapsulation. Globally a burst of 8 (one per peer
// after a reboot) and one per 10 s, 12 per 120 s rekey interval, which
// covers 8 peers' rekeys with room for retransmissions.
pub const RP_HELLO_SRC_BURST: u64 = 1;
pub const RP_HELLO_SRC_INTERVAL_NS: u64 = 20_000_000_000;
pub const RP_HELLO_GLOBAL_BURST: u64 = 8;
pub const RP_HELLO_GLOBAL_INTERVAL_NS: u64 = 10_000_000_000;
pub const RP_CONF_SRC_BURST: u64 = 3;
pub const RP_CONF_SRC_INTERVAL_NS: u64 = 1_000_000_000;
pub const RP_CONF_GLOBAL_BURST: u64 = 8;
pub const RP_CONF_GLOBAL_INTERVAL_NS: u64 = 50_000_000;
/// InitHellos `ingress` lets be unreturned on the `ingress`→`pq` link at
/// once, the one `pq` is working on included: `pq` returns a buffer only
/// after its completion record (M3b plan, S14). Each costs `pq` seconds
/// (MCE-COST), so a deeper queue would only delay the InitConfs behind it.
pub const RP_HELLO_IN_FLIGHT: usize = 2;
/// InitConfs likewise. InitHellos never take these slots, nor InitConfs
/// InitHello's [S-3].
pub const RP_CONF_IN_FLIGHT: usize = 8;
/// Forwards unreturned at once (the "pq ring backlog" of the C2 key-bucket
/// assertion), and so the most completion records ever owed.
pub const RP_IN_FLIGHT: usize = RP_HELLO_IN_FLIGHT + RP_CONF_IN_FLIGHT;

const _: () = assert!(RP_HELLO_IN_FLIGHT > 0 && RP_CONF_IN_FLIGHT > 0, "an empty Rosenpass share");
const _: () = assert!(RP_IN_FLIGHT <= NET_BUFFERS, "RP_IN_FLIGHT above the link's buffers");
// One drain of the completion link empties it whenever `pq` is honest.
const _: () = assert!(RP_IN_FLIGHT < PASS_FRAMES, "RP_IN_FLIGHT not below PASS_FRAMES");
// A single source can never be allowed more than all sources together.
const _: () = assert!(RP_HELLO_SRC_INTERVAL_NS >= RP_HELLO_GLOBAL_INTERVAL_NS, "RP_HELLO source rate above global");
const _: () = assert!(RP_CONF_SRC_INTERVAL_NS >= RP_CONF_GLOBAL_INTERVAL_NS, "RP_CONF source rate above global");

/// Per-source meters in a fixed table, with `Buckets`' replacement rule: a
/// new source takes a free slot or evicts the least recently used one, so a
/// spoofed-source flood churns budgets and the global meter bounds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMeters<const N: usize, const BURST: u64, const INTERVAL_NS: u64> {
    slots: [Option<(Ipv4, Meter<BURST, INTERVAL_NS>)>; N],
}

impl<const N: usize, const BURST: u64, const INTERVAL_NS: u64> Default for SourceMeters<N, BURST, INTERVAL_NS> {
    fn default() -> Self {
        Self { slots: [None; N] }
    }
}

impl<const N: usize, const BURST: u64, const INTERVAL_NS: u64> SourceMeters<N, BURST, INTERVAL_NS> {
    pub fn allow(&mut self, ip: Ipv4, now_ns: u64) -> bool {
        let slot = match self.slots.iter().position(|s| s.is_some_and(|(i, _)| i == ip)) {
            Some(i) => i,
            None => {
                // Free slots sort first (key 0), then the oldest.
                let victim = self
                    .slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.map_or(0, |(_, m)| m.last_ns.saturating_add(1)))
                    .map_or(0, |(i, _)| i);
                if let Some(s) = self.slots.get_mut(victim) {
                    *s = Some((ip, Meter::full_at(now_ns)));
                }
                victim
            }
        };
        self.slots.get_mut(slot).and_then(Option::as_mut).is_some_and(|(_, m)| m.allow(now_ns))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpKind {
    Hello,
    Conf,
}

/// What `pq` has said about a forward (M3b plan, "Reply ownership").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    AwaitingRecord,
    CompletedReply,
    CompletedNoReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    kind: RpKind,
    /// Where the forward came from: the only destination its reply may have.
    src: Endpoint,
    state: EntryState,
}

const NO_ENTRY: Entry = Entry { kind: RpKind::Hello, src: Endpoint { ip: [0; 4], port: 0 }, state: EntryState::AwaitingRecord };

/// The forwards sent to `pq` whose return `ingress` has not yet seen,
/// oldest first. It is also the table of what `pq` may answer: each entry
/// takes exactly one completion record, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InFlight {
    entries: [Entry; RP_IN_FLIGHT],
    head: usize,
    len: usize,
}

impl Default for InFlight {
    fn default() -> Self {
        Self { entries: [NO_ENTRY; RP_IN_FLIGHT], head: 0, len: 0 }
    }
}

impl InFlight {
    fn get(&self, i: usize) -> Option<&Entry> {
        if i >= self.len {
            return None;
        }
        self.entries.get(self.head.wrapping_add(i) % RP_IN_FLIGHT)
    }

    fn get_mut(&mut self, i: usize) -> Option<&mut Entry> {
        if i >= self.len {
            return None;
        }
        self.entries.get_mut(self.head.wrapping_add(i) % RP_IN_FLIGHT)
    }

    fn count(&self, kind: RpKind) -> usize {
        (0..self.len).filter(|i| self.get(*i).is_some_and(|e| e.kind == kind)).count()
    }

    fn push(&mut self, kind: RpKind, src: Endpoint) -> bool {
        if self.len >= RP_IN_FLIGHT {
            return false;
        }
        let Some(e) = self.entries.get_mut(self.head.wrapping_add(self.len) % RP_IN_FLIGHT) else {
            return false;
        };
        *e = Entry { kind, src, state: EntryState::AwaitingRecord };
        self.len = self.len.saturating_add(1);
        true
    }

    /// The oldest entry still waiting for its record.
    fn first_awaiting(&mut self) -> Option<&mut Entry> {
        let i = (0..self.len).find(|i| self.get(*i).is_some_and(|e| e.state == EntryState::AwaitingRecord))?;
        self.get_mut(i)
    }

    /// Drops the `r` oldest entries; `r` was checked against `len`.
    fn pop(&mut self, r: usize) {
        let r = r.min(self.len);
        self.head = self.head.wrapping_add(r) % RP_IN_FLIGHT;
        self.len = self.len.saturating_sub(r);
    }
}

/// The Rosenpass path's state: its own meters and ring accounting, apart
/// from the WireGuard path's `Gate` and `Buckets`, so a flood on either
/// leaves the other's meters untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpGate<const N: usize> {
    hello_src: SourceMeters<N, RP_HELLO_SRC_BURST, RP_HELLO_SRC_INTERVAL_NS>,
    hello_global: Meter<RP_HELLO_GLOBAL_BURST, RP_HELLO_GLOBAL_INTERVAL_NS>,
    conf_src: SourceMeters<N, RP_CONF_SRC_BURST, RP_CONF_SRC_INTERVAL_NS>,
    conf_global: Meter<RP_CONF_GLOBAL_BURST, RP_CONF_GLOBAL_INTERVAL_NS>,
    in_flight: InFlight,
    /// Sticky: `pq`'s records and returns fell out of step, so no entry can
    /// be trusted. Nothing more is forwarded, relayed or retired until
    /// reboot (M3b plan, R4-F2).
    pq_dead: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpOutcome<'a> {
    /// The only outcomes the PD sends to `pq`, each built by one
    /// constructor (`rp_forward_hello`, `rp_forward_conf`).
    ForwardHello { src: Endpoint, msg: &'a [u8; RP_INIT_HELLO_LEN] },
    ForwardConf { src: Endpoint, msg: &'a [u8; RP_INIT_CONF_LEN] },
    /// Not an InitHello or InitConf of its exact length.
    TypeDropped,
    BadMac,
    /// Over the source's or the global meter of its type.
    RateLimited,
    /// No room on the link for its type: its kind's slots are all taken.
    RingReserved,
    /// The `pq` path stopped for good (`pq_sync_dead`); nothing is sent.
    PqDown,
}

/// Rosenpass checks on a datagram addressed to the Rosenpass port, in
/// order: type and exact length, then the mac, then the forward
/// constructor of its type. Nothing spends a meter before the mac passed.
pub fn rp_classify<'a, M: RpMac, const N: usize>(
    gate: &mut RpGate<N>,
    mac: &M,
    now_ns: u64,
    src: Endpoint,
    payload: &'a [u8],
) -> RpOutcome<'a> {
    match payload.first() {
        Some(&RP_MSG_INIT_HELLO) => {
            let Ok(msg) = <&[u8; RP_INIT_HELLO_LEN]>::try_from(payload) else {
                return RpOutcome::TypeDropped;
            };
            if !mac.verify(msg) {
                return RpOutcome::BadMac;
            }
            gate.rp_forward_hello(now_ns, src, msg)
        }
        Some(&RP_MSG_INIT_CONF) => {
            let Ok(msg) = <&[u8; RP_INIT_CONF_LEN]>::try_from(payload) else {
                return RpOutcome::TypeDropped;
            };
            if !mac.verify(msg) {
                return RpOutcome::BadMac;
            }
            gate.rp_forward_conf(now_ns, src, msg)
        }
        _ => RpOutcome::TypeDropped,
    }
}

/// Whether a Rosenpass reply (RespHello, EmptyData) may take a TX buffer.
/// Each answers a mac-valid initiator message, which proves nothing about
/// its sender, so it stays out of the reserve as cookie replies do.
pub fn rp_reply_allowed(tx_free: usize) -> bool {
    tx_free > TX_RESERVE
}

impl<const N: usize> RpGate<N> {
    /// The single constructor of `ForwardHello`.
    fn rp_forward_hello<'a>(&mut self, now_ns: u64, src: Endpoint, msg: &'a [u8; RP_INIT_HELLO_LEN]) -> RpOutcome<'a> {
        match self.admit(RpKind::Hello, now_ns, src.ip) {
            Ok(()) => RpOutcome::ForwardHello { src, msg },
            Err(refused) => refused,
        }
    }

    /// The single constructor of `ForwardConf`.
    fn rp_forward_conf<'a>(&mut self, now_ns: u64, src: Endpoint, msg: &'a [u8; RP_INIT_CONF_LEN]) -> RpOutcome<'a> {
        match self.admit(RpKind::Conf, now_ns, src.ip) {
            Ok(()) => RpOutcome::ForwardConf { src, msg },
            Err(refused) => refused,
        }
    }

    /// The `pq` path first, then room on the link, so a refusal there
    /// spends nothing; then the source's meter, then the global one (spent
    /// only if the source had a token). Nothing is counted here: the PD
    /// calls `sent` once the forward is on the link.
    fn admit(&mut self, kind: RpKind, now_ns: u64, ip: Ipv4) -> Result<(), RpOutcome<'static>> {
        if self.pq_dead {
            return Err(RpOutcome::PqDown);
        }
        let cap = match kind {
            RpKind::Hello => RP_HELLO_IN_FLIGHT,
            RpKind::Conf => RP_CONF_IN_FLIGHT,
        };
        if self.in_flight.len >= RP_IN_FLIGHT || self.in_flight.count(kind) >= cap {
            return Err(RpOutcome::RingReserved);
        }
        let allowed = match kind {
            RpKind::Hello => self.hello_src.allow(ip, now_ns) && self.hello_global.allow(now_ns),
            RpKind::Conf => self.conf_src.allow(ip, now_ns) && self.conf_global.allow(now_ns),
        };
        if !allowed {
            return Err(RpOutcome::RateLimited);
        }
        Ok(())
    }

    /// Forwards of `kind` whose return has not been seen.
    pub fn in_flight(&self, kind: RpKind) -> usize {
        self.in_flight.count(kind)
    }

    /// Whether the `pq` path has stopped for good.
    pub fn pq_dead(&self) -> bool {
        self.pq_dead
    }

    /// Records a forward the PD just put on the link, as awaiting its
    /// record. Only a send that succeeded is recorded, so a failed send
    /// leaves nothing. A forward with no room to be recorded cannot be
    /// paired with its record, which stops the `pq` path.
    pub fn sent(&mut self, kind: RpKind, src: Endpoint) {
        if !self.in_flight.push(kind, src) {
            self.pq_dead = true;
        }
    }

    /// Pairs `pq`'s next completion record with the oldest forward still
    /// waiting for one. A `Reply` must be that forward's reply type and goes
    /// to its stored source, never to anything the record says. An extra
    /// record, a wrong type, a malformed record or an index outside
    /// `peers` stops the `pq` path.
    pub fn complete<'r>(&mut self, record: &'r [u8], peers: usize) -> Result<Completion<'r>, SyncDead> {
        if self.pq_dead {
            return Err(SyncDead);
        }
        let pairing = msgs::RpReply::decode(record).ok().and_then(|r| {
            let e = self.in_flight.first_awaiting()?;
            match r {
                msgs::RpReply::NoReply => {
                    e.state = EntryState::CompletedNoReply;
                    Some(None)
                }
                msgs::RpReply::Reply { index, msg } => {
                    let peer = match (e.kind, msg.len()) {
                        (RpKind::Hello, RP_RESP_HELLO_LEN) if index == msgs::RP_NO_PEER => None,
                        (RpKind::Conf, RP_EMPTY_DATA_LEN) if usize::from(index) < peers => Some(index),
                        _ => return None,
                    };
                    e.state = EntryState::CompletedReply;
                    Some(Some((e.src, e.kind, peer)))
                }
            }
        });
        let reply = record.get(2..).unwrap_or(&[]);
        match pairing {
            Some(Some((dst, kind, peer))) => Ok(Completion::Reply { dst, kind, peer, msg: reply }),
            Some(None) => Ok(Completion::NoReply),
            None => {
                self.pq_dead = true;
                Err(SyncDead)
            }
        }
    }

    /// Retires the `r` oldest forwards, whose returns the sync observed,
    /// only if each has its record; otherwise the `pq` path stops and
    /// nothing is retired.
    fn retire(&mut self, r: usize) -> Result<(), SyncDead> {
        let all_done = r <= self.in_flight.len
            && (0..r).all(|i| self.in_flight.get(i).is_some_and(|e| e.state != EntryState::AwaitingRecord));
        if self.pq_dead || !all_done {
            self.pq_dead = true;
            return Err(SyncDead);
        }
        self.in_flight.pop(r);
        Ok(())
    }
}

/// The reply lengths `pq` answers with (rosenpass-wire's, which this crate
/// does not depend on; the PD asserts the two agree).
pub const RP_RESP_HELLO_LEN: usize = 1132;
pub const RP_EMPTY_DATA_LEN: usize = 64;

/// The `pq` path broke its completion protocol; it is now stopped for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncDead;

/// What one completion record means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion<'a> {
    /// Send `msg` to `dst`, the stored source of the forward it answers.
    /// `peer` is the configured peer of an EmptyData.
    Reply { dst: Endpoint, kind: RpKind, peer: Option<u8>, msg: &'a [u8] },
    NoReply,
}

/// The longest completion record: tag, index, RespHello.
pub const RP_RECORD_MAX: usize = 2 + RP_RESP_HELLO_LEN;

/// The PD's side of a sync with `pq` (M3b plan C2/C3). It mirrors `PassIo`:
/// the order lives in `sync_pq`, and the PD only moves bytes.
pub trait PqSync {
    /// Buffers `pq` still holds on the `ingress`→`pq` link, read after a
    /// validated reclaim; `None` on a link error.
    fn outstanding(&mut self) -> Option<usize>;
    /// Copies the next completion record into `out`: `None` when the link
    /// is empty, `Some(None)` for a record that could not be read.
    fn next_record(&mut self, out: &mut [u8; RP_RECORD_MAX]) -> Option<Option<usize>>;
    /// Sends `reply` to `dst`; false when it could not go out. The PD gets
    /// no index and no record, so it cannot choose another destination.
    fn transmit(&mut self, dst: Endpoint, reply: &[u8]) -> bool;
}

/// How one sync ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Every observed return was retired; `relayed` replies went out.
    Synced { relayed: usize },
    /// This sync found the protocol broken (audit `RpPqSyncDead` once).
    DiedNow,
    /// The path was already stopped; nothing was done.
    Dead,
}

/// One sync with `pq`, in the only order the completion protocol allows
/// (M3b plan, "The sync"):
///
/// 1. snapshot how many forwards `pq` has returned;
/// 2. drain every completion record, pairing each with the oldest forward
///    still waiting and sending each reply to that forward's source;
/// 3. retire exactly the snapshotted returns, if each has its record.
///
/// `pq` sends a forward's record before returning its buffer, so every
/// return counted in step 1 has its record visible in step 2. A return
/// after the snapshot waits for the next sync.
pub fn sync_pq<T: PqSync, const N: usize>(gate: &mut RpGate<N>, io: &mut T, peers: usize) -> SyncOutcome {
    if gate.pq_dead {
        return SyncOutcome::Dead;
    }
    let len_before = gate.in_flight.len;
    let returned = io.outstanding().and_then(|outstanding| len_before.checked_sub(outstanding));
    let Some(returned) = returned else {
        gate.pq_dead = true;
        return SyncOutcome::DiedNow;
    };
    let mut relayed = 0usize;
    let mut out = [0u8; RP_RECORD_MAX];
    let mut drained = 0usize;
    while let Some(read) = io.next_record(&mut out) {
        // An honest `pq` owes at most RP_IN_FLIGHT records (< PASS_FRAMES).
        drained = drained.saturating_add(1);
        let record = read.filter(|_| drained <= PASS_FRAMES).and_then(|n| out.get(..n));
        let Some(record) = record else {
            gate.pq_dead = true;
            return SyncOutcome::DiedNow;
        };
        match gate.complete(record, peers) {
            Ok(Completion::Reply { dst, msg, .. }) => {
                if io.transmit(dst, msg) {
                    relayed = relayed.saturating_add(1);
                }
            }
            Ok(Completion::NoReply) => {}
            Err(SyncDead) => return SyncOutcome::DiedNow,
        }
    }
    out.fill(0);
    match gate.retire(returned) {
        Ok(()) => SyncOutcome::Synced { relayed },
        Err(SyncDead) => SyncOutcome::DiedNow,
    }
}

/// The PD's side of one handler-loop pass. Each input moves at most `max`
/// messages, through `ring::pass::drain`, and returns how many it moved.
pub trait PassIo {
    fn serve_hs(&mut self, max: usize) -> usize;
    /// Rosenpass replies from `pq`.
    fn serve_pq(&mut self, max: usize) -> usize;
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
        let n_pq = self.0.serve_pq(PASS_FRAMES);
        let n_data = self.0.serve_data(PASS_FRAMES);
        self.0.tick();
        let n_outside = self.0.serve_outside(PASS_FRAMES);
        ring::pass::any_full(&[n_hs, n_pq, n_data, n_outside], PASS_FRAMES)
    }

    fn end_pass(&mut self) {
        self.0.end_pass();
    }
}

/// The handler loop (plan, "Handler loop"): every pass serves all four
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
