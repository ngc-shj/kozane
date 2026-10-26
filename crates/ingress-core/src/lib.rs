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
//!
//! M6 (plan C2): TCP to the HTTPS port, past its buckets, goes to `tls` as
//! an IP packet, and `tls_egress` is the one gate for what `tls` sends out.

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
use wire::{ArpOp, ArpPacket, Body, DropReason, EmitError, EthAddrs, Frame, IPPROTO_TCP, Ipv4, Mac, Udp4};

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
    /// The HTTPS endpoint's TCP port (`tls`); nonzero (config-validated).
    pub https_port: u16,
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
    /// TCP to our HTTPS port, within its buckets: `packet` (the IPv4
    /// datagram, not the frame) goes to `tls` (M6 plan C2).
    Tls { packet: &'a [u8] },
    /// TCP to our HTTPS port over one of its buckets.
    TcpLimited(TcpLimit),
}

/// Which TCP bucket refused a segment (audited as `TcpLimited`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpLimit {
    SynSource,
    SynGlobal,
    Data,
}

const BROADCAST: Mac = [0xff; 6];

#[allow(clippy::too_many_arguments)] // each argument is an independent input the PD reads per frame (state, crypto, levels, frame); bundling them would only rename the list
pub fn respond<'a, C: CookieCrypto, M: Mac1, const N: usize, const S: usize>(
    cfg: &Config,
    gate: &mut Gate,
    crypto: &mut C,
    mac1: &M,
    buckets: &mut Buckets<N>,
    tcp: &mut TcpGate<S>,
    now_ns: u64,
    backlog: usize,
    tx_free: usize,
    frame: &'a [u8],
    out: &mut [u8],
    cookie: &mut [u8; COOKIE_REPLY_LEN],
) -> Outcome<'a> {
    let f = match wire::parse_frame(frame) {
        Ok(f) => f,
        // `parse_frame` and its proof stay ARP and UDP only (M6 plan C2):
        // TCP is a second parse of what it refused.
        Err(DropReason::NotUdp) => return tcp.admit(cfg, now_ns, frame),
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
    if !rp_tx_allowed(TxTier::Unsolicited, tx_free) {
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
/// (M2.5 plan C3, C5). The burst `B` and interval `I` default to the
/// initiation limiter's; `tls`'s SYN table has its own (M6 plan C2).
#[derive(Debug, Clone)]
pub struct Buckets<const N: usize, const B: u64 = BURST, const I: u64 = INTERVAL_NS> {
    slots: [Option<Bucket>; N],
}

impl<const N: usize, const B: u64, const I: u64> Default for Buckets<N, B, I> {
    fn default() -> Self {
        Self { slots: [None; N] }
    }
}

impl<const N: usize, const B: u64, const I: u64> Buckets<N, B, I> {
    const CAPACITY_NS: u64 = B.saturating_mul(I);

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
                    *s = Some(Bucket { ip, budget_ns: Self::CAPACITY_NS, last_ns: now_ns });
                }
                victim
            }
        };
        let Some(Some(b)) = self.slots.get_mut(slot) else {
            return false;
        };
        // A clock that goes backwards refills nothing.
        let elapsed = now_ns.saturating_sub(b.last_ns);
        b.budget_ns = b.budget_ns.saturating_add(elapsed).min(Self::CAPACITY_NS);
        b.last_ns = b.last_ns.max(now_ns);
        if b.budget_ns < I {
            return false;
        }
        b.budget_ns = b.budget_ns.saturating_sub(I);
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
/// Replies `ingress` makes up itself, and Rosenpass answers, may use only
/// the TX buffers above this; the rest stays for `hs` and `data` [R2-F-F4].
const TX_RESERVE: usize = NET_BUFFERS / 2;
/// Of the buffers above the reserve, the share Rosenpass answers (RespHello,
/// EmptyData: replies to metered, forwarded work) keep from replies an
/// attacker can elicit for free (cookie replies of both gates, ARP) (M3b
/// plan, S2).
pub const RP_ANSWER_SHARE: usize = 8;
const _: () = assert!(0 < RP_ANSWER_SHARE && RP_ANSWER_SHARE < NET_BUFFERS - TX_RESERVE, "RP_ANSWER_SHARE out of range");

/// Of the buffers above the reserve, the share `tls`'s segments (M6 plan
/// C2) leave to everything else: HTTPS takes a TX buffer only where an
/// unsolicited reply could too, so `hs`, `data` and Rosenpass keep theirs
/// whatever a flood at 443 makes `tls` send.
pub const TLS_TX_SHARE: usize = 16;
const _: () = assert!(
    TLS_TX_SHARE >= RP_ANSWER_SHARE && TLS_TX_SHARE < NET_BUFFERS - TX_RESERVE,
    "TLS_TX_SHARE below the Unsolicited tier or out of range"
);

/// Who may take a TX buffer (M3b plan, "TX tiers").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxTier {
    /// RespHello and EmptyData.
    Answer,
    /// Cookie replies (WireGuard and Rosenpass) and ARP replies.
    Unsolicited,
    /// `tls`'s TCP segments (M6 plan C2).
    Tls,
}

/// Whether a reply of `tier` may take a TX buffer with `tx_free` free: an
/// unsolicited one is never allowed where an answer would be refused (I8),
/// nor a `tls` segment where an unsolicited reply would be.
pub fn rp_tx_allowed(tier: TxTier, tx_free: usize) -> bool {
    match tier {
        TxTier::Answer => tx_free > TX_RESERVE,
        TxTier::Unsolicited => tx_free > TX_RESERVE + RP_ANSWER_SHARE,
        TxTier::Tls => tx_free > TX_RESERVE + TLS_TX_SHARE,
    }
}

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

    /// Whole tokens available at `now_ns`, refilled but not spent.
    pub fn tokens(&self, now_ns: u64) -> u64 {
        self.level_ns(now_ns).checked_div(INTERVAL_NS).unwrap_or(0)
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
            Secret::Usable if rp_tx_allowed(TxTier::Unsolicited, tx_free) && crypto.seal_reply(src, msg, out) => {
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

// ---- TCP to the HTTPS endpoint (M6 plan C2) ----

// SYNs: a listener holds a slot for each until its 5 s timeout (smoltcp
// has no SYN cookies, RM6-7), and each completed handshake costs `tls` and
// `tlskey` a signature, so new connections are metered per source and
// globally. A source's burst of 4 at one per 250 ms covers a browser's
// parallel connections; globally 16 at one per 50 ms (20 per second), the
// forwarded handshake rate that `tlskey`'s sign bucket is sized against
// (M6 plan C12; the global values live in `limits`, which both share).
pub const SYN_SRC_BURST: u64 = 4;
pub const SYN_SRC_INTERVAL_NS: u64 = 250_000_000;
pub use limits::{SYN_GLOBAL_BURST, SYN_GLOBAL_INTERVAL_NS};
// Every other segment to the port, globally: a burst of one `itl` ring
// and 10 000 segments per second, about 14.6 MB/s of 1460-byte segments
// into `tls` (recorded per F-N11). Spoofed segments spend it too, stalling
// HTTPS but nothing else (RM6-7).
pub const TCP_DATA_BURST: u64 = NET_BUFFERS as u64;
pub const TCP_DATA_INTERVAL_NS: u64 = 100_000;

// A single source can never be allowed more than all sources together.
const _: () = assert!(SYN_SRC_INTERVAL_NS >= SYN_GLOBAL_INTERVAL_NS, "SYN source rate above global");
const _: () = assert!(SYN_SRC_BURST <= SYN_GLOBAL_BURST, "SYN source burst above global");

/// `ingress`'s TCP state: SYNs pass a per-source and a global bucket,
/// every other segment a global data bucket of its own (M6 plan C2, F11).
#[derive(Debug, Clone, Default)]
pub struct TcpGate<const N: usize> {
    syn_sources: Buckets<N, SYN_SRC_BURST, SYN_SRC_INTERVAL_NS>,
    syn_global: Meter<SYN_GLOBAL_BURST, SYN_GLOBAL_INTERVAL_NS>,
    data: Meter<TCP_DATA_BURST, TCP_DATA_INTERVAL_NS>,
}

impl<const N: usize> TcpGate<N> {
    /// A frame `parse_frame` refused as NotUdp. Only a TCP segment to our
    /// MAC, address and HTTPS port, from neither our address nor our MAC,
    /// and within its buckets goes to `tls`; any other TCP has no service
    /// and any other protocol stays NotUdp.
    fn admit<'a>(&mut self, cfg: &Config, now_ns: u64, frame: &'a [u8]) -> Outcome<'a> {
        let f = match wire::parse_frame_ip(frame) {
            Ok(f) => f,
            Err(r) => return Outcome::Dropped(r),
        };
        let p = match f.body {
            Body::Ipv4(p) if p.proto == IPPROTO_TCP => p,
            _ => return Outcome::Dropped(DropReason::NotUdp),
        };
        let t = match wire::parse_tcp(&p) {
            Ok(t) => t,
            Err(r) => return Outcome::Dropped(r),
        };
        if f.eth.dst != cfg.mac
            || p.dst != cfg.ipv4
            || t.dst_port != cfg.https_port
            || p.src == cfg.ipv4
            || f.eth.src == cfg.mac
        {
            return Outcome::NoService;
        }
        // The global bucket is spent only when the source's allowed.
        if t.is_syn_request() {
            if !self.syn_sources.allow(p.src, now_ns) {
                return Outcome::TcpLimited(TcpLimit::SynSource);
            }
            if !self.syn_global.allow(now_ns) {
                return Outcome::TcpLimited(TcpLimit::SynGlobal);
            }
        } else if !self.data.allow(now_ns) {
            return Outcome::TcpLimited(TcpLimit::Data);
        }
        Outcome::Tls { packet: p.packet }
    }
}

/// Why `tls_egress` refused a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// Malformed, or not TCP from our HTTPS port to a remote unicast
    /// address (`DropReason::TcpEgressRefused`).
    Dropped(DropReason),
    /// No TX buffer above `tls`'s tier.
    TxReserve,
}

/// Not unspecified, broadcast, multicast, loopback or reserved (240/4).
fn remote_unicast(a: Ipv4) -> bool {
    a != [0; 4] && a != [255; 4] && a[0] & 0xf0 != 0xe0 && a[0] & 0xf0 != 0xf0 && a[0] != 127
}

/// The one gate for what `tls` sends out (M6 plan C2, F2, S2, S3): a
/// packet from `tli` leaves only as a valid IPv4/TCP datagram of at most
/// 1500 bytes, both checksums right, from our address and HTTPS port to a
/// remote unicast address, never a SYN without ACK (`tls` opens no
/// connections), framed to the router (no ARP cache), and only while more
/// than `TX_RESERVE + TLS_TX_SHARE` TX buffers are free.
pub fn tls_egress<'a>(cfg: &Config, packet: &'a [u8], tx_free: usize) -> Result<Frame<'a>, EgressRefusal> {
    let refused = EgressRefusal::Dropped(DropReason::TcpEgressRefused);
    if packet.len() > wire::MAX_FRAME - wire::ETH_HDR {
        return Err(EgressRefusal::Dropped(DropReason::TooLong));
    }
    let p = wire::parse_ipv4_packet(packet).map_err(EgressRefusal::Dropped)?;
    if p.proto != IPPROTO_TCP {
        return Err(refused);
    }
    let t = wire::parse_tcp(&p).map_err(EgressRefusal::Dropped)?;
    if p.src != cfg.ipv4 || t.src_port != cfg.https_port || p.dst == cfg.ipv4 || !remote_unicast(p.dst) {
        return Err(refused);
    }
    if t.is_syn_request() {
        return Err(refused);
    }
    if !rp_tx_allowed(TxTier::Tls, tx_free) {
        return Err(EgressRefusal::TxReserve);
    }
    Ok(Frame { eth: EthAddrs { src: cfg.mac, dst: cfg.router_mac }, body: Body::Ipv4(p) })
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

/// The Rosenpass CookieReply's length: the InitHello's, so it never
/// amplifies.
pub const RP_COOKIE_REPLY_LEN: usize = RP_INIT_HELLO_LEN;
/// Where the cookie field starts in an InitHello (the envelope's last 16
/// bytes).
pub const RP_COOKIE_AT: usize = RP_INIT_HELLO_LEN - 16;
/// Where the session ids start in every envelope (after type and reserved):
/// RespHello `sidr ‖ sidi`, InitConf `sidi ‖ sidr`, EmptyData `sid`.
pub const RP_SID_AT: usize = 4;

/// The Rosenpass cookie secret's operations (M3b plan C2/C3). The PD's
/// adapter owns the current and previous secrets; this crate only decides
/// when each call may happen.
pub trait RpCookieCheck {
    /// Whether `msg`'s cookie field is valid for `src` under the current or
    /// the previous secret (constant time, fail-closed).
    fn valid(&self, src: Endpoint, msg: &[u8; RP_INIT_HELLO_LEN]) -> bool;
    /// Writes the CookieReply to `msg` from `src` into `out`.
    fn seal(&mut self, src: Endpoint, msg: &[u8; RP_INIT_HELLO_LEN], out: &mut [u8; RP_COOKIE_REPLY_LEN]) -> bool;
    /// Moves the current secret to previous and draws a new one; false if
    /// the RNG failed.
    fn rotate(&mut self) -> bool;
    /// Zeroizes both secrets.
    fn clear(&mut self);
}

/// An endpoint that got a RespHello, waiting for the InitConf of that
/// exchange (M3b plan, "Session binding").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Awaited {
    ep: Endpoint,
    sidi: [u8; 4],
    sidr: [u8; 4],
    at: u64,
    /// Matched InitConfs it may still forward.
    conf_budget: u64,
    /// A matched InitConf was forwarded.
    conf_seen: bool,
    /// Its InitHello spent the unfinished meter, refunded once when its
    /// exchange completes (post-M6 plan P1, A1).
    counted: bool,
}

/// A configured peer's last proven endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Proven {
    ep: Endpoint,
    at: u64,
    credit: Meter<RP_PROVEN_CREDIT_BURST, RP_PROVEN_CREDIT_INTERVAL_NS>,
}

/// State edges from `RpGate::tick_if_due`, each for one never-coalesced
/// audit event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RpTickReport {
    pub rotated: bool,
    /// `RpCookieSecretUnavailable`: the first failed rotation since a good one.
    pub secret_unavailable: bool,
    /// `RpLoadCleared`.
    pub left_load: bool,
}

/// Which trigger engaged load (`RpUnderLoad`; post-M6 plan P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpLoadTrigger {
    /// The global InitHello meter below half, a refusal or the legacy probe.
    Meters,
    /// The unfinished meter below one interval (`RpUnfinishedLoad`).
    Unfinished,
}

/// The unfinished meter (post-M6 plan P1, amendment A1): each uncookied
/// InitHello spends one RP_UNFINISHED_INTERVAL_NS, and its exchange's
/// completion refunds it. It counts events, not `pq` time, so it means the
/// same on every host. The same shape as `Meter`: a budget in ns refilled
/// 1 ns per ns from `last_ns`, saturating, written only at `sent` and the
/// refund; `unfinished_credit` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Unfinished {
    budget_ns: u64,
    last_ns: u64,
    /// Ghost: every spend.
    #[cfg(kani)]
    spent_total: u128,
    /// Ghost: every refund, saturated at the capacity or not.
    #[cfg(kani)]
    refunded_total: u128,
}

impl Default for Unfinished {
    fn default() -> Self {
        Self {
            budget_ns: Self::CAPACITY_NS,
            last_ns: 0,
            #[cfg(kani)]
            spent_total: 0,
            #[cfg(kani)]
            refunded_total: 0,
        }
    }
}

impl Unfinished {
    const CAPACITY_NS: u64 = (RP_UNFINISHED_BURST as u64).saturating_mul(RP_UNFINISHED_INTERVAL_NS);

    /// Budget at `now_ns`, refilled. A clock that goes backwards refills
    /// nothing.
    fn level_ns(&self, now_ns: u64) -> u64 {
        self.budget_ns.saturating_add(now_ns.saturating_sub(self.last_ns)).min(Self::CAPACITY_NS)
    }

    /// Stores the budget refilled to `now_ns`, before a spend or a refund.
    fn settle(&mut self, now_ns: u64) {
        self.budget_ns = self.level_ns(now_ns);
        self.last_ns = self.last_ns.max(now_ns);
    }

    /// Spends one interval, saturating at 0: it never refuses.
    fn spend(&mut self, now_ns: u64) {
        self.settle(now_ns);
        self.budget_ns = self.budget_ns.saturating_sub(RP_UNFINISHED_INTERVAL_NS);
        #[cfg(kani)]
        {
            self.spent_total = self.spent_total.saturating_add(1);
        }
    }

    /// Gives one interval back, saturating at the capacity.
    fn refund(&mut self, now_ns: u64) {
        self.settle(now_ns);
        self.budget_ns = self.budget_ns.saturating_add(RP_UNFINISHED_INTERVAL_NS).min(Self::CAPACITY_NS);
        #[cfg(kani)]
        {
            self.refunded_total = self.refunded_total.saturating_add(1);
        }
    }
}

fn sid_pair(msg: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    let a = *msg.get(RP_SID_AT..)?.first_chunk::<4>()?;
    let b = *msg.get(RP_SID_AT.checked_add(4)?..)?.first_chunk::<4>()?;
    Some((a, b))
}

fn live(at: u64, now_ns: u64, for_ns: u64) -> bool {
    now_ns.checked_sub(at).is_some_and(|age| age < for_ns)
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

// The Rosenpass cookie gate (M3b plan, "Load state", "Lanes", "Session
// binding"). Proposed values; the assertions below may not be weakened.

/// `config::MAX_PEERS`, which this crate does not depend on (the PD asserts
/// the two agree).
pub const RP_MAX_PEERS: usize = 8;
/// Load holds this long after its last trigger: three per-source periods.
/// An uncookied InitHello under load is not a trigger (rosenpass 0.2.3
/// would never get through), so load clears under a sustained spoof; the
/// first uncookied InitHello forwarded within RP_LEGACY_PROBE_NS after that
/// is the one legacy probe, and it re-arms load at once. While a spoofer
/// keeps sending within each clearance's probe window, it so gets at most
/// one uncookied InitHello to `pq` per clearance: one per
/// RP_UNDER_LOAD_AFTER_NS. A window that lapses with nothing forwarded
/// ends the cycle: the gate is off until a trigger engages it again.
pub const RP_UNDER_LOAD_AFTER_NS: u64 = 60_000_000_000;
/// After load clears, how long the next uncookied forward re-arms it (the
/// integration suite reads this literal).
pub const RP_LEGACY_PROBE_NS: u64 = 60_000_000_000;
/// The per-IP cap on cookied InitHellos: every configured peer behind one
/// address, one each per rekey interval (F3).
pub const RP_HELLO_COOKIED_IP_BURST: u64 = RP_MAX_PEERS as u64;
pub const RP_HELLO_COOKIED_IP_INTERVAL_NS: u64 = 120_000_000_000 / RP_MAX_PEERS as u64;
/// Global InitHello tokens only a proven endpoint may take (a floor on the
/// shared meter, not a quota).
pub const RP_HELLO_PROVEN_RESERVE: u64 = 4;
/// How long a completed exchange keeps its endpoint proven.
pub const RP_PROVEN_NS: u64 = 300_000_000_000;
/// Each proven peer's own spend below the reserve: a burst of two, one per
/// rekey interval.
pub const RP_PROVEN_CREDIT_BURST: u64 = 2;
pub const RP_PROVEN_CREDIT_INTERVAL_NS: u64 = 120_000_000_000;
/// How long an endpoint that got a RespHello stays awaited.
pub const RP_AWAIT_CONF_NS: u64 = 30_000_000_000;
/// Awaited entries: every RespHello `pq` can make within RP_AWAIT_CONF_NS
/// (the global meter's burst and refill bound the InitHellos it is sent,
/// plus those still in flight), so a live entry is never evicted.
pub const RP_AWAIT_SLOTS: usize = RP_HELLO_GLOBAL_BURST as usize
    + RP_AWAIT_CONF_NS.div_ceil(RP_HELLO_GLOBAL_INTERVAL_NS) as usize
    + RP_HELLO_IN_FLIGHT
    + 1;
/// InitConf link slots, and conf-global tokens, only a matched InitConf may
/// take.
pub const RP_CONF_AWAITED_RESERVED: usize = 4;
/// The cost of one uncookied InitHello whose exchange does not complete
/// (post-M6 plan P1, amendment A1); below one of these left in the
/// unfinished meter is a load trigger. A spoof at most one per interval
/// never engages it (R6 (7), narrowed).
pub const RP_UNFINISHED_INTERVAL_NS: u64 = 60_000_000_000;
/// The unfinished meter's capacity, in InitHellos: every peer's boot
/// exchange at once.
pub const RP_UNFINISHED_BURST: usize = RP_MAX_PEERS;

// May not be weakened (post-M6 plan A1): an attack at the global InitHello
// rate spends more than it refills, so it drains the unfinished meter and
// engages load.
const _: () = assert!(
    RP_UNFINISHED_INTERVAL_NS > RP_HELLO_GLOBAL_INTERVAL_NS,
    "A1: an attack at the global rate would never drain the unfinished meter"
);
// May not be weakened (post-M6 plan A1): headroom for boot fan-in beyond
// the exchanges in flight.
const _: () = assert!(RP_UNFINISHED_BURST > RP_HELLO_IN_FLIGHT, "A1: no unfinished-meter headroom for boot fan-in");

// A spoofer at the per-source rate always lands in the probe window, so it
// re-arms load instead of escaping it.
const _: () = assert!(RP_LEGACY_PROBE_NS >= RP_HELLO_SRC_INTERVAL_NS, "a per-source spoofer would escape the probe window");
const _: () = assert!(RP_UNDER_LOAD_AFTER_NS >= RP_HELLO_SRC_INTERVAL_NS, "load would clear within one source period");
const _: () = assert!(
    0 < RP_HELLO_PROVEN_RESERVE && RP_HELLO_PROVEN_RESERVE < RP_HELLO_GLOBAL_BURST,
    "RP_HELLO_PROVEN_RESERVE out of range"
);
const _: () = assert!(RP_HELLO_COOKIED_IP_BURST >= RP_MAX_PEERS as u64, "peers behind one address");
// Refill rates, not bursts: every proven slot together never refills faster
// than the global meter.
const _: () = assert!(
    RP_MAX_PEERS as u64 * (120_000_000_000 / RP_PROVEN_CREDIT_INTERVAL_NS) <= 120_000_000_000 / RP_HELLO_GLOBAL_INTERVAL_NS,
    "proven credit refills faster than the global meter"
);
const _: () = assert!(RP_CONF_AWAITED_RESERVED < RP_CONF_IN_FLIGHT, "RP_CONF_AWAITED_RESERVED out of range");
const _: () = assert!((RP_CONF_AWAITED_RESERVED as u64) < RP_CONF_GLOBAL_BURST, "RP_CONF_AWAITED_RESERVED above the burst");
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
pub struct SourceMeters<const N: usize, const BURST: u64, const INTERVAL_NS: u64, K = Ipv4> {
    slots: [Option<(K, Meter<BURST, INTERVAL_NS>)>; N],
}

impl<const N: usize, const BURST: u64, const INTERVAL_NS: u64, K: Copy> Default for SourceMeters<N, BURST, INTERVAL_NS, K> {
    fn default() -> Self {
        Self { slots: [None; N] }
    }
}

/// Keyed by IP (the off-load and per-IP cookied tables) or by endpoint (the
/// cookied per-endpoint table, M3b plan F13).
impl<const N: usize, const BURST: u64, const INTERVAL_NS: u64, K: Copy + PartialEq> SourceMeters<N, BURST, INTERVAL_NS, K> {
    pub fn allow(&mut self, ip: K, now_ns: u64) -> bool {
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
    /// An uncookied InitHello: it spent the unfinished meter, until
    /// `complete` moves the mark into its `Reply`.
    counted: bool,
}

const NO_ENTRY: Entry = Entry {
    kind: RpKind::Hello,
    src: Endpoint { ip: [0; 4], port: 0 },
    state: EntryState::AwaitingRecord,
    counted: false,
};

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

    fn push(&mut self, kind: RpKind, src: Endpoint, counted: bool) -> bool {
        if self.len >= RP_IN_FLIGHT {
            return false;
        }
        let Some(e) = self.entries.get_mut(self.head.wrapping_add(self.len) % RP_IN_FLIGHT) else {
            return false;
        };
        *e = Entry { kind, src, state: EntryState::AwaitingRecord, counted };
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
    /// Off load: per IP.
    hello_src: SourceMeters<N, RP_HELLO_SRC_BURST, RP_HELLO_SRC_INTERVAL_NS>,
    /// Under load, with a valid cookie: per endpoint, then the per-IP cap
    /// (F13: separate tables; a token in one is not one in another).
    hello_cookied_ep: SourceMeters<N, RP_HELLO_SRC_BURST, RP_HELLO_SRC_INTERVAL_NS, Endpoint>,
    hello_cookied_ip: SourceMeters<N, RP_HELLO_COOKIED_IP_BURST, RP_HELLO_COOKIED_IP_INTERVAL_NS>,
    hello_global: Meter<RP_HELLO_GLOBAL_BURST, RP_HELLO_GLOBAL_INTERVAL_NS>,
    conf_src: SourceMeters<N, RP_CONF_SRC_BURST, RP_CONF_SRC_INTERVAL_NS>,
    conf_global: Meter<RP_CONF_GLOBAL_BURST, RP_CONF_GLOBAL_INTERVAL_NS>,
    in_flight: InFlight,
    /// Sticky: `pq`'s records and returns fell out of step, so no entry can
    /// be trusted. Nothing more is forwarded, relayed or retired until
    /// reboot (M3b plan, R4-F2).
    pq_dead: bool,
    /// Endpoints a RespHello went to, keyed by (endpoint, sidr).
    awaited: [Option<Awaited>; RP_AWAIT_SLOTS],
    /// Per configured peer (S7): only that peer's EmptyData changes its slot.
    proven: [Option<Proven>; RP_MAX_PEERS],
    /// Load holds while `now` is before this.
    under_load_until_ns: u64,
    /// Load as last announced, so `RpUnderLoad` and `RpLoadCleared` alternate.
    in_load: bool,
    /// Load entered, by this trigger, and not yet taken by the PD.
    entered_load: Option<RpLoadTrigger>,
    life: SecretLife,
    unfinished: Unfinished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpOutcome<'a> {
    /// The only outcomes the PD sends to `pq`, each built by one
    /// constructor (`rp_forward_hello`, `rp_forward_conf`).
    /// `cookied`: it passed the cookie gate under load (`RpCookieAccepted`).
    ForwardHello { src: Endpoint, msg: &'a [u8; RP_INIT_HELLO_LEN], cookied: bool },
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
    /// Under load without a valid cookie: a CookieReply for `dst` is in the
    /// cookie buffer.
    CookieReply { dst: Endpoint },
    /// A CookieReply was due but TX had no room for it, or sealing failed.
    CookieSuppressed,
    /// A CookieReply was due but no secret is held (RNG failure).
    NoCookieSecret,
    /// A CookieReply was due but the secret is at or past its maximum age.
    CookieSecretExpired,
}

/// Rosenpass checks on a datagram addressed to the Rosenpass port, in
/// order: type and exact length, then the mac, then the forward
/// constructor of its type. Nothing spends a meter before the mac passed.
///
/// Under load an InitHello needs a valid cookie; without one it spends
/// nothing and gets a CookieReply in `out` (M3b plan, "Lanes").
#[allow(clippy::too_many_arguments)] // each argument is an independent input the PD reads per datagram (state, crypto, levels, datagram); bundling them would only rename the list
pub fn rp_classify<'a, M: RpMac, K: RpCookieCheck, const N: usize>(
    gate: &mut RpGate<N>,
    mac: &M,
    cookie: &mut K,
    now_ns: u64,
    tx_free: usize,
    src: Endpoint,
    payload: &'a [u8],
    out: &mut [u8; RP_COOKIE_REPLY_LEN],
) -> RpOutcome<'a> {
    match payload.first() {
        Some(&RP_MSG_INIT_HELLO) => {
            let Ok(msg) = <&[u8; RP_INIT_HELLO_LEN]>::try_from(payload) else {
                return RpOutcome::TypeDropped;
            };
            if !mac.verify(msg) {
                return RpOutcome::BadMac;
            }
            gate.rp_hello(cookie, now_ns, tx_free, src, msg, out)
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


impl<const N: usize> RpGate<N> {
    /// Whether load holds at `now_ns`: the global InitHello meter below half
    /// and the unfinished meter below one interval are triggers by
    /// themselves; refusals refresh it through `refresh_load`. Evaluated at
    /// `now_ns`, so the tick sees it with no new transition (post-M6 plan
    /// P1, S4).
    fn observe_load(&mut self, now_ns: u64) -> bool {
        if self.hello_global.below_half(now_ns) {
            self.refresh_load(now_ns, RpLoadTrigger::Meters);
        }
        if self.unfinished_low(now_ns) {
            self.refresh_load(now_ns, RpLoadTrigger::Unfinished);
        }
        now_ns < self.under_load_until_ns
    }

    /// Off load, whether load ended less than RP_LEGACY_PROBE_NS ago (never
    /// before the first load: the deadline starts at zero).
    fn in_probe_window(&self, now_ns: u64) -> bool {
        self.under_load_until_ns != 0 && now_ns < self.under_load_until_ns.saturating_add(RP_LEGACY_PROBE_NS)
    }

    /// A trigger held: load holds until RP_UNDER_LOAD_AFTER_NS from now.
    fn refresh_load(&mut self, now_ns: u64, trigger: RpLoadTrigger) {
        self.under_load_until_ns = self.under_load_until_ns.max(now_ns.saturating_add(RP_UNDER_LOAD_AFTER_NS));
        if !self.in_load {
            self.in_load = true;
            self.entered_load = Some(trigger);
        }
    }

    /// The unfinished meter's credit at `now_ns` (post-M6 plan P1, A1), a
    /// pure read: refilled 1 ns per ns, within 0 and its capacity.
    pub fn unfinished_credit(&self, now_ns: u64) -> u64 {
        self.unfinished.level_ns(now_ns)
    }

    /// The unfinished trigger: less than one interval left and the path is
    /// up (a dead path is idle).
    fn unfinished_low(&self, now_ns: u64) -> bool {
        !self.pq_dead && self.unfinished_credit(now_ns) < RP_UNFINISHED_INTERVAL_NS
    }

    /// An InitHello after its mac passed (M3b plan, "Load state", "Lanes").
    fn rp_hello<'a, K: RpCookieCheck>(
        &mut self,
        cookie: &mut K,
        now_ns: u64,
        tx_free: usize,
        src: Endpoint,
        msg: &'a [u8; RP_INIT_HELLO_LEN],
        out: &mut [u8; RP_COOKIE_REPLY_LEN],
    ) -> RpOutcome<'a> {
        if self.pq_dead {
            return RpOutcome::PqDown;
        }
        if !self.observe_load(now_ns) {
            // I2: off load the cookie is never computed.
            let o = self.rp_forward_hello(now_ns, src, msg, false);
            if matches!(o, RpOutcome::RateLimited | RpOutcome::RingReserved) {
                self.refresh_load(now_ns, RpLoadTrigger::Meters);
            }
            return o;
        }
        // An all-zero cookie field is invalid by definition; skip its hash.
        let field_zero = msg.get(RP_COOKIE_AT..).is_none_or(|c| c.iter().all(|&b| b == 0));
        let secret = self.life.secret(now_ns);
        if !field_zero && secret == Secret::Usable && cookie.valid(src, msg) {
            let o = self.rp_forward_hello(now_ns, src, msg, true);
            if matches!(o, RpOutcome::RateLimited | RpOutcome::RingReserved) {
                self.refresh_load(now_ns, RpLoadTrigger::Meters);
            }
            return o;
        }
        // I1: no meter, nothing in flight, and no load refresh: rosenpass
        // 0.2.3 cannot answer a CookieReply and retransmits, so a refresh
        // here would hold the gate for as long as an old client retries.
        match secret {
            Secret::Missing => RpOutcome::NoCookieSecret,
            Secret::Expired => {
                self.life.note_expired();
                RpOutcome::CookieSecretExpired
            }
            Secret::Usable if rp_tx_allowed(TxTier::Unsolicited, tx_free) && cookie.seal(src, msg, out) => {
                RpOutcome::CookieReply { dst: src }
            }
            Secret::Usable => RpOutcome::CookieSuppressed,
        }
    }

    /// The single constructor of `ForwardHello`. `cookied` is the lane: a
    /// valid cookie under load.
    fn rp_forward_hello<'a>(
        &mut self,
        now_ns: u64,
        src: Endpoint,
        msg: &'a [u8; RP_INIT_HELLO_LEN],
        cookied: bool,
    ) -> RpOutcome<'a> {
        match self.admit_hello(cookied, now_ns, src) {
            Ok(()) => {
                // Off load (the only uncookied lane): the legacy probe.
                if !cookied && self.in_probe_window(now_ns) {
                    self.refresh_load(now_ns, RpLoadTrigger::Meters);
                }
                RpOutcome::ForwardHello { src, msg, cookied }
            }
            Err(refused) => refused,
        }
    }

    /// The single constructor of `ForwardConf`.
    fn rp_forward_conf<'a>(&mut self, now_ns: u64, src: Endpoint, msg: &'a [u8; RP_INIT_CONF_LEN]) -> RpOutcome<'a> {
        match self.admit_conf(now_ns, src, msg) {
            Ok(()) => RpOutcome::ForwardConf { src, msg },
            Err(refused) => refused,
        }
    }

    /// The `pq` path, then room on the link (a refusal there spends
    /// nothing), as for both kinds.
    fn room(&self, kind: RpKind) -> Result<(), RpOutcome<'static>> {
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
        Ok(())
    }

    /// Room, then the source's meters, then the global one, spent only if
    /// the source had a token; nothing is counted (the PD calls `sent`).
    /// An endpoint that is no live proven slot's never takes the global
    /// meter to the reserve (I3); a proven one may, within its credit, and
    /// only on the cookied lane, where the cookie proves the endpoint.
    fn admit_hello(&mut self, cookied: bool, now_ns: u64, src: Endpoint) -> Result<(), RpOutcome<'static>> {
        self.room(RpKind::Hello)?;
        let source_ok = if cookied {
            self.hello_cookied_ep.allow(src, now_ns) && self.hello_cookied_ip.allow(src.ip, now_ns)
        } else {
            self.hello_src.allow(src.ip, now_ns)
        };
        if !source_ok {
            return Err(RpOutcome::RateLimited);
        }
        let proven = if cookied { self.proven_slot(src, now_ns) } else { None };
        let credit = proven.and_then(|i| self.proven.get(i).copied().flatten()).is_some_and(|p| p.credit.tokens(now_ns) > 0);
        let tokens = self.hello_global.tokens(now_ns);
        let floor = if credit { 0 } else { RP_HELLO_PROVEN_RESERVE };
        if tokens <= floor || !self.hello_global.allow(now_ns) {
            return Err(RpOutcome::RateLimited);
        }
        if credit
            && let Some(Some(p)) = proven.and_then(|i| self.proven.get_mut(i))
        {
            p.credit.allow(now_ns);
        }
        Ok(())
    }

    /// Room, with the awaited reserve: of the InitConf slots and conf-global
    /// tokens, RP_CONF_AWAITED_RESERVED are only for an InitConf matching a
    /// live awaited entry of its endpoint (I5), one such slot per endpoint.
    fn admit_conf(&mut self, now_ns: u64, src: Endpoint, msg: &[u8; RP_INIT_CONF_LEN]) -> Result<(), RpOutcome<'static>> {
        self.room(RpKind::Conf)?;
        let matched = sid_pair(msg).and_then(|(sidi, sidr)| {
            self.awaited.iter().position(|a| {
                a.is_some_and(|a| {
                    a.ep == src && a.sidi == sidi && a.sidr == sidr && a.conf_budget > 0 && live(a.at, now_ns, RP_AWAIT_CONF_NS)
                })
            })
        });
        let unreserved = self.in_flight.count(RpKind::Conf) < RP_CONF_IN_FLIGHT - RP_CONF_AWAITED_RESERVED;
        let own_reserved =
            (0..self.in_flight.len).any(|i| self.in_flight.get(i).is_some_and(|e| e.kind == RpKind::Conf && e.src == src));
        let slot_ok = unreserved || (matched.is_some() && !own_reserved);
        if !slot_ok {
            return Err(RpOutcome::RingReserved);
        }
        if !self.conf_src.allow(src.ip, now_ns) {
            return Err(RpOutcome::RateLimited);
        }
        let floor = if matched.is_some() { 0 } else { RP_CONF_AWAITED_RESERVED as u64 };
        if self.conf_global.tokens(now_ns) <= floor || !self.conf_global.allow(now_ns) {
            return Err(RpOutcome::RateLimited);
        }
        if let Some(Some(a)) = matched.and_then(|i| self.awaited.get_mut(i)) {
            a.conf_budget = a.conf_budget.saturating_sub(1);
            a.conf_seen = true;
        }
        Ok(())
    }

    /// The live proven slot whose endpoint is `src`.
    fn proven_slot(&self, src: Endpoint, now_ns: u64) -> Option<usize> {
        self.proven.iter().position(|p| p.is_some_and(|p| p.ep == src && live(p.at, now_ns, RP_PROVEN_NS)))
    }

    /// The endpoint-state feed (M3b plan, "Session binding"), for a reply
    /// `sync_pq` handed to the driver: a RespHello makes its destination
    /// awaited under the reply's session ids; an EmptyData proves its
    /// destination for the configured peer `peer`, only if a matched
    /// InitConf of that exchange was forwarded (I6). `dst` is always the
    /// forward's stored source.
    ///
    /// Unfinished meter (post-M6 plan P1, A1): a RespHello's awaited entry
    /// stores `counted`, the mark `complete` moved off its InitHello; the
    /// EmptyData of a matched `conf_seen` entry refunds one interval if it
    /// carries the mark, and clears it (so a retransmitted InitConf's
    /// EmptyData refunds nothing). Nothing else refunds.
    fn replied(&mut self, kind: RpKind, dst: Endpoint, peer: Option<u8>, msg: &[u8], counted: bool, now_ns: u64) {
        match kind {
            RpKind::Hello => {
                // RespHello: sidr ‖ sidi.
                let Some((sidr, sidi)) = sid_pair(msg) else { return };
                let slot = self
                    .awaited
                    .iter()
                    .position(|a| a.is_some_and(|a| a.ep == dst && a.sidr == sidr))
                    .or_else(|| self.awaited.iter().position(|a| a.is_none_or(|a| !live(a.at, now_ns, RP_AWAIT_CONF_NS))));
                // A full table of live entries records nothing; it never
                // evicts one (RP_AWAIT_SLOTS bounds the live ones).
                if let Some(a) = slot.and_then(|i| self.awaited.get_mut(i)) {
                    *a = Some(Awaited { ep: dst, sidi, sidr, at: now_ns, conf_budget: RP_CONF_SRC_BURST, conf_seen: false, counted });
                }
            }
            RpKind::Conf => {
                let (Some(peer), Some(sid)) = (peer, msg.get(RP_SID_AT..).and_then(|m| m.first_chunk::<4>())) else {
                    return;
                };
                let Some(i) = self.awaited.iter().position(|a| a.is_some_and(|a| a.ep == dst && a.conf_seen && a.sidi == *sid))
                else {
                    return;
                };
                self.refund(i, now_ns);
                let Some(slot) = self.proven.get_mut(usize::from(peer)) else { return };
                let credit = slot.filter(|p| p.ep == dst).map_or(Meter::full_at(now_ns), |p| p.credit);
                *slot = Some(Proven { ep: dst, at: now_ns, credit });
                if let Some(a) = self.awaited.get_mut(i) {
                    *a = None;
                }
            }
        }
    }

    /// Refunds awaited entry `i`'s exchange, which completed, if it carries
    /// the mark, and clears the mark.
    fn refund(&mut self, i: usize, now_ns: u64) {
        let Some(Some(a)) = self.awaited.get_mut(i) else { return };
        if core::mem::take(&mut a.counted) {
            self.unfinished.refund(now_ns);
        }
    }

    /// Runs on every handler-loop pass and on the timer tick: rotates the
    /// Rosenpass cookie secret when due (`SecretLife`), and notices load
    /// leaving with no InitHello arriving.
    pub fn tick_if_due<K: RpCookieCheck>(&mut self, cookie: &mut K, now_ns: u64) -> RpTickReport {
        let mut report = RpTickReport::default();
        let cookie = core::cell::RefCell::new(cookie);
        (report.rotated, report.secret_unavailable) =
            self.life.tick(now_ns, || cookie.borrow_mut().rotate(), || cookie.borrow_mut().clear());
        if !self.observe_load(now_ns) && self.in_load {
            self.in_load = false;
            report.left_load = true;
        }
        report
    }

    /// Whether load was entered since the last call (`RpUnderLoad`), and by
    /// which trigger (`RpUnfinishedLoad` for the unfinished meter).
    pub fn take_load_entered(&mut self) -> Option<RpLoadTrigger> {
        self.entered_load.take()
    }

    /// Whether the expiry backstop fired for the first time since a valid
    /// secret (`RpCookieSecretExpired`).
    pub fn take_expired(&mut self) -> bool {
        self.life.take_expired()
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
    /// paired with its record, which stops the `pq` path. An uncookied
    /// InitHello spends one interval of the unfinished meter and is marked
    /// counted (post-M6 plan P1, A1).
    pub fn sent(&mut self, kind: RpKind, src: Endpoint, cookied: bool, now_ns: u64) {
        let counted = kind == RpKind::Hello && !cookied;
        if !self.in_flight.push(kind, src, counted) {
            self.pq_dead = true;
        } else if counted {
            self.unfinished.spend(now_ns);
        }
    }

    /// Pairs `pq`'s next completion record with the oldest forward still
    /// waiting for one. A `Reply` must be that forward's reply type and goes
    /// to its stored source, never to anything the record says. An extra
    /// record, a wrong type, a malformed record or an index outside
    /// `peers` stops the `pq` path. The forward's counted mark moves into
    /// the `Reply` (and off the entry).
    pub fn complete<'r>(&mut self, record: &'r [u8], peers: usize) -> Result<Completion<'r>, SyncDead> {
        if self.pq_dead {
            return Err(SyncDead);
        }
        let pairing = msgs::RpReply::decode(record).ok().and_then(|r| {
            let e = self.in_flight.first_awaiting()?;
            match r {
                msgs::RpReply::NoReply => {
                    e.state = EntryState::CompletedNoReply;
                    e.counted = false;
                    Some(None)
                }
                msgs::RpReply::Reply { index, msg } => {
                    let peer = match (e.kind, msg.len()) {
                        (RpKind::Hello, RP_RESP_HELLO_LEN) if index == msgs::RP_NO_PEER => None,
                        (RpKind::Conf, RP_EMPTY_DATA_LEN) if usize::from(index) < peers => Some(index),
                        _ => return None,
                    };
                    e.state = EntryState::CompletedReply;
                    Some(Some((e.src, e.kind, peer, core::mem::take(&mut e.counted))))
                }
            }
        });
        let reply = record.get(2..).unwrap_or(&[]);
        match pairing {
            Some(Some((dst, kind, peer, counted))) => Ok(Completion::Reply { dst, kind, peer, msg: reply, counted }),
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
    /// `peer` is the configured peer of an EmptyData. `counted` is the
    /// forward's unfinished-meter mark, for `replied` to store.
    Reply { dst: Endpoint, kind: RpKind, peer: Option<u8>, msg: &'a [u8], counted: bool },
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
pub fn sync_pq<T: PqSync, const N: usize>(gate: &mut RpGate<N>, io: &mut T, peers: usize, now_ns: u64) -> SyncOutcome {
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
            Ok(Completion::Reply { dst, kind, peer, msg, counted }) => {
                // Only a reply that went out feeds the endpoint state, and
                // always with the stored source (T19, R4-F1).
                if io.transmit(dst, msg) {
                    relayed = relayed.saturating_add(1);
                    gate.replied(kind, dst, peer, msg, counted, now_ns);
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
    /// TCP segments from `tls`, through `tls_egress`.
    fn serve_tls(&mut self, max: usize) -> usize;
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
        let n_tls = self.0.serve_tls(PASS_FRAMES);
        self.0.tick();
        let n_outside = self.0.serve_outside(PASS_FRAMES);
        ring::pass::any_full(&[n_hs, n_pq, n_data, n_tls, n_outside], PASS_FRAMES)
    }

    fn end_pass(&mut self) {
        self.0.end_pass();
    }
}

/// The handler loop (plan, "Handler loop"): every pass serves all five
/// inputs, at most PASS_FRAMES each, runs the tick between `serve_tls` and
/// `serve_outside`, and ends with `end_pass`, so a flood on any input starves
/// neither the others, nor the tick, nor the peers waiting to be notified.
pub fn run_passes(io: &mut impl PassIo) {
    ring::pass::run_passes(&mut Order(io));
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
