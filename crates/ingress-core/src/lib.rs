//! `ingress` v2 decision logic (plan C14): answer ARP for the outside
//! address and classify WireGuard datagrams on the listen port. Only a
//! well-formed initiation with a valid mac1 from a source within its rate
//! budget reaches `hs`; only a transport message of plausible size reaches
//! `data`; everything else is dropped with a reason. Pure and total, so it
//! is unit-tested and proved on the host; the PD only moves bytes.
//!
//! mac1 needs BLAKE2s, so it is checked through the `Mac1` trait: the PD
//! plugs in wg-core's MAC and the proofs a nondeterministic stub.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use wg_wire::{INITIATION_LEN, MSG_INITIATION, MSG_TRANSPORT, TRANSPORT_MIN_LEN};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// Reply of this many bytes was written to `out`.
    ArpReplied(usize),
    Initiation { src: Endpoint, msg: &'a [u8; INITIATION_LEN] },
    Transport { src: Endpoint, msg: &'a [u8] },
    Dropped(DropReason),
    NotForUs,
    /// Valid frame for us that no service handles (other port, ARP reply).
    NoService,
    /// Source claims to be us, or ARP sender differs from the Ethernet source.
    Spoofed,
    /// WireGuard type/length combination a responder does not accept.
    BadMessage,
    BadMac1,
    RateLimited,
}

const BROADCAST: Mac = [0xff; 6];

pub fn respond<'a, M: Mac1, const N: usize>(
    cfg: &Config,
    mac1: &M,
    buckets: &mut Buckets<N>,
    now_ns: u64,
    frame: &'a [u8],
    out: &mut [u8],
) -> Outcome<'a> {
    let f = match wire::parse_frame(frame) {
        Ok(f) => f,
        Err(r) => return Outcome::Dropped(r),
    };
    match f.body {
        Body::Arp(a) => arp(cfg, &f.eth, &a, out),
        Body::Udp4(u) => udp(cfg, mac1, buckets, now_ns, &f.eth, &u),
        // `parse_frame` (outside NIC) never yields it.
        Body::Ipv4(_) => Outcome::Dropped(DropReason::NotUdp),
    }
}

fn arp<'a>(cfg: &Config, eth: &EthAddrs, a: &ArpPacket, out: &mut [u8]) -> Outcome<'a> {
    if (eth.dst != cfg.mac && eth.dst != BROADCAST) || a.tpa != cfg.ipv4 {
        return Outcome::NotForUs;
    }
    if a.sha != eth.src || eth.src == cfg.mac || a.spa == cfg.ipv4 {
        return Outcome::Spoofed;
    }
    if a.op != ArpOp::Request {
        return Outcome::NoService;
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

fn udp<'a, M: Mac1, const N: usize>(
    cfg: &Config,
    mac1: &M,
    buckets: &mut Buckets<N>,
    now_ns: u64,
    eth: &EthAddrs,
    u: &Udp4<'a>,
) -> Outcome<'a> {
    if eth.dst != cfg.mac || u.dst != cfg.ipv4 {
        return Outcome::NotForUs;
    }
    if u.src == cfg.ipv4 || eth.src == cfg.mac {
        return Outcome::Spoofed;
    }
    if u.dport != cfg.port {
        return Outcome::NoService;
    }
    classify(mac1, buckets, now_ns, Endpoint { ip: u.src, port: u.sport }, u.payload)
}

/// WireGuard-level checks on a datagram addressed to the listen port. The
/// rate budget is spent only after a valid mac1. mac1 is no authentication:
/// it needs only the gateway's public key, which is compiled into the image
/// (law L6), so anyone holding the image can pass it with spoofed sources
/// and spend `key`'s shared budget. Cookies (SC13) close that; until then
/// M2 images are dev-only (architecture R6).
pub fn classify<'a, M: Mac1, const N: usize>(
    mac1: &M,
    buckets: &mut Buckets<N>,
    now_ns: u64,
    src: Endpoint,
    payload: &'a [u8],
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
            if !buckets.allow(src.ip, now_ns) {
                return Outcome::RateLimited;
            }
            Outcome::Initiation { src, msg }
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
/// churns budgets rather than exhausting memory; `key`'s own quota is the
/// backstop for that case (plan, DoS).
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

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
