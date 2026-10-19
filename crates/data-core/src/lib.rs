//! `data` decision logic (plan C12): per-peer transport sessions, key
//! confirmation, roaming and the allowed-IP checks around the tunnel. This
//! is the only code that sees tunnelled plaintext (law L3). Pure and total
//! so that it is unit-tested on the host with real AEAD; the PD only moves
//! bytes between rings.
//!
//! Slot rules (plan, key confirmation): an install replaces `next`; the
//! first authenticated packet on `next` (keepalives included) promotes it
//! to `current`, the old `current` becomes `previous` (still accepted for
//! receiving) and the old `previous` is dropped. Only `current` seals.
//! Dropping a `Session` zeroizes its keys (`wg_core::crypto::Key32`).
//!
//! Passive keepalive (plan C7): data received from a peer arms
//! `unacked_since`; anything sealed for the peer, or `current` being
//! dropped by `tick`, disarms it. A promotion does not: the new `current`
//! owes the same reply and carries the keepalive.
//!
//! Memory: every slot holds a `wg_core::session::Session`, whose replay
//! window is `REPLAY_BITS` = 2048 one-byte flags, so a slot is ~2.1 KiB and
//! `Data<N>` is ~6.3 KiB per peer. That is fine for the handful of peers a
//! compiled-in configuration has; shrink `REPLAY_BITS` in wg-core before
//! raising the peer count by orders of magnitude.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use msgs::{Endpoint, Install};
use wg_core::KEEPALIVE_TIMEOUT_NS;
use wg_core::crypto::Key32;
use wg_core::noise::SessionKeys;
use wg_core::session::{Session, SessionError};
use wg_wire::{TAG_LEN, TRANSPORT_HEADER_LEN, TRANSPORT_MIN_LEN, Transport, WireError};
use wire::{DropReason, Ipv4};

/// Largest plaintext we seal or forward: a transport message must fit the
/// largest outer UDP payload. A multiple of 16, so padding never exceeds it.
pub const MTU: usize = wire::MAX_UDP_PAYLOAD - TRANSPORT_MIN_LEN;
/// Largest transport message `outbound` writes.
pub const MAX_TRANSPORT: usize = MTU + TRANSPORT_MIN_LEN;
const PAD: usize = 16;

/// Peer allowed IPs, supplied by the caller (the PD implements it over the
/// compiled-in configuration, whose allowed IPs never overlap).
pub trait AllowedIps {
    fn contains(&self, peer: usize, ip: Ipv4) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
    PeerOutOfRange,
    /// `local_index` equals the index of a live session (any peer, any slot).
    IndexCollision,
}

/// What an authenticated packet carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'o> {
    Keepalive,
    /// The IPv4 datagram (padding stripped) to hand to `inner`.
    Forward(&'o [u8]),
    /// The inner source is outside the peer's allowed IPs.
    SpoofedSource,
    /// The plaintext is not a valid IPv4 datagram.
    Invalid(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOutcome<'o> {
    /// The packet authenticated. `endpoint` is `Some(src)` iff its counter is
    /// a new highest on its session: send `EndpointUpdate { peer, src }`.
    Authenticated {
        peer: u16,
        endpoint: Option<Endpoint>,
        promoted: bool,
        payload: Payload<'o>,
    },
    Malformed(WireError),
    UnknownIndex,
    /// The session refused it (auth, replay, expired, counter limit, buffer).
    /// No slot and no endpoint changed.
    Rejected(SessionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundOutcome {
    /// A transport message of `len` bytes is at the start of `out`; the PD
    /// wraps it as `msgs::ToIngress::Outbound { peer, msg }`.
    Sealed {
        peer: u16,
        len: usize,
    },
    Dropped(DropReason),
    /// Larger than `MTU`.
    TooLarge,
    /// No peer's allowed IPs contain the destination.
    NoPeer,
    /// The peer has no confirmed (`current`) session.
    NoSession,
    /// `current` refused to seal (expired or out of counters).
    Rejected(SessionError),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Next,
    Current,
    Previous,
}

/// A peer's sessions. Not `Clone`/`Copy`/`Debug`.
#[derive(Default)]
struct Peer {
    next: Option<Session>,
    current: Option<Session>,
    previous: Option<Session>,
    /// Last endpoint `ingress` is known to have been told (see
    /// `endpoint_delivered`); suppresses repeated identical updates.
    endpoint: Option<Endpoint>,
    /// When the oldest data packet nothing has been sent back for arrived.
    unacked_since: Option<u64>,
}

impl Peer {
    fn slot_mut(&mut self, slot: Slot) -> &mut Option<Session> {
        match slot {
            Slot::Next => &mut self.next,
            Slot::Current => &mut self.current,
            Slot::Previous => &mut self.previous,
        }
    }

    fn sessions(&self) -> [(Slot, Option<&Session>); 3] {
        [
            (Slot::Next, self.next.as_ref()),
            (Slot::Current, self.current.as_ref()),
            (Slot::Previous, self.previous.as_ref()),
        ]
    }

    fn promote(&mut self) {
        // Assigning drops (and so zeroizes) the old `previous`.
        self.previous = self.current.take();
        self.current = self.next.take();
    }
}

/// Transport sessions of up to `MAX_PEERS` peers. Not `Clone`/`Copy`/`Debug`.
pub struct Data<const MAX_PEERS: usize> {
    peers: [Peer; MAX_PEERS],
}

impl<const MAX_PEERS: usize> Default for Data<MAX_PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_PEERS: usize> Data<MAX_PEERS> {
    pub fn new() -> Self {
        const { assert!(MAX_PEERS <= u16::MAX as usize + 1, "peer ids are u16") };
        Self { peers: core::array::from_fn(|_| Peer::default()) }
    }

    /// Replaces `peer`'s `next` (an older unconfirmed `next` is dropped). The
    /// keys are copied out of `msg`; the caller zeroes its install buffer.
    /// The session clock starts at `now_ns`, taken by `data` itself.
    pub fn install(&mut self, msg: &Install<'_>, now_ns: u64) -> InstallOutcome {
        if self.find(msg.local_index).is_some() {
            return InstallOutcome::IndexCollision;
        }
        let Some(p) = self.peers.get_mut(usize::from(msg.peer)) else {
            return InstallOutcome::PeerOutOfRange;
        };
        let keys = SessionKeys { send: Key32::from_bytes(*msg.send), recv: Key32::from_bytes(*msg.recv) };
        p.next = Some(Session::new(keys, msg.local_index, msg.remote_index, now_ns));
        InstallOutcome::Installed
    }

    /// Opens a transport message from `src` into `out` (which must hold the
    /// ciphertext length minus the tag). A refused packet changes nothing
    /// here, although an expired session wipes its own keys (wg-core).
    pub fn inbound<'o>(
        &mut self,
        allowed: &impl AllowedIps,
        src: Endpoint,
        msg: &[u8],
        now_ns: u64,
        out: &'o mut [u8],
    ) -> InboundOutcome<'o> {
        let t = match Transport::parse(msg) {
            Ok(t) => t,
            Err(e) => return InboundOutcome::Malformed(e),
        };
        let Some((peer, slot)) = self.find(t.receiver) else {
            return InboundOutcome::UnknownIndex;
        };
        let Some(p) = self.peers.get_mut(peer) else {
            return InboundOutcome::UnknownIndex;
        };
        let Some(s) = p.slot_mut(slot).as_mut() else {
            return InboundOutcome::UnknownIndex;
        };
        let before = s.highest_received();
        let n = match s.open(t.counter, t.ciphertext, out, now_ns) {
            Ok(n) => n,
            Err(e) => return InboundOutcome::Rejected(e),
        };
        // `None < Some(_)`: the first accepted counter is a new maximum. An
        // update is due only when the source differs from what `ingress`
        // last accepted: one per roam, not one per packet.
        let endpoint = (before < Some(t.counter) && p.endpoint != Some(src)).then_some(src);
        let promoted = slot == Slot::Next;
        if promoted {
            p.promote();
        }
        let payload = classify(allowed, peer, out, n);
        if matches!(payload, Payload::Forward(_)) && p.unacked_since.is_none() {
            p.unacked_since = Some(now_ns);
        }
        // `find` only yields peers below MAX_PEERS, which fit in u16.
        let peer = u16::try_from(peer).unwrap_or(u16::MAX);
        InboundOutcome::Authenticated { peer, endpoint, promoted, payload }
    }

    /// Records that `ingress` accepted an `EndpointUpdate` for `peer`. Call
    /// only after the update was actually sent: until then every new
    /// highest counter from that source asks for it again.
    pub fn endpoint_delivered(&mut self, peer: u16, endpoint: Endpoint) {
        if let Some(p) = self.peers.get_mut(usize::from(peer)) {
            p.endpoint = Some(endpoint);
        }
    }

    /// Seals an IPv4 datagram from `inner` for the peer whose allowed IPs
    /// contain its destination, using that peer's `current` session only.
    /// The plaintext is zero-padded to a multiple of 16 (whitepaper 5.4.6).
    pub fn outbound(
        &mut self,
        allowed: &impl AllowedIps,
        packet: &[u8],
        now_ns: u64,
        out: &mut [u8],
    ) -> OutboundOutcome {
        let ip = match wire::parse_ipv4_packet(packet) {
            Ok(ip) => ip,
            Err(r) => return OutboundOutcome::Dropped(r),
        };
        let datagram = ip.packet;
        let Some(padded_len) = padded_len(datagram.len()) else {
            return OutboundOutcome::TooLarge;
        };
        let Some((peer, p)) = self.peers.iter_mut().enumerate().find(|(i, _)| allowed.contains(*i, ip.dst)) else {
            return OutboundOutcome::NoPeer;
        };
        let Some(s) = p.current.as_mut() else {
            return OutboundOutcome::NoSession;
        };
        let mut plain = [0u8; MTU];
        let sealed = pad(&mut plain, datagram, padded_len)
            .ok_or(SessionError::Buffer)
            .and_then(|pt| seal_into(s, pt, now_ns, out));
        plain.fill(0);
        let peer = u16::try_from(peer).unwrap_or(u16::MAX);
        match sealed {
            Ok(len) => {
                p.unacked_since = None;
                OutboundOutcome::Sealed { peer, len }
            }
            Err(e) => OutboundOutcome::Rejected(e),
        }
    }

    /// Drops (zeroizes) every session, `next` included, that has reached
    /// REJECT_AFTER_TIME. Returns how many were dropped.
    pub fn tick(&mut self, now_ns: u64) -> usize {
        let mut dropped = 0usize;
        for p in &mut self.peers {
            for slot in [Slot::Next, Slot::Current, Slot::Previous] {
                let s = p.slot_mut(slot);
                if s.as_ref().is_some_and(|s| s.expired(now_ns)) {
                    *s = None;
                    dropped = dropped.saturating_add(1);
                    if slot == Slot::Current {
                        p.unacked_since = None;
                    }
                }
            }
        }
        dropped
    }

    /// Seals an empty transport message (a keepalive) on `current` for the
    /// first peer whose data has gone unanswered for KEEPALIVE_TIMEOUT, and
    /// returns `(peer, len)` with the message at the start of `out`. A peer
    /// whose `current` cannot seal is disarmed and skipped, so one failing
    /// peer never starves the rest. Call until `None`.
    pub fn keepalive(&mut self, now_ns: u64, out: &mut [u8]) -> Option<(u16, usize)> {
        for (peer, p) in self.peers.iter_mut().enumerate() {
            // `checked_sub`: a clock reading before the arming never fires.
            let due = p.unacked_since.and_then(|t| now_ns.checked_sub(t)).is_some_and(|d| d >= KEEPALIVE_TIMEOUT_NS);
            if !due {
                continue;
            }
            p.unacked_since = None;
            let Some(s) = p.current.as_mut() else {
                continue;
            };
            if let Ok(len) = seal_into(s, &[], now_ns, out) {
                return Some((u16::try_from(peer).unwrap_or(u16::MAX), len));
            }
        }
        None
    }

    /// The peer and slot of the live session whose local index is `index`.
    fn find(&self, index: u32) -> Option<(usize, Slot)> {
        self.peers.iter().enumerate().find_map(|(i, p)| {
            p.sessions().into_iter().find_map(|(slot, s)| s.filter(|s| s.recv_index == index).map(|_| (i, slot)))
        })
    }

    #[cfg(test)]
    fn has(&self, peer: usize, slot: Slot) -> Option<u32> {
        let p = self.peers.get(peer)?;
        p.sessions().into_iter().find(|(s, _)| *s == slot)?.1.map(|s| s.recv_index)
    }
}

/// Validates decrypted plaintext; wipes it unless it is forwarded.
fn classify<'o>(allowed: &impl AllowedIps, peer: usize, out: &'o mut [u8], n: usize) -> Payload<'o> {
    if n == 0 {
        return Payload::Keepalive;
    }
    let out: &'o mut [u8] = match out.get_mut(..n) {
        Some(p) => p,
        None => return Payload::Invalid(DropReason::TooShort),
    };
    let verdict = match wire::parse_ipv4_packet(out) {
        Ok(ip) if !allowed.contains(peer, ip.src) => Err(Payload::SpoofedSource),
        Ok(ip) => Ok(ip.packet.len()),
        Err(r) => Err(Payload::Invalid(r)),
    };
    match verdict {
        Ok(len) => Payload::Forward(out.get(..len).unwrap_or(&[])),
        Err(drop) => {
            out.fill(0);
            drop
        }
    }
}

/// `len` rounded up to a multiple of 16; `None` above `MTU`.
fn padded_len(len: usize) -> Option<usize> {
    if len > MTU {
        return None;
    }
    len.checked_next_multiple_of(PAD).map(|l| l.min(MTU))
}

/// Copies `datagram` into the zeroed `plain`; returns the first `padded_len` bytes.
fn pad<'p>(plain: &'p mut [u8; MTU], datagram: &[u8], padded_len: usize) -> Option<&'p [u8]> {
    plain.get_mut(..datagram.len())?.copy_from_slice(datagram);
    plain.get(..padded_len)
}

/// Writes header || ciphertext || tag into `out`; returns its length.
fn seal_into(s: &mut Session, plain: &[u8], now_ns: u64, out: &mut [u8]) -> Result<usize, SessionError> {
    let need = plain.len().checked_add(TRANSPORT_HEADER_LEN + TAG_LEN).ok_or(SessionError::Buffer)?;
    let out = out.get_mut(..need).ok_or(SessionError::Buffer)?;
    let (hdr, body) = out.split_at_mut_checked(TRANSPORT_HEADER_LEN).ok_or(SessionError::Buffer)?;
    let (counter, n) = s.seal(plain, body, now_ns)?;
    wg_wire::emit_transport_header(s.send_index, counter, hdr).map_err(|_| SessionError::Buffer)?;
    n.checked_add(TRANSPORT_HEADER_LEN).ok_or(SessionError::Buffer)
}

#[cfg(test)]
mod tests;
