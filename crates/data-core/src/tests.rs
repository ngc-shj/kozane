#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use static_assertions::assert_not_impl_any;
use wg_core::REJECT_AFTER_TIME_NS;
use wire::{Body, EthAddrs, Frame, Udp4};

use super::*;

assert_not_impl_any!(Data<2>: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(Peer: Clone, Copy, core::fmt::Debug);

const T0: u64 = 1_000_000_000_000;
const PEER0_IP: Ipv4 = [10, 200, 0, 2];
const PEER1_IP: Ipv4 = [10, 201, 0, 5];
const HOST_IP: Ipv4 = [10, 99, 0, 2];
const EP1: Endpoint = Endpoint { ip: [192, 0, 2, 1], port: 1111 };
const EP2: Endpoint = Endpoint { ip: [198, 51, 100, 7], port: 2222 };

/// Peer 0 owns 10.200.0.2/32, peer 1 owns 10.201.0.0/24.
struct Allowed;

impl AllowedIps for Allowed {
    fn contains(&self, peer: usize, ip: Ipv4) -> bool {
        match peer {
            0 => ip == PEER0_IP,
            1 => ip[..3] == PEER1_IP[..3],
            _ => false,
        }
    }
}

type D = Data<2>;

/// The initiator's half of a session installed in `data`: its send key is
/// our receive key and vice versa, so packets go through real AEAD.
struct Client {
    s: Session,
    /// Our local index (the receiver index on its packets).
    to: u32,
    /// The client's clock: its session's creation time, so it never seals
    /// before `data` installed the session.
    at: u64,
}

impl Client {
    fn packet(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ct = std::vec![0u8; plaintext.len() + TAG_LEN];
        let (c, n) = self.s.seal(plaintext, &mut ct, self.at).unwrap();
        let mut msg = std::vec![0u8; TRANSPORT_HEADER_LEN];
        wg_wire::emit_transport_header(self.to, c, &mut msg).unwrap();
        msg.extend_from_slice(&ct[..n]);
        msg
    }

    /// Opens a message `outbound` produced; `None` if it is not for us.
    fn open(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        let t = Transport::parse(msg).ok()?;
        if t.receiver != self.s.recv_index {
            return None;
        }
        let mut pt = std::vec![0u8; t.ciphertext.len() - TAG_LEN];
        let n = self.s.open(t.counter, t.ciphertext, &mut pt, self.at).ok()?;
        pt.truncate(n);
        Some(pt)
    }
}

fn install_at(d: &mut D, peer: u16, local_index: u32, created_ns: u64) -> (InstallOutcome, Client) {
    let seed = local_index as u8;
    let send = [seed; 32];
    let recv = [seed ^ 0x80; 32];
    let remote_index = local_index + 1000;
    let o = d.install(&Install { peer, local_index, remote_index, send: &send, recv: &recv }, created_ns);
    let keys = SessionKeys { send: Key32::from_bytes(recv), recv: Key32::from_bytes(send) };
    (o, Client { s: Session::new(keys, remote_index, local_index, created_ns), to: local_index, at: created_ns })
}

fn install(d: &mut D, peer: u16, local_index: u32) -> Client {
    let (o, c) = install_at(d, peer, local_index, T0);
    assert_eq!(o, InstallOutcome::Installed);
    c
}

fn recv<'o>(d: &mut D, src: Endpoint, msg: &[u8], out: &'o mut [u8]) -> InboundOutcome<'o> {
    d.inbound(&Allowed, src, msg, T0, out)
}

fn confirm(d: &mut D, c: &mut Client) {
    let mut buf = [0u8; 64];
    let o = d.inbound(&Allowed, EP1, &c.packet(&[]), c.at, &mut buf);
    assert!(matches!(o, InboundOutcome::Authenticated { promoted: true, .. }), "{o:?}");
}

fn datagram_with(src: Ipv4, dst: Ipv4, payload: &[u8]) -> Vec<u8> {
    let f = Frame {
        eth: EthAddrs { src: [2; 6], dst: [4; 6] },
        body: Body::Udp4(Udp4 { src, dst, sport: 1, dport: 2, payload }),
    };
    let mut out = [0u8; wire::MAX_FRAME];
    let n = wire::emit(&f, &mut out).unwrap();
    out[wire::ETH_HDR..n].to_vec()
}

fn datagram(src: Ipv4, dst: Ipv4) -> Vec<u8> {
    datagram_with(src, dst, b"ping")
}

fn send(d: &mut D, packet: &[u8]) -> (OutboundOutcome, Vec<u8>) {
    let mut out = [0u8; MAX_TRANSPORT];
    let o = d.outbound(&Allowed, packet, T0, &mut out);
    let len = if let OutboundOutcome::Sealed { len, .. } = o { len } else { 0 };
    (o, out[..len].to_vec())
}

// --- install ---

#[test]
fn install_replaces_next_and_drops_the_old_one() {
    let mut d = D::new();
    let mut old = install(&mut d, 0, 1);
    let mut new = install(&mut d, 0, 2);
    assert_eq!(d.has(0, Slot::Next), Some(2));
    assert_eq!(recv(&mut d, EP1, &old.packet(&[]), &mut [0u8; 16]), InboundOutcome::UnknownIndex);
    assert!(matches!(recv(&mut d, EP1, &new.packet(&[]), &mut [0u8; 16]), InboundOutcome::Authenticated { .. }));
}

#[test]
fn install_rejects_an_index_live_in_any_peer_and_slot() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 7);
    assert_eq!(install_at(&mut d, 1, 7, T0).0, InstallOutcome::IndexCollision);
    assert_eq!(d.has(1, Slot::Next), None);
    // Also once confirmed into `current`, and for the same peer.
    confirm(&mut d, &mut a);
    assert_eq!(install_at(&mut d, 0, 7, T0).0, InstallOutcome::IndexCollision);
    assert_eq!(d.has(0, Slot::Current), Some(7));
    assert_eq!(d.has(0, Slot::Next), None);
}

#[test]
fn install_rejects_a_peer_out_of_range() {
    let mut d = D::new();
    assert_eq!(install_at(&mut d, 2, 1, T0).0, InstallOutcome::PeerOutOfRange);
    assert_eq!(install_at(&mut d, u16::MAX, 1, T0).0, InstallOutcome::PeerOutOfRange);
}

// --- promotion ---

#[test]
fn first_keepalive_on_next_promotes_it() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut buf = [0u8; 16];
    let o = recv(&mut d, EP1, &a.packet(&[]), &mut buf);
    assert_eq!(
        o,
        InboundOutcome::Authenticated { peer: 0, endpoint: Some(EP1), promoted: true, payload: Payload::Keepalive }
    );
    assert_eq!((d.has(0, Slot::Next), d.has(0, Slot::Current)), (None, Some(1)));
}

#[test]
fn first_data_packet_on_next_promotes_it_and_current_becomes_previous() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &b.packet(&datagram(PEER0_IP, HOST_IP)), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { promoted: true, payload: Payload::Forward(_), .. }));
    assert_eq!((d.has(0, Slot::Current), d.has(0, Slot::Previous)), (Some(2), Some(1)));
}

#[test]
fn unconfirmed_next_never_displaces_current_for_sending() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    let (o, msg) = send(&mut d, &datagram(HOST_IP, PEER0_IP));
    assert!(matches!(o, OutboundOutcome::Sealed { peer: 0, .. }));
    assert_eq!(b.open(&msg), None);
    assert_eq!(a.open(&msg).unwrap()[..32], datagram(HOST_IP, PEER0_IP)[..]);
}

#[test]
fn previous_is_still_accepted_for_receiving() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    confirm(&mut d, &mut b);
    let pkt = datagram(PEER0_IP, HOST_IP);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &a.packet(&pkt), &mut out);
    assert!(
        matches!(o, InboundOutcome::Authenticated { promoted: false, payload: Payload::Forward(p), .. } if p == pkt)
    );
    assert_eq!((d.has(0, Slot::Current), d.has(0, Slot::Previous)), (Some(2), Some(1)));
}

#[test]
fn promotion_drops_the_old_previous() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    confirm(&mut d, &mut b);
    let mut c = install(&mut d, 0, 3);
    confirm(&mut d, &mut c);
    assert_eq!((d.has(0, Slot::Current), d.has(0, Slot::Previous)), (Some(3), Some(2)));
    assert_eq!(recv(&mut d, EP1, &a.packet(&[]), &mut [0u8; 16]), InboundOutcome::UnknownIndex);
    // Its index is free again.
    assert_eq!(install_at(&mut d, 1, 1, T0).0, InstallOutcome::Installed);
}

#[test]
fn packets_on_current_do_not_promote() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let _b = install(&mut d, 0, 2);
    let mut buf = [0u8; 16];
    let o = recv(&mut d, EP1, &a.packet(&[]), &mut buf);
    assert!(matches!(o, InboundOutcome::Authenticated { promoted: false, .. }));
    assert_eq!((d.has(0, Slot::Next), d.has(0, Slot::Current)), (Some(2), Some(1)));
}

// --- roaming ---

#[test]
fn endpoint_update_only_on_a_new_highest_counter() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let msgs: Vec<_> = (0..3).map(|_| a.packet(&[])).collect();
    let mut out = [0u8; 16];
    let endpoint = |o: InboundOutcome<'_>| match o {
        InboundOutcome::Authenticated { endpoint, .. } => endpoint,
        o => panic!("{o:?}"),
    };
    assert_eq!(endpoint(recv(&mut d, EP1, &msgs[1], &mut out)), Some(EP1));
    // Older but in the window: authentic, accepted, yet no roaming.
    assert_eq!(endpoint(recv(&mut d, EP2, &msgs[0], &mut out)), None);
    assert_eq!(recv(&mut d, EP2, &msgs[1], &mut out), InboundOutcome::Rejected(SessionError::Replay));
    assert_eq!(endpoint(recv(&mut d, EP2, &msgs[2], &mut out)), Some(EP2));
}

fn endpoint_of(o: InboundOutcome<'_>) -> Option<Endpoint> {
    match o {
        InboundOutcome::Authenticated { endpoint, .. } => endpoint,
        o => panic!("{o:?}"),
    }
}

#[test]
fn delivered_endpoint_is_not_repeated_for_later_packets() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut out = [0u8; 16];
    assert_eq!(endpoint_of(recv(&mut d, EP1, &a.packet(&[]), &mut out)), Some(EP1));
    d.endpoint_delivered(0, EP1);
    for _ in 0..100 {
        assert_eq!(endpoint_of(recv(&mut d, EP1, &a.packet(&[]), &mut out)), None);
    }
}

#[test]
fn undelivered_endpoint_is_asked_for_again() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut out = [0u8; 16];
    assert_eq!(endpoint_of(recv(&mut d, EP1, &a.packet(&[]), &mut out)), Some(EP1));
    // The send failed, so nothing was recorded: the next packet asks again.
    assert_eq!(endpoint_of(recv(&mut d, EP1, &a.packet(&[]), &mut out)), Some(EP1));
}

#[test]
fn roaming_after_delivery_updates_once() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut out = [0u8; 16];
    recv(&mut d, EP1, &a.packet(&[]), &mut out);
    d.endpoint_delivered(0, EP1);
    assert_eq!(endpoint_of(recv(&mut d, EP2, &a.packet(&[]), &mut out)), Some(EP2));
    d.endpoint_delivered(0, EP2);
    assert_eq!(endpoint_of(recv(&mut d, EP2, &a.packet(&[]), &mut out)), None);
}

#[test]
fn roaming_to_a_delivered_endpoint_on_an_old_counter_does_not_update() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let old = a.packet(&[]);
    let new = a.packet(&[]);
    let mut out = [0u8; 16];
    recv(&mut d, EP1, &new, &mut out);
    d.endpoint_delivered(0, EP1);
    assert_eq!(endpoint_of(recv(&mut d, EP2, &old, &mut out)), None);
}

#[test]
fn session_clock_starts_when_data_installs_it() {
    let mut d = D::new();
    // `install`'s clock argument is data's own CNTPCT reading; the install
    // message carries no time at all. Boundary: expired at exactly
    // REJECT_AFTER_TIME after install, alive one nanosecond before.
    let (o, _) = install_at(&mut d, 0, 1, 1_000);
    assert_eq!(o, InstallOutcome::Installed);
    assert_eq!(d.tick(1_000 + wg_core::REJECT_AFTER_TIME_NS - 1), 0);
    assert_eq!(d.tick(1_000 + wg_core::REJECT_AFTER_TIME_NS), 1);
}

#[test]
fn each_session_tracks_its_own_highest_counter() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    for _ in 0..5 {
        recv(&mut d, EP1, &a.packet(&[]), &mut [0u8; 16]);
    }
    let mut b = install(&mut d, 0, 2);
    let mut buf = [0u8; 16];
    let o = recv(&mut d, EP2, &b.packet(&[]), &mut buf);
    assert!(matches!(o, InboundOutcome::Authenticated { endpoint: Some(EP2), .. }));
}

// --- inner packet checks ---

#[test]
fn forwards_exactly_the_datagram_without_padding() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let pkt = datagram_with(PEER0_IP, HOST_IP, b"hello"); // 33 bytes
    let mut padded = pkt.clone();
    padded.resize(48, 0);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &a.packet(&padded), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::Forward(p), .. } if p == pkt));
}

#[test]
fn spoofed_inner_source_is_dropped_and_wiped() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &a.packet(&datagram(PEER1_IP, HOST_IP)), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { peer: 0, payload: Payload::SpoofedSource, .. }));
    assert_eq!(out, [0; 64]);
}

#[test]
fn source_in_the_peers_own_range_is_forwarded() {
    let mut d = D::new();
    let mut b = install(&mut d, 1, 1);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &b.packet(&datagram([10, 201, 0, 99], HOST_IP)), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { peer: 1, payload: Payload::Forward(_), .. }));
}

#[test]
fn non_ipv4_plaintext_is_dropped_and_wiped() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &a.packet(&[0x60; 40]), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::Invalid(DropReason::Ipv4Version), .. }));
    assert_eq!(out, [0; 64]);
}

// --- refused packets ---

#[test]
fn malformed_and_unknown_index_are_distinct() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let mut msg = a.packet(&[]);
    assert_eq!(recv(&mut d, EP1, &msg[..31], &mut [0u8; 16]), InboundOutcome::Malformed(WireError::TooShort));
    msg[4] = 9;
    assert_eq!(recv(&mut d, EP1, &msg, &mut [0u8; 16]), InboundOutcome::UnknownIndex);
}

#[test]
fn failed_open_leaves_slots_and_endpoint_untouched() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let good = a.packet(&[]);
    let mut forged = good.clone();
    forged[TRANSPORT_HEADER_LEN] ^= 1;
    assert_eq!(recv(&mut d, EP2, &forged, &mut [0u8; 16]), InboundOutcome::Rejected(SessionError::Auth));
    assert_eq!((d.has(0, Slot::Next), d.has(0, Slot::Current)), (Some(1), None));
    // The forgery neither consumed the counter nor set a maximum.
    let mut buf = [0u8; 16];
    let o = recv(&mut d, EP1, &good, &mut buf);
    assert!(matches!(o, InboundOutcome::Authenticated { endpoint: Some(EP1), promoted: true, .. }));
    // A replay neither demotes nor moves anything.
    let mut b = install(&mut d, 0, 2);
    let b0 = b.packet(&[]);
    assert_eq!(recv(&mut d, EP2, &good, &mut [0u8; 16]), InboundOutcome::Rejected(SessionError::Replay));
    assert_eq!((d.has(0, Slot::Next), d.has(0, Slot::Current)), (Some(2), Some(1)));
    let mut buf = [0u8; 16];
    let o = recv(&mut d, EP2, &b0, &mut buf);
    assert!(matches!(o, InboundOutcome::Authenticated { endpoint: Some(EP2), promoted: true, .. }));
}

#[test]
fn expired_session_refuses_packets_until_tick_drops_it() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    let msg = a.packet(&[]);
    let late = T0 + REJECT_AFTER_TIME_NS;
    let mut buf = [0u8; 16];
    let o = d.inbound(&Allowed, EP1, &msg, late, &mut buf);
    assert_eq!(o, InboundOutcome::Rejected(SessionError::Expired));
    assert_eq!(d.has(0, Slot::Next), Some(1));
}

// --- expiry ---

#[test]
fn tick_drops_every_slot_including_next_at_reject_after_time() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    confirm(&mut d, &mut b);
    install(&mut d, 0, 3);
    let (_, _late) = install_at(&mut d, 1, 4, T0 + 1);
    assert_eq!(d.tick(T0 + REJECT_AFTER_TIME_NS - 1), 0);
    assert_eq!(d.tick(T0 + REJECT_AFTER_TIME_NS), 3);
    for slot in [Slot::Next, Slot::Current, Slot::Previous] {
        assert_eq!(d.has(0, slot), None);
    }
    assert_eq!(d.has(1, Slot::Next), Some(4));
    assert_eq!(d.tick(T0 + REJECT_AFTER_TIME_NS + 1), 1);
    assert_eq!(d.has(1, Slot::Next), None);
}

// --- outbound ---

#[test]
fn outbound_needs_a_peer_and_a_current_session() {
    let mut d = D::new();
    assert_eq!(send(&mut d, &datagram(HOST_IP, [10, 9, 9, 9])).0, OutboundOutcome::NoPeer);
    let mut a = install(&mut d, 0, 1);
    assert_eq!(send(&mut d, &datagram(HOST_IP, PEER0_IP)).0, OutboundOutcome::NoSession);
    confirm(&mut d, &mut a);
    // Peer 1 has nothing even though peer 0 does.
    assert_eq!(send(&mut d, &datagram(HOST_IP, PEER1_IP)).0, OutboundOutcome::NoSession);
}

#[test]
fn outbound_routes_by_destination_and_uses_the_remote_index() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 1, 2);
    confirm(&mut d, &mut b);
    let (o, msg) = send(&mut d, &datagram(HOST_IP, PEER1_IP));
    assert!(matches!(o, OutboundOutcome::Sealed { peer: 1, .. }));
    assert_eq!(Transport::parse(&msg).unwrap().receiver, 1002);
    assert!(b.open(&msg).is_some());
}

#[test]
fn outbound_does_not_use_previous() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut b = install(&mut d, 0, 2);
    confirm(&mut d, &mut b);
    let (_, msg) = send(&mut d, &datagram(HOST_IP, PEER0_IP));
    assert_eq!(a.open(&msg), None);
    assert!(b.open(&msg).is_some());
}

#[test]
fn outbound_pads_plaintext_to_a_multiple_of_16() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let pkt = datagram_with(HOST_IP, PEER0_IP, b"hello"); // 33 bytes
    // Trailing bytes past the IPv4 total length are not sent.
    let mut trailing = pkt.clone();
    trailing.extend_from_slice(&[0xee; 7]);
    let (o, msg) = send(&mut d, &trailing);
    assert_eq!(o, OutboundOutcome::Sealed { peer: 0, len: TRANSPORT_MIN_LEN + 48 });
    let pt = a.open(&msg).unwrap();
    assert_eq!(pt[..33], pkt[..]);
    assert_eq!(pt[33..], [0; 15]);
}

#[test]
fn outbound_padding_is_bounded_by_the_mtu() {
    assert_eq!(MTU % 16, 0);
    assert_eq!((padded_len(0), padded_len(16), padded_len(17)), (Some(0), Some(16), Some(32)));
    assert_eq!((padded_len(MTU), padded_len(MTU + 1)), (Some(MTU), None));
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let full = datagram_with(HOST_IP, PEER0_IP, &[7; MTU - 28]);
    let (o, msg) = send(&mut d, &full);
    assert_eq!(o, OutboundOutcome::Sealed { peer: 0, len: MAX_TRANSPORT });
    assert_eq!(a.open(&msg).unwrap(), full);
    let over = datagram_with(HOST_IP, PEER0_IP, &[7; MTU - 27]);
    assert_eq!(send(&mut d, &over).0, OutboundOutcome::TooLarge);
}

#[test]
fn outbound_rejects_invalid_packets_and_short_buffers() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    assert_eq!(send(&mut d, &[0x45; 10]).0, OutboundOutcome::Dropped(DropReason::TooShort));
    let mut out = [0u8; TRANSPORT_MIN_LEN + 31];
    let o = d.outbound(&Allowed, &datagram(HOST_IP, PEER0_IP), T0, &mut out);
    assert_eq!(o, OutboundOutcome::Rejected(SessionError::Buffer));
    // The failed seal did not consume a counter.
    let (_, msg) = send(&mut d, &datagram(HOST_IP, PEER0_IP));
    assert_eq!(Transport::parse(&msg).unwrap().counter, 0);
}

#[test]
fn outbound_refuses_an_expired_current() {
    let mut d = D::new();
    let mut a = install(&mut d, 0, 1);
    confirm(&mut d, &mut a);
    let mut out = [0u8; MAX_TRANSPORT];
    let o = d.outbound(&Allowed, &datagram(HOST_IP, PEER0_IP), T0 + REJECT_AFTER_TIME_NS, &mut out);
    assert_eq!(o, OutboundOutcome::Rejected(SessionError::Expired));
}

// --- passive keepalive ---

const KEEPALIVE: u64 = wg_core::KEEPALIVE_TIMEOUT_NS;

fn data_in(d: &mut D, c: &mut Client, src: Ipv4, now_ns: u64) {
    let mut out = [0u8; 64];
    let o = d.inbound(&Allowed, EP1, &c.packet(&datagram(src, HOST_IP)), now_ns, &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::Forward(_), .. }), "{o:?}");
}

fn keepalive(d: &mut D, now_ns: u64) -> Option<(u16, Vec<u8>)> {
    let mut out = [0u8; MAX_TRANSPORT];
    d.keepalive(now_ns, &mut out).map(|(peer, len)| (peer, out[..len].to_vec()))
}

fn confirmed(d: &mut D, peer: u16, local_index: u32) -> Client {
    let mut c = install(d, peer, local_index);
    confirm(d, &mut c);
    c
}

#[test]
fn keepalive_is_not_sent_when_a_reply_went_out() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    assert!(matches!(send(&mut d, &datagram(HOST_IP, PEER0_IP)).0, OutboundOutcome::Sealed { .. }));
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE), None);
}

#[test]
fn unanswered_data_gets_exactly_one_empty_message_on_the_next_counter() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    let (_, first) = send(&mut d, &datagram(HOST_IP, PEER0_IP));
    assert!(a.open(&first).is_some());
    data_in(&mut d, &mut a, PEER0_IP, T0);
    let (peer, msg) = keepalive(&mut d, T0 + KEEPALIVE).unwrap();
    assert_eq!((peer, msg.len()), (0, TRANSPORT_MIN_LEN));
    assert_eq!(Transport::parse(&msg).unwrap().counter, 1);
    assert_eq!(a.open(&msg), Some(Vec::new()));
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE), None);
    assert_eq!(keepalive(&mut d, T0 + 2 * KEEPALIVE), None);
}

#[test]
fn sent_keepalive_is_classified_as_keepalive_by_a_receiving_data() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    let (_, msg) = keepalive(&mut d, T0 + KEEPALIVE).unwrap();
    // The peer's side as another `Data`: its receive key is our send key.
    let mut peer = D::new();
    let (send, recv_key) = ([1u8 ^ 0x80; 32], [1u8; 32]);
    let o = peer.install(&Install { peer: 0, local_index: 1001, remote_index: 1, send: &send, recv: &recv_key }, T0);
    assert_eq!(o, InstallOutcome::Installed);
    let mut out = [0u8; 16];
    let o = peer.inbound(&Allowed, EP1, &msg, T0 + KEEPALIVE, &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::Keepalive, .. }), "{o:?}");
}

#[test]
fn received_keepalives_alone_do_not_arm() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    for _ in 0..3 {
        recv(&mut d, EP1, &a.packet(&[]), &mut [0u8; 16]);
    }
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE), None);
}

#[test]
fn expired_current_is_disarmed_and_a_later_peer_is_still_served() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    // Peer 1's session starts later, so it outlives peer 0's.
    let t1 = T0 + 10 * KEEPALIVE;
    let (o, mut b) = install_at(&mut d, 1, 2, t1);
    assert_eq!(o, InstallOutcome::Installed);
    confirm(&mut d, &mut b);
    data_in(&mut d, &mut b, PEER1_IP, t1);
    // Peer 0's current has expired; peer 1's has not.
    let late = T0 + REJECT_AFTER_TIME_NS;
    let (peer, msg) = keepalive(&mut d, late).unwrap();
    assert_eq!(peer, 1);
    assert_eq!(b.open(&msg), Some(Vec::new()));
    assert_eq!(keepalive(&mut d, late), None);
    // Peer 0 was disarmed, not merely skipped: a fresh current sends nothing.
    let (_, mut a2) = install_at(&mut d, 0, 3, late);
    confirm(&mut d, &mut a2);
    assert_eq!(keepalive(&mut d, late), None);
}

#[test]
fn tick_dropping_current_disarms() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    let late = T0 + REJECT_AFTER_TIME_NS;
    assert_eq!(d.tick(late), 1);
    let (_, mut a2) = install_at(&mut d, 0, 2, late);
    confirm(&mut d, &mut a2);
    assert_eq!(keepalive(&mut d, late), None);
}

#[test]
fn data_on_previous_gets_a_keepalive_on_current() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    let mut b = confirmed(&mut d, 0, 2);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    let (_, msg) = keepalive(&mut d, T0 + KEEPALIVE).unwrap();
    assert_eq!(a.open(&msg), None);
    assert_eq!(b.open(&msg), Some(Vec::new()));
}

#[test]
fn promotion_keeps_the_debt_and_the_new_current_carries_the_keepalive() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    let mut b = confirmed(&mut d, 0, 2);
    let (_, msg) = keepalive(&mut d, T0 + KEEPALIVE).unwrap();
    assert_eq!(b.open(&msg), Some(Vec::new()));
}

#[test]
fn second_data_packet_does_not_move_the_deadline() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    data_in(&mut d, &mut a, PEER0_IP, T0 + KEEPALIVE / 2);
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE - 1), None);
    assert!(keepalive(&mut d, T0 + KEEPALIVE).is_some());
}

#[test]
fn rejected_packet_does_not_arm() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    let mut forged = a.packet(&datagram(PEER0_IP, HOST_IP));
    forged[TRANSPORT_HEADER_LEN] ^= 1;
    assert_eq!(recv(&mut d, EP1, &forged, &mut [0u8; 64]), InboundOutcome::Rejected(SessionError::Auth));
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE), None);
}

#[test]
fn spoofed_or_invalid_payloads_do_not_arm() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    let mut out = [0u8; 64];
    let o = recv(&mut d, EP1, &a.packet(&datagram(PEER1_IP, HOST_IP)), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::SpoofedSource, .. }));
    let o = recv(&mut d, EP1, &a.packet(&[0x60; 40]), &mut out);
    assert!(matches!(o, InboundOutcome::Authenticated { payload: Payload::Invalid(_), .. }));
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE), None);
}

#[test]
fn backwards_clock_does_not_fire() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    assert_eq!(keepalive(&mut d, T0 - 1), None);
    assert_eq!(keepalive(&mut d, 0), None);
    // Still armed for the real deadline.
    assert!(keepalive(&mut d, T0 + KEEPALIVE).is_some());
}

#[test]
fn keepalive_fires_at_exactly_the_timeout_and_not_a_nanosecond_before() {
    let mut d = D::new();
    let mut a = confirmed(&mut d, 0, 1);
    data_in(&mut d, &mut a, PEER0_IP, T0);
    assert_eq!(keepalive(&mut d, T0 + KEEPALIVE - 1), None);
    assert!(keepalive(&mut d, T0 + KEEPALIVE).is_some());
}

// --- handler loop ---

/// A PD stand-in for `run_passes`: `waiting` messages queue on installs,
/// inbound and outbound; every call is logged in order.
#[derive(Default)]
struct FakePass {
    waiting: [usize; 3],
    log: Vec<&'static str>,
    maxes: Vec<usize>,
}

impl FakePass {
    fn queued(waiting: [usize; 3]) -> Self {
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
    fn expire(&mut self) {
        self.log.push("expire");
    }
    fn serve_installs(&mut self, max: usize) -> usize {
        self.take(0, "installs", max)
    }
    fn serve_inbound(&mut self, max: usize) -> usize {
        self.take(1, "inbound", max)
    }
    fn serve_outbound(&mut self, max: usize) -> usize {
        self.take(2, "outbound", max)
    }
    fn keepalives(&mut self) {
        self.log.push("keepalives");
    }
    fn end_pass(&mut self) {
        self.log.push("end");
    }
}

#[test]
fn every_pass_of_an_inbound_flood_runs_the_keepalives_and_ends_with_notify() {
    let mut io = FakePass::queued([0, 3 * PASS_MSGS, 0]);
    run_passes(&mut io);
    let pass = ["expire", "installs", "inbound", "outbound", "keepalives", "end"];
    // Three full passes, then one that finds the queue empty and breaks.
    assert_eq!(io.log, pass.repeat(4), "each pass must end with end_pass, after expiry, installs first and keepalives last");
}

#[test]
fn every_data_input_is_bounded_to_pass_msgs() {
    let mut io = FakePass::queued([PASS_MSGS + 1; 3]);
    run_passes(&mut io);
    assert!(io.maxes.iter().all(|&m| m == PASS_MSGS), "inputs must be capped at PASS_MSGS: {:?}", io.maxes);
    assert_eq!(io.passes(), 2);
}

#[test]
fn k_on_any_one_data_input_runs_another_pass() {
    for input in 0..3 {
        let mut waiting = [0; 3];
        waiting[input] = PASS_MSGS;
        let mut io = FakePass::queued(waiting);
        run_passes(&mut io);
        assert_eq!(io.passes(), 2, "input {input}");
    }
}

#[test]
fn k_minus_one_on_every_data_input_is_the_last_pass() {
    let mut io = FakePass::queued([PASS_MSGS - 1; 3]);
    run_passes(&mut io);
    assert_eq!((io.passes(), io.waiting), (1, [0; 3]));
}
