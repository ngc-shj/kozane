//! Group authorization and the flow table (M8 plan C8, D9): what a peer may
//! reach on the LAN, and what the LAN may send back.
//!
//! Inbound (tunnel → LAN): default deny. A packet from peer `p` passes iff
//! a group `p` belongs to has a rule naming its destination, protocol and
//! destination port ([`rule_admits`]); ICMP rules name echo requests only.
//! Every pass records (or refreshes) the flow in `p`'s share of the table.
//!
//! Outbound (LAN → tunnel): a packet passes only as the reverse of a live
//! flow (ICMP: an echo reply with the request's id), and the flow names the
//! peer. `data` still routes by allowed IPs (D9): the flow's peer address
//! came from a packet `data` authenticated as that peer, and allowed IPs
//! never overlap, so a reply on X's flow can only be sealed for X. A LAN
//! host that spoofs the remote end of a live flow is not stopped (RM8-10).
//!
//! The table is `MAX_FLOWS` entries in `MAX_PEERS` fixed shares: a peer
//! that opens more flows than its share evicts its own least recently used
//! one, never another peer's. A flow ends after `FLOW_IDLE_NS` without a
//! packet, at once on a TCP RST seen in its own direction (from the peer on
//! the forward tuple, from the LAN on the reverse one), or `FLOW_LINGER_NS`
//! after FIN was seen both ways. The clock is an input (`now`, ns from a
//! monotonic counter), so all of it is pure.

use limits::{FLOW_IDLE_NS, FLOW_LINGER_NS, MAX_PEERS};
use policy_wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, Rule};
use wire::{DropReason, IPPROTO_TCP, IPPROTO_UDP, IPV4_HDR, Ipv4, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, UDP_HDR};

/// Entries in the table. Kani proves the logic over a small table, one
/// entry a peer (below), with the same code (M8 plan C8).
#[cfg(not(kani))]
pub const MAX_FLOWS: usize = limits::MAX_FLOWS;
#[cfg(kani)]
// One entry a peer under Kani: an own-share eviction still happens on every
// second flow, and I8.3's operation sequence fits the 40 GB cap (D-17).
pub const MAX_FLOWS: usize = MAX_PEERS;
/// Each peer's share of the table.
pub const QUOTA: usize = MAX_FLOWS / MAX_PEERS;
// Both instances (F36): every peer gets the same whole share, at least one.
const _: () = assert!(MAX_FLOWS.is_multiple_of(MAX_PEERS) && QUOTA >= 1, "MAX_FLOWS must split into per-peer quotas");

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
/// Destination unreachable, source quench, redirect, time exceeded and
/// parameter problem: the ICMP errors, which quote another packet and are
/// dropped both ways (M8 plan C8).
const ICMP_ERRORS: [u8; 5] = [3, 4, 5, 11, 12];
const ICMP_HDR: usize = 8;

/// Why `inner` refused a packet: the `InnerDenied` reason
/// (`audit_event::INNER_REASON_NAMES`, which the PD checks against this at
/// compile time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Denied {
    /// Inbound: no rule of the peer's groups admits it (a peer with no
    /// groups reaches nothing).
    NoRule = 0,
    /// Inbound: the peer id names no peer of the bundle.
    UnknownPeer = 1,
    /// Outbound: no live flow it answers.
    NoFlow = 2,
    /// Either way: an ICMP error.
    IcmpError = 3,
}

impl Denied {
    /// Every reason, in code order (`ALL[i].code() == i`).
    pub const ALL: [Denied; 4] = [Denied::NoRule, Denied::UnknownPeer, Denied::NoFlow, Denied::IcmpError];

    pub const fn code(self) -> u16 {
        self as u16
    }

    pub const fn name(self) -> &'static str {
        match self {
            Denied::NoRule => "NoRule",
            Denied::UnknownPeer => "UnknownPeer",
            Denied::NoFlow => "NoFlow",
            Denied::IcmpError => "IcmpError",
        }
    }
}

/// What a packet carries above IPv4, as far as authorization looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp { sport: u16, dport: u16, flags: u8 },
    Udp { sport: u16, dport: u16 },
    EchoRequest { id: u16 },
    EchoReply { id: u16 },
    IcmpError,
    /// Any other ICMP type, or another protocol.
    Other,
}

/// A packet's addresses and transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub transport: Transport,
}

/// Reads a datagram's addresses and transport. Refused: an IPv4 header
/// `wire` refuses (options, fragments, checksum), a TCP segment
/// `wire::parse_tcp` refuses, a UDP header shorter than 8 bytes or whose
/// length is not the datagram's, an ICMP message shorter than its header.
pub fn classify(packet: &[u8]) -> Result<Packet, DropReason> {
    if packet.len() > wire::MAX_FRAME {
        return Err(DropReason::TooLong);
    }
    let p = wire::parse_ipv4_packet(packet)?;
    let payload = p.packet.get(IPV4_HDR..).ok_or(DropReason::Ipv4BadLength)?;
    let be16 = |at: usize| -> Option<u16> {
        let b: [u8; 2] = payload.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    };
    let transport = match p.proto {
        IPPROTO_TCP => {
            let t = wire::parse_tcp(&p)?;
            Transport::Tcp { sport: t.src_port, dport: t.dst_port, flags: t.flags }
        }
        IPPROTO_UDP => {
            if payload.len() < UDP_HDR || be16(4).map(usize::from) != Some(payload.len()) {
                return Err(DropReason::UdpBadLength);
            }
            match (be16(0), be16(2)) {
                (Some(sport), Some(dport)) => Transport::Udp { sport, dport },
                _ => return Err(DropReason::UdpBadLength),
            }
        }
        PROTO_ICMP => {
            if payload.len() < ICMP_HDR {
                return Err(DropReason::TooShort);
            }
            let (kind, code, id) = (payload.first().copied(), payload.get(1).copied(), be16(4));
            match (kind, code, id) {
                (Some(ICMP_ECHO_REQUEST), Some(0), Some(id)) => Transport::EchoRequest { id },
                (Some(ICMP_ECHO_REPLY), Some(0), Some(id)) => Transport::EchoReply { id },
                (Some(k), _, _) if ICMP_ERRORS.contains(&k) => Transport::IcmpError,
                _ => Transport::Other,
            }
        }
        _ => Transport::Other,
    };
    Ok(Packet { src: p.src, dst: p.dst, transport })
}

/// The bundle's groups and rules as `inner` reads them (M8 plan C1, C8).
pub trait Rules {
    /// `peer`'s group-membership mask (bit `g`: a member of group `g`), or
    /// `None` if the bundle names no such peer.
    fn groups(&self, peer: u8) -> Option<u8>;
    /// True if some rule of group `group` satisfies `f` (false if there is
    /// no such group).
    fn any_rule_in(&self, group: u8, f: impl FnMut(&Rule) -> bool) -> bool;
}

/// `r` admits a packet with this destination and transport: the address in
/// the rule's prefix, the same protocol, the destination port in
/// `port_lo..=port_hi`; an ICMP rule (ports 0) admits echo requests only.
pub fn rule_admits(r: &Rule, dst: Ipv4, t: Transport) -> bool {
    if !r.dst.contains(dst) {
        return false;
    }
    match t {
        Transport::Tcp { dport, .. } => r.proto == PROTO_TCP && r.port_lo <= dport && dport <= r.port_hi,
        Transport::Udp { dport, .. } => r.proto == PROTO_UDP && r.port_lo <= dport && dport <= r.port_hi,
        Transport::EchoRequest { .. } => r.proto == PROTO_ICMP && r.port_lo == 0 && r.port_hi == 0,
        Transport::EchoReply { .. } | Transport::IcmpError | Transport::Other => false,
    }
}

/// True if a rule of a group `mask` names admits the packet.
fn groups_admit<R: Rules>(rules: &R, mask: u8, dst: Ipv4, t: Transport) -> bool {
    (0..8u8).filter(|g| (mask >> g) & 1 == 1).any(|g| rules.any_rule_in(g, |r| rule_admits(r, dst, t)))
}

/// A flow, seen from the peer that opened it: its address and port and the
/// LAN host's (an ICMP echo's id stands in for both ports).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuple {
    pub proto: u8,
    pub peer_ip: Ipv4,
    pub peer_port: u16,
    pub lan_ip: Ipv4,
    pub lan_port: u16,
}

impl Tuple {
    /// The flow a packet from a peer opens, if its transport opens one.
    pub fn inbound(p: &Packet) -> Option<Tuple> {
        let (proto, sport, dport) = match p.transport {
            Transport::Tcp { sport, dport, .. } => (PROTO_TCP, sport, dport),
            Transport::Udp { sport, dport } => (PROTO_UDP, sport, dport),
            Transport::EchoRequest { id } => (PROTO_ICMP, id, id),
            Transport::EchoReply { .. } | Transport::IcmpError | Transport::Other => return None,
        };
        Some(Tuple { proto, peer_ip: p.src, peer_port: sport, lan_ip: p.dst, lan_port: dport })
    }

    /// The flow a packet from the LAN would answer, if its transport can
    /// answer one.
    pub fn outbound(p: &Packet) -> Option<Tuple> {
        let (proto, sport, dport) = match p.transport {
            Transport::Tcp { sport, dport, .. } => (PROTO_TCP, sport, dport),
            Transport::Udp { sport, dport } => (PROTO_UDP, sport, dport),
            Transport::EchoReply { id } => (PROTO_ICMP, id, id),
            Transport::EchoRequest { .. } | Transport::IcmpError | Transport::Other => return None,
        };
        Some(Tuple { proto, peer_ip: p.dst, peer_port: dport, lan_ip: p.src, lan_port: sport })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flow {
    used: bool,
    tuple: Tuple,
    last_ns: u64,
    fin_in: bool,
    fin_out: bool,
    /// When FIN had been seen both ways.
    closing_since: Option<u64>,
}

const EMPTY: Flow = Flow {
    used: false,
    tuple: Tuple { proto: 0, peer_ip: [0; 4], peer_port: 0, lan_ip: [0; 4], lan_port: 0 },
    last_ns: 0,
    fin_in: false,
    fin_out: false,
    closing_since: None,
};

impl Flow {
    fn alive(&self, now: u64) -> bool {
        self.used
            && now.saturating_sub(self.last_ns) <= FLOW_IDLE_NS
            && self.closing_since.is_none_or(|t| now.saturating_sub(t) <= FLOW_LINGER_NS)
    }

    fn is(&self, t: &Tuple, now: u64) -> bool {
        self.alive(now) && self.tuple == *t
    }

    /// A packet of this flow went by: `inbound` from the peer, else from
    /// the LAN, with these TCP flags (0 for UDP and ICMP).
    fn seen(&mut self, inbound: bool, flags: u8, now: u64) {
        self.last_ns = now;
        if flags & TCP_RST != 0 {
            self.used = false;
            return;
        }
        if inbound && flags & (TCP_SYN | TCP_ACK) == TCP_SYN {
            // The peer opens the tuple anew: an old close is forgotten.
            self.fin_in = false;
            self.fin_out = false;
            self.closing_since = None;
        }
        if flags & TCP_FIN != 0 {
            if inbound {
                self.fin_in = true;
            } else {
                self.fin_out = true;
            }
        }
        if self.fin_in && self.fin_out && self.closing_since.is_none() {
            self.closing_since = Some(now);
        }
    }
}

/// An inbound packet's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    Allow,
    Deny(Denied),
    Malformed(DropReason),
}

/// An outbound packet's verdict: on `Allow`, the peer whose flow it
/// answers; on `Deny`, its destination, so the PD can name the peer it was
/// headed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    Allow { peer: u8 },
    Deny { reason: Denied, dst: Ipv4 },
    Malformed(DropReason),
}

fn tcp_flags(t: Transport) -> u8 {
    match t {
        Transport::Tcp { flags, .. } => flags,
        _ => 0,
    }
}

/// The flow table: `MAX_PEERS` shares of `QUOTA` entries, share `p` peer
/// `p`'s. Built by a const fn, so the PD keeps it in a static.
#[cfg_attr(kani, derive(Clone, Copy))]
pub struct FlowTable {
    flows: [Flow; MAX_FLOWS],
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    pub const fn new() -> Self {
        Self { flows: [EMPTY; MAX_FLOWS] }
    }

    fn share(&mut self, peer: u8) -> &mut [Flow] {
        let start = usize::from(peer).saturating_mul(QUOTA);
        self.flows.get_mut(start..start.saturating_add(QUOTA)).unwrap_or(&mut [])
    }

    /// A packet from peer `peer` (the id `data` authenticated, the bundle
    /// index) for the LAN.
    pub fn inbound<R: Rules>(&mut self, rules: &R, peer: u8, packet: &[u8], now: u64) -> Inbound {
        if usize::from(peer) >= MAX_PEERS || rules.groups(peer).is_none() {
            return Inbound::Deny(Denied::UnknownPeer);
        }
        match classify(packet) {
            Ok(p) => self.authorize_inbound(rules, peer, &p, now),
            Err(r) => Inbound::Malformed(r),
        }
    }

    /// [`inbound`](Self::inbound) on a classified packet: default deny;
    /// allowed iff a rule of `peer`'s groups admits it, and then its flow is
    /// recorded in `peer`'s share.
    pub fn authorize_inbound<R: Rules>(&mut self, rules: &R, peer: u8, p: &Packet, now: u64) -> Inbound {
        if usize::from(peer) >= MAX_PEERS {
            return Inbound::Deny(Denied::UnknownPeer);
        }
        let Some(mask) = rules.groups(peer) else {
            return Inbound::Deny(Denied::UnknownPeer);
        };
        if p.transport == Transport::IcmpError {
            return Inbound::Deny(Denied::IcmpError);
        }
        if !groups_admit(rules, mask, p.dst, p.transport) {
            return Inbound::Deny(Denied::NoRule);
        }
        // Every transport a rule admits opens a flow.
        let Some(tuple) = Tuple::inbound(p) else {
            return Inbound::Deny(Denied::NoRule);
        };
        let flags = tcp_flags(p.transport);
        let share = self.share(peer);
        if let Some(f) = share.iter_mut().find(|f| f.is(&tuple, now)) {
            f.seen(true, flags, now);
            return Inbound::Allow;
        }
        if flags & TCP_RST != 0 {
            // A reset of nothing tracked opens nothing.
            return Inbound::Allow;
        }
        let free = share.iter().position(|f| !f.alive(now));
        // The share is full of live flows: the peer's own least recently
        // used one goes.
        let lru = || share.iter().enumerate().min_by_key(|(_, f)| f.last_ns).map(|(i, _)| i);
        let slot = free.or_else(lru);
        if let Some(f) = slot.and_then(|i| share.get_mut(i)) {
            *f = Flow { used: true, tuple, last_ns: now, ..EMPTY };
            f.seen(true, flags, now);
        }
        Inbound::Allow
    }

    /// A packet from the LAN for the tunnel (already TTL-checked by
    /// `from_lan`).
    pub fn outbound(&mut self, packet: &[u8], now: u64) -> Outbound {
        match classify(packet) {
            Ok(p) => self.authorize_outbound(&p, now),
            Err(r) => Outbound::Malformed(r),
        }
    }

    /// [`outbound`](Self::outbound) on a classified packet: allowed only as
    /// the reverse of a live flow, and then that flow's peer.
    pub fn authorize_outbound(&mut self, p: &Packet, now: u64) -> Outbound {
        if p.transport == Transport::IcmpError {
            return Outbound::Deny { reason: Denied::IcmpError, dst: p.dst };
        }
        let deny = Outbound::Deny { reason: Denied::NoFlow, dst: p.dst };
        let Some(tuple) = Tuple::outbound(p) else {
            return deny;
        };
        let Some(i) = self.flows.iter().position(|f| f.is(&tuple, now)) else {
            return deny;
        };
        let (Some(f), Ok(peer)) = (self.flows.get_mut(i), u8::try_from(i.checked_div(QUOTA).unwrap_or(usize::MAX))) else {
            return deny;
        };
        f.seen(false, tcp_flags(p.transport), now);
        Outbound::Allow { peer }
    }

    /// Live flows in `peer`'s share at `now`.
    pub fn live(&mut self, peer: u8, now: u64) -> usize {
        self.share(peer).iter().filter(|f| f.alive(now)).count()
    }
}

/// A bundle-shaped [`Rules`] for the unit tests and the proofs: peer `i`'s
/// mask is `peers[i]`, group `g`'s rules `groups[g]`.
#[cfg(any(test, kani))]
pub(crate) struct ModelRules<'a> {
    pub peers: &'a [u8],
    pub groups: &'a [&'a [Rule]],
}

#[cfg(any(test, kani))]
impl Rules for ModelRules<'_> {
    fn groups(&self, peer: u8) -> Option<u8> {
        self.peers.get(usize::from(peer)).copied()
    }

    fn any_rule_in(&self, group: u8, f: impl FnMut(&Rule) -> bool) -> bool {
        self.groups.get(usize::from(group)).is_some_and(|rules| rules.iter().any(f))
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use policy_wire::Prefix;

    fn any_rule() -> Rule {
        let len: u8 = kani::any();
        kani::assume(len <= 32);
        Rule { dst: Prefix { addr: kani::any(), len }, proto: kani::any(), port_lo: kani::any(), port_hi: kani::any() }
    }

    fn any_transport() -> Transport {
        match kani::any::<u8>() {
            0 => Transport::Tcp { sport: kani::any(), dport: kani::any(), flags: kani::any() },
            1 => Transport::Udp { sport: kani::any(), dport: kani::any() },
            2 => Transport::EchoRequest { id: kani::any() },
            3 => Transport::EchoReply { id: kani::any() },
            4 => Transport::IcmpError,
            _ => Transport::Other,
        }
    }

    fn any_packet() -> Packet {
        Packet { src: kani::any(), dst: kani::any(), transport: any_transport() }
    }

    /// One of two values: I8.3's operation sequence runs out of memory over
    /// full-width fields (CBMC at the 40 GB cap). The table only compares
    /// addresses, ports, ids and peers, never computes on them, so two values
    /// each still reach every match/mismatch branch (deviation D-17).
    fn one_of<T: Copy>(a: T, b: T) -> T {
        if kani::any() { a } else { b }
    }

    fn small_packet() -> Packet {
        let (x, y) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        let transport = match kani::any::<u8>() {
            0 => Transport::Tcp { sport: one_of(1, 2), dport: one_of(1, 2), flags: kani::any() },
            1 => Transport::Udp { sport: one_of(1, 2), dport: one_of(1, 2) },
            2 => Transport::EchoRequest { id: one_of(1, 2) },
            3 => Transport::EchoReply { id: one_of(1, 2) },
            _ => Transport::IcmpError,
        };
        Packet { src: one_of(x, y), dst: one_of(x, y), transport }
    }

    /// `dst` in `r`'s prefix, written apart from `Prefix::contains`: the
    /// top `len` bits agree.
    fn in_prefix(r: &Rule, dst: Ipv4) -> bool {
        let (a, b) = (u32::from_be_bytes(r.dst.addr), u32::from_be_bytes(dst));
        r.dst.len == 0 || (a ^ b) >> (32 - u32::from(r.dst.len)) == 0
    }

    /// The rule match C8 states, written apart from `rule_admits`.
    fn matches(r: &Rule, p: &Packet) -> bool {
        in_prefix(r, p.dst)
            && match p.transport {
                Transport::Tcp { dport, .. } => r.proto == 6 && r.port_lo <= dport && dport <= r.port_hi,
                Transport::Udp { dport, .. } => r.proto == 17 && r.port_lo <= dport && dport <= r.port_hi,
                Transport::EchoRequest { .. } => r.proto == 1 && r.port_lo == 0 && r.port_hi == 0,
                _ => false,
            }
    }

    /// Some rule of some group `peers[peer]` names matches `p`.
    fn some_rule_matches(peers: &[u8], groups: &[&[Rule]], peer: u8, p: &Packet) -> bool {
        let Some(&mask) = peers.get(usize::from(peer)) else { return false };
        let mut found = false;
        for (g, rules) in groups.iter().enumerate() {
            if (mask >> g) & 1 == 1 {
                for r in rules.iter() {
                    found |= matches(r, p);
                }
            }
        }
        found
    }

    /// I8.1: an inbound `Allow` means a rule of one of the peer's groups
    /// matches the packet, whatever the table held before.
    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_1_inbound_allow_has_a_matching_rule() {
        let (r0, r1) = (any_rule(), any_rule());
        let (g0, g1) = ([r0], [r1]);
        let groups: [&[Rule]; 2] = [&g0, &g1];
        let peers: [u8; 2] = [kani::any(), kani::any()];
        let rules = ModelRules { peers: &peers, groups: &groups };
        let mut table = FlowTable::new();
        // An arbitrary earlier packet, so a recorded flow is in play.
        let first = any_packet();
        let t0: u64 = kani::any();
        let _ = table.authorize_inbound(&rules, kani::any(), &first, t0);
        let (peer, p, now): (u8, Packet, u64) = (kani::any(), any_packet(), kani::any());
        kani::assume(now >= t0);
        let v = table.authorize_inbound(&rules, peer, &p, now);
        if v == Inbound::Allow {
            assert!(some_rule_matches(&peers, &groups, peer, &p));
        }
        kani::cover!(v == Inbound::Allow && Tuple::inbound(&first) == Tuple::inbound(&p));
        kani::cover!(v == Inbound::Allow && matches!(p.transport, Transport::EchoRequest { .. }));
        kani::cover!(v == Inbound::Allow && matches!(p.transport, Transport::Tcp { .. }));
        kani::cover!(v == Inbound::Allow && matches!(p.transport, Transport::Udp { .. }));
    }

    /// I8.2: a peer id the bundle does not name is denied as unknown,
    /// whatever the packet, below `MAX_PEERS` or not.
    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_2_unknown_peer_is_denied() {
        let r = [any_rule()];
        let groups: [&[Rule]; 1] = [&r];
        let peers: [u8; 2] = [kani::any(), kani::any()];
        let rules = ModelRules { peers: &peers, groups: &groups };
        let mut table = FlowTable::new();
        let first = any_packet();
        let _ = table.authorize_inbound(&rules, kani::any(), &first, kani::any());
        let peer: u8 = kani::any();
        kani::assume(usize::from(peer) >= peers.len());
        let v = table.authorize_inbound(&rules, peer, &any_packet(), kani::any());
        assert!(v == Inbound::Deny(Denied::UnknownPeer));
        kani::cover!(usize::from(peer) >= MAX_PEERS);
        kani::cover!(usize::from(peer) < MAX_PEERS);
    }

    /// I8.4: with no matching rule the packet is denied, even when another
    /// peer has just opened a flow on the very same tuple.
    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_4_no_matching_rule_is_denied() {
        let r = [any_rule()];
        let groups: [&[Rule]; 1] = [&r];
        let peers: [u8; 2] = [kani::any(), kani::any()];
        let rules = ModelRules { peers: &peers, groups: &groups };
        let mut table = FlowTable::new();
        let p = any_packet();
        let opener: u8 = kani::any();
        let t0: u64 = kani::any();
        let opened = table.authorize_inbound(&rules, opener, &p, t0);
        let peer: u8 = kani::any();
        let now: u64 = kani::any();
        kani::assume(now >= t0);
        kani::assume(!some_rule_matches(&peers, &groups, peer, &p));
        let v = table.authorize_inbound(&rules, peer, &p, now);
        assert!(v != Inbound::Allow);
        kani::cover!(opened == Inbound::Allow && usize::from(peer) < peers.len());
    }

    const OPS: usize = 3;

    /// I8.3: over a bounded sequence of inbound and outbound packets at a
    /// non-decreasing clock, an outbound `Allow { peer }` answers a tuple
    /// an inbound `Allow` from that same peer opened, with a packet of the
    /// flow (either way) no more than `FLOW_IDLE_NS` before.
    /// An arbitrary table entry over the small value domain.
    fn any_flow() -> Flow {
        let (x, y) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        Flow {
            used: kani::any(),
            tuple: Tuple {
                proto: one_of(6, 17),
                peer_ip: one_of(x, y),
                peer_port: one_of(1, 2),
                lan_ip: one_of(x, y),
                lan_port: one_of(1, 2),
            },
            last_ns: kani::any(),
            fin_in: kani::any(),
            fin_out: kani::any(),
            closing_since: if kani::any() { Some(kani::any()) } else { None },
        }
    }

    fn any_table() -> FlowTable {
        let mut t = FlowTable::new();
        for f in t.flows.iter_mut() {
            *f = any_flow();
        }
        t
    }

    // I8.3, by induction over any operation sequence (D-17): (a) an outbound
    // Allow names a live entry of that peer's share for the reversed tuple,
    // (b) an outbound packet makes no entry alive and rewrites no tuple,
    // (c) an inbound Deny changes nothing, (d) an inbound Allow writes only
    // its own peer's share and only its packet's tuple; so only an inbound
    // Allow from a peer makes an entry of that peer's alive, and I8.1 says
    // that needs a matching rule. A sequence harness ran out of memory at
    // the 40 GB cap; these are one step from an arbitrary table.

    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_3_outbound_allow_answers_a_live_peer_opened_flow() {
        let before = any_table();
        let mut table = before;
        let p = small_packet();
        let now: u64 = kani::any();
        if let Outbound::Allow { peer } = table.authorize_outbound(&p, now) {
            let t = Tuple::outbound(&p);
            let start = usize::from(peer) * QUOTA;
            let live = (start..start + QUOTA).any(|i| before.flows.get(i).is_some_and(|f| Some(f.tuple) == t && f.alive(now)));
            kani::cover!(true);
            assert!(live);
        }
    }

    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_3_outbound_makes_no_entry_alive() {
        let before = any_table();
        let mut table = before;
        let now: u64 = kani::any();
        let _ = table.authorize_outbound(&small_packet(), now);
        let mut changed = 0;
        for (b, a) in before.flows.iter().zip(table.flows.iter()) {
            assert!(b.alive(now) || !a.alive(now));
            assert!(b.tuple == a.tuple);
            if b != a {
                changed += 1;
            }
        }
        assert!(changed <= 1);
    }

    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_3_inbound_allow_writes_only_its_share_and_its_tuple() {
        let r = [any_rule()];
        let groups: [&[Rule]; 1] = [&r];
        let peers: [u8; 2] = [kani::any(), kani::any()];
        let rules = ModelRules { peers: &peers, groups: &groups };
        let before = any_table();
        let mut table = before;
        let now: u64 = kani::any();
        let peer: u8 = one_of(0, 1);
        let p = small_packet();
        if table.authorize_inbound(&rules, peer, &p, now) == Inbound::Allow {
            let start = usize::from(peer) * QUOTA;
            let t = Tuple::inbound(&p);
            for (i, (b, a)) in before.flows.iter().zip(table.flows.iter()).enumerate() {
                if i < start || i >= start + QUOTA {
                    assert!(b == a);
                } else if b != a {
                    assert!(Some(a.tuple) == t);
                }
            }
            // An eviction, not a refresh: the share was full and an entry now
            // holds this tuple where another tuple was.
            let share_full = (start..start + QUOTA).all(|i| before.flows.get(i).is_some_and(|f| f.alive(now)));
            let replaced = (start..start + QUOTA).any(|i| {
                before.flows.get(i).is_some_and(|b| Some(b.tuple) != t) && table.flows.get(i).is_some_and(|a| Some(a.tuple) == t)
            });
            kani::cover!(share_full && replaced, "an own-share eviction");
        }
    }

    #[kani::proof]
    #[kani::unwind(18)]
    fn i8_3_inbound_deny_changes_nothing() {
        let r = [any_rule()];
        let groups: [&[Rule]; 1] = [&r];
        let peers: [u8; 2] = [kani::any(), kani::any()];
        let rules = ModelRules { peers: &peers, groups: &groups };
        let before = any_table();
        let mut table = before;
        let now: u64 = kani::any();
        let peer: u8 = one_of(0, 1);
        if let Inbound::Deny(_) = table.authorize_inbound(&rules, peer, &small_packet(), now) {
            kani::cover!(true);
            assert!(before.flows == table.flows);
        }
    }
}
