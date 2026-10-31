//! `inner` (plan C13): the inside NIC's only consumer. Forwards IPv4 from
//! static neighbors to `data` for the tunnel and frames decrypted packets
//! for static neighbors. Sees tunnelled plaintext (law L3), no secrets.
//! Also the HTTPS backend link (M6 plan C4): the backend's segments to
//! `tls` go to `ntl`, and `tls`'s segments from `tln` leave only towards the
//! backend; both are proxied plaintext, which this PD sees by design.
//! It reads nothing before `policy` has verified a bundle (M8 plan C6), and
//! the bundle's groups decide what each peer reaches on the LAN and what
//! may answer it (M8 plan C8, `inner_core::flow`).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;

use audit_event::Event;
use inner_core::flow::{Denied, FlowTable, Inbound, Outbound, Rules};
use inner_core::{Config, FromLan, FromTls, TLS_REFUSED, ToLan, from_lan, from_tls, to_lan};
use layout::inner as ch;
use msgs::TunnelPacket;
use pdkit::{Audit, Buf, Rx, Tx};
use policy_wire::{Bundle, Rule};
use ring::pass::drain;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, memory_region_symbol, protection_domain};

const ETH_IN: Channel = Channel::new(ch::CH_ETH_IN);
const DATA: Channel = Channel::new(ch::CH_DATA);
const TLS: Channel = Channel::new(ch::CH_TLS);
const MAX_NEIGHBORS: usize = config::MAX_NEIGHBORS;
const _: () = assert!(config::NEIGHBORS.len() <= MAX_NEIGHBORS);
const _: () = assert!(inner_core::NET_BUFFERS == layout::NET_BUFFERS, "inner-core NET_BUFFERS differs from layout");
/// Segments taken from `tln` per notification (M6 code review S1): `tls`
/// runs at this PD's priority and can refill the ring while it is drained,
/// so the drain is bounded rather than run until empty. What is left waits
/// for the next notification; `tls` retransmits what the tier refused.
const TLS_DRAIN: usize = layout::NET_BUFFERS;

// `audit` names the drops from its own table, by peer block; this PD sees
// both sides.
const _: () = assert!(reasons_match());
const _: () = assert!(audit_event::INNER_PEERS as usize == limits::MAX_PEERS, "InnerDenied's peer blocks");

// Both run only at compile time, where an out-of-bounds index or an
// overflow is a build error.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn reasons_match() -> bool {
    use audit_event::{INNER_REASON_NAMES, INNER_REASONS};
    let all = Denied::ALL;
    if all.len() != INNER_REASON_NAMES.len() || all.len() + 1 != INNER_REASONS as usize {
        return false;
    }
    let mut i = 0;
    while i < all.len() {
        if all[i].code() as usize != i || !str_eq(all[i].name(), INNER_REASON_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// The flow table (M8 plan C8): about 20 KiB, so a static rather than part
/// of the handler state, which lives on the 64 KiB stack.
struct Flows(UnsafeCell<FlowTable>);

// SAFETY: a PD runs one thread, and `start` hands the table out once.
unsafe impl Sync for Flows {}

static FLOWS: Flows = Flows(UnsafeCell::new(FlowTable::new()));

/// The verified bundle's groups and rules (M8 plan C1, C8).
struct Groups(Bundle<'static>);

impl Rules for Groups {
    fn groups(&self, peer: u8) -> Option<u8> {
        self.0.peer(peer).map(|p| p.groups())
    }

    fn any_rule_in(&self, group: u8, mut f: impl FnMut(&Rule) -> bool) -> bool {
        self.0.group(group).is_some_and(|g| g.rules().any(|r| f(&r)))
    }
}

struct Inner {
    from_driver: Rx,
    to_driver: Tx,
    to_data: Tx,
    from_data: Rx,
    /// The HTTPS backend links (M6 plan C1, C4): `tls`'s segments to the
    /// backend and the backend's to `tls`.
    from_tls: Rx,
    to_tls: Tx,
    audit: Audit,
    groups: Groups,
    flows: &'static mut FlowTable,
    neighbors: [([u8; 4], [u8; 6]); MAX_NEIGHBORS],
    neighbor_count: usize,
    buf: Buf,
    reply: Buf,
    scratch: Buf,
}

/// `Halted` reasons (the record's `a`), stable per M5 plan C6.
mod halt {
    /// `policy` verified no bundle, or its slot did not open (M8 plan C6).
    pub const POLICY_UNAVAILABLE: u32 = layout::policy::HALT_UNAVAILABLE;
}

/// `Await` on `policy`, then the slot it verified (M8 plan C6), whose groups
/// authorize the tunnel's traffic (C8).
fn barrier() -> Result<Bundle<'static>, policy_wire::Reject> {
    let token = policy_client::await_verified(Channel::new(ch::CH_POLICY))?;
    policy_client::open(&token, &config::node_config())
}

// The closure names this init in run_init's symbol (ct-shape's stage check).
#[allow(clippy::redundant_closure)]
#[protection_domain]
fn init() -> pdkit::Stage<Inner> {
    boot_stage::run_init(|init| start(init))
}

/// Init proper. Its one refusal, the barrier's, is a boot stop (M7 plan
/// C9): `inner` is a leaf PD.
fn start(init: &boot_stage::Init) -> pdkit::Stage<Inner> {
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout`; receive data regions are read-only here.
    let (from_driver, to_driver, to_data, from_data, from_tls, to_tls, mut audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(inner_rx_used: *mut u8),
                memory_region_symbol!(inner_rx_free: *mut u8),
                memory_region_symbol!(inner_rx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(inner_tx_used: *mut u8),
                memory_region_symbol!(inner_tx_free: *mut u8),
                memory_region_symbol!(inner_tx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(nd_used: *mut u8),
                memory_region_symbol!(nd_free: *mut u8),
                memory_region_symbol!(nd_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(dn_used: *mut u8),
                memory_region_symbol!(dn_free: *mut u8),
                memory_region_symbol!(dn_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(tln_used: *mut u8),
                memory_region_symbol!(tln_free: *mut u8),
                memory_region_symbol!(tln_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(ntl_used: *mut u8),
                memory_region_symbol!(ntl_free: *mut u8),
                memory_region_symbol!(ntl_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_inner: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    // The barrier (M8 plan C6): no LAN frame or backend segment is read
    // before `policy` has verified a bundle; until then they wait in the
    // rings.
    let Ok(bundle) = barrier() else {
        return pdkit::Stage::Dormant(audit.boot_stop(init, halt::POLICY_UNAVAILABLE));
    };
    // SAFETY: `start` runs once, and this is the only reference to the
    // table ever made (see `Flows`).
    let flows = unsafe { &mut *FLOWS.0.get() };
    let mut neighbors = [([0u8; 4], [0u8; 6]); MAX_NEIGHBORS];
    for (dst, n) in neighbors.iter_mut().zip(config::NEIGHBORS) {
        *dst = (n.ip, n.mac);
    }
    audit.ready();
    pdkit::Stage::Run(Inner {
        from_driver,
        to_driver,
        to_data,
        from_data,
        from_tls,
        to_tls,
        audit,
        groups: Groups(bundle),
        flows,
        neighbors,
        neighbor_count: config::NEIGHBORS.len(),
        buf: [0; layout::NET_BUF_SIZE],
        reply: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
    })
}

#[derive(Default)]
struct Wake {
    driver: bool,
    data: bool,
    tls: bool,
}

fn lan_config(neighbors: &[([u8; 4], [u8; 6])]) -> Config<'_> {
    Config {
        mac: config::INSIDE_MAC,
        ipv4: config::INSIDE_IP,
        neighbors,
        backend: config::BACKEND,
        tls_ports: config::TLS_PORTS,
    }
}

impl Inner {

    fn drain_lan(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_driver, &mut self.buf, &mut self.audit) {
            wake.driver = true;
            let cfg = lan_config(self.neighbors.get(..self.neighbor_count).unwrap_or(&[]));
            let reply = &mut self.reply;
            let outcome = from_lan(&cfg, self.buf.get(..n).unwrap_or(&[]), reply);
            match outcome {
                FromLan::ArpReplied(len) => {
                    let r = reply.get(..len).unwrap_or(&[]);
                    if pdkit::send(&mut self.to_driver, &mut self.scratch, r, &mut self.audit) {
                        self.audit.record(Event::ArpReplied);
                    }
                }
                FromLan::Forward(len) => {
                    let p = reply.get(..len).unwrap_or(&[]);
                    // Only as the reverse of a flow a peer opened (M8 plan
                    // C8, D9); `data` routes it by allowed IPs.
                    match self.flows.outbound(p, cpu::now_ns()) {
                        Outbound::Allow { .. } => {
                            wake.data |= pdkit::send(&mut self.to_data, &mut self.scratch, p, &mut self.audit);
                        }
                        Outbound::Deny { reason, dst } => {
                            // Named for the peer it was headed for; an address
                            // no peer owns counts as an unknown peer.
                            let peer = self.groups.0.owner_of(dst).map_or(audit_event::INNER_PEERS, u16::from);
                            self.audit.record(Event::InnerDenied { peer, reason: reason.code() });
                        }
                        Outbound::Malformed(reason) => self.audit.record(Event::FrameDropped { reason: reason as u16 }),
                    }
                }
                FromLan::Tls(len) => {
                    let p = reply.get(..len).unwrap_or(&[]);
                    wake.tls |= pdkit::send(&mut self.to_tls, &mut self.scratch, p, &mut self.audit);
                }
                FromLan::Dropped(reason) => self.audit.record(Event::FrameDropped { reason: reason as u16 }),
                FromLan::NotForUs => self.audit.record(Event::NotForUs),
                FromLan::NoService => self.audit.record(Event::NoService),
                FromLan::Spoofed => self.audit.record(Event::Spoofed),
            }
        }
    }

    fn drain_tunnel(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_data, &mut self.buf, &mut self.audit) {
            wake.data = true;
            let Ok(m) = TunnelPacket::decode(self.buf.get(..n).unwrap_or(&[])) else {
                self.audit.record(Event::BadDescriptor);
                continue;
            };
            // The peer's groups decide (M8 plan C8): default deny.
            match self.flows.inbound(&self.groups, m.peer, m.packet, cpu::now_ns()) {
                Inbound::Allow => {}
                Inbound::Deny(reason) => {
                    self.audit.record(Event::InnerDenied { peer: u16::from(m.peer), reason: reason.code() });
                    continue;
                }
                Inbound::Malformed(reason) => {
                    self.audit.record(Event::FrameDropped { reason: reason as u16 });
                    continue;
                }
            }
            let cfg = lan_config(self.neighbors.get(..self.neighbor_count).unwrap_or(&[]));
            let frame = &mut self.reply;
            match to_lan(&cfg, m.packet, frame) {
                ToLan::Emitted(len) => {
                    let f = frame.get(..len).unwrap_or(&[]);
                    wake.driver |= pdkit::send(&mut self.to_driver, &mut self.scratch, f, &mut self.audit);
                }
                ToLan::Dropped(reason) => self.audit.record(Event::FrameDropped { reason: reason as u16 }),
                ToLan::UnknownNeighbor => self.audit.record(Event::UnknownNeighbor),
                ToLan::NoBuffer => self.audit.record(Event::TxNoBuffer),
            }
        }
    }

    /// `tls`'s segments, at most `TLS_DRAIN` of them.
    fn drain_tls(&mut self, wake: &mut Wake) {
        drain(TLS_DRAIN, || self.tls_one(wake));
    }

    /// One of `tls`'s segments, which leaves only through `from_tls`, the
    /// gate for what `tls` can reach inside; `false` when `tln` is empty.
    fn tls_one(&mut self, wake: &mut Wake) -> bool {
        let Some(n) = pdkit::recv(&mut self.from_tls, &mut self.buf, &mut self.audit) else { return false };
        wake.tls = true;
        let tx_free = match self.to_driver.free() {
            Ok(n) => n,
            Err(e) => {
                self.audit.link_error(e);
                0
            }
        };
        let cfg = lan_config(self.neighbors.get(..self.neighbor_count).unwrap_or(&[]));
        let frame = &mut self.reply;
        match from_tls(&cfg, self.buf.get(..n).unwrap_or(&[]), tx_free, frame) {
            FromTls::Emitted(len) => {
                let f = frame.get(..len).unwrap_or(&[]);
                wake.driver |= pdkit::send(&mut self.to_driver, &mut self.scratch, f, &mut self.audit);
            }
            FromTls::Dropped(reason) => self.audit.record(Event::FrameDropped { reason: reason as u16 }),
            FromTls::Refused => self.audit.record(Event::FrameDropped { reason: TLS_REFUSED as u16 }),
            FromTls::UnknownNeighbor => self.audit.record(Event::UnknownNeighbor),
            FromTls::NoBuffer | FromTls::TxReserve => self.audit.record(Event::TxNoBuffer),
        }
        true
    }
}

impl Handler for Inner {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let mut wake = Wake::default();
        self.drain_tunnel(&mut wake);
        self.drain_tls(&mut wake);
        self.drain_lan(&mut wake);
        if wake.driver {
            ETH_IN.notify();
        }
        if wake.data {
            DATA.notify();
        }
        if wake.tls {
            TLS.notify();
        }
        self.audit.flush();
        Ok(())
    }
}
