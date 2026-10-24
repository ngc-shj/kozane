//! `inner` (plan C13): the inside NIC's only consumer. Forwards IPv4 from
//! static neighbors to `data` for the tunnel and frames decrypted packets
//! for static neighbors. Sees tunnelled plaintext (law L3), no secrets.
//! Also the HTTPS backend link (M6 plan C4): the backend's segments to
//! `tls` go to `ntl`, and `tls`'s segments from `tln` leave only towards the
//! backend; both are proxied plaintext, which this PD sees by design.

#![no_std]
#![no_main]

use audit_event::Event;
use inner_core::{Config, FromLan, FromTls, TLS_REFUSED, ToLan, from_lan, from_tls, to_lan};
use layout::inner as ch;
use pdkit::{Audit, Buf, Rx, Tx};
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
    neighbors: [([u8; 4], [u8; 6]); MAX_NEIGHBORS],
    neighbor_count: usize,
    buf: Buf,
    reply: Buf,
    scratch: Buf,
}

#[protection_domain]
fn init() -> Inner {
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
    let mut neighbors = [([0u8; 4], [0u8; 6]); MAX_NEIGHBORS];
    for (dst, n) in neighbors.iter_mut().zip(config::NEIGHBORS) {
        *dst = (n.ip, n.mac);
    }
    audit.ready();
    Inner {
        from_driver,
        to_driver,
        to_data,
        from_data,
        from_tls,
        to_tls,
        audit,
        neighbors,
        neighbor_count: config::NEIGHBORS.len(),
        buf: [0; layout::NET_BUF_SIZE],
        reply: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
    }
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
                    wake.data |= pdkit::send(&mut self.to_data, &mut self.scratch, p, &mut self.audit);
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
            let cfg = lan_config(self.neighbors.get(..self.neighbor_count).unwrap_or(&[]));
            let frame = &mut self.reply;
            match to_lan(&cfg, self.buf.get(..n).unwrap_or(&[]), frame) {
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
