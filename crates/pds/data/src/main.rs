//! `data` (plan C12): transport sessions. Decrypts inbound transport
//! messages for `inner`, encrypts inside traffic for `ingress`, and is
//! with `inner` the only reader of tunnelled plaintext (law L3).

#![no_std]
#![no_main]

use audit_event::Event;
use data_core::{AllowedIps, Data, InboundOutcome, InstallOutcome, OutboundOutcome, Payload};
use layout::data as ch;
use msgs::ToIngress;
use pdkit::{Audit, Buf, Rx, Tx};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain};

const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const HS: Channel = Channel::new(ch::CH_HS);
const INNER: Channel = Channel::new(ch::CH_INNER);
const TIMER: Channel = Channel::new(ch::CH_TIMER);
const MAX_PEERS: usize = 8;

/// Allowed IPs from the compiled configuration (law L6).
struct Config;

impl AllowedIps for Config {
    fn contains(&self, peer: usize, ip: [u8; 4]) -> bool {
        config::PEERS.get(peer).is_some_and(|p| p.allowed.iter().any(|a| a.contains(ip)))
    }
}

struct DataPd {
    from_hs: Rx,
    from_ingress: Rx,
    to_ingress: Tx,
    from_inner: Rx,
    to_inner: Tx,
    audit: Audit,
    data: Data<MAX_PEERS>,
    buf: Buf,
    out: Buf,
    msg: Buf,
    scratch: Buf,
}

#[protection_domain]
fn init() -> DataPd {
    if config::PEERS.len() > MAX_PEERS {
        debug_println!("data: more peers configured than MAX_PEERS");
        panic!("data: halted");
    }
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout`; receive data regions are read-only here.
    let (from_hs, from_ingress, to_ingress, from_inner, to_inner, audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(hd_used: *mut u8),
                memory_region_symbol!(hd_free: *mut u8),
                memory_region_symbol!(hd_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(id_used: *mut u8),
                memory_region_symbol!(id_free: *mut u8),
                memory_region_symbol!(id_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(di_used: *mut u8),
                memory_region_symbol!(di_free: *mut u8),
                memory_region_symbol!(di_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(nd_used: *mut u8),
                memory_region_symbol!(nd_free: *mut u8),
                memory_region_symbol!(nd_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(dn_used: *mut u8),
                memory_region_symbol!(dn_free: *mut u8),
                memory_region_symbol!(dn_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_data: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    debug_println!("data: ready");
    DataPd {
        from_hs,
        from_ingress,
        to_ingress,
        from_inner,
        to_inner,
        audit,
        data: Data::new(),
        buf: [0; layout::NET_BUF_SIZE],
        out: [0; layout::NET_BUF_SIZE],
        msg: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
    }
}

fn send_to_ingress(tx: &mut Tx, scratch: &mut Buf, audit: &mut Audit, m: ToIngress<'_>) -> bool {
    let mut enc = [0u8; layout::NET_BUF_SIZE];
    match m.encode(&mut enc) {
        Some(len) => pdkit::send(tx, scratch, enc.get(..len).unwrap_or(&[]), audit),
        None => false,
    }
}

#[derive(Default)]
struct Wake {
    hs: bool,
    ingress: bool,
    inner: bool,
}

impl DataPd {
    fn installs(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_hs, &mut self.buf, &mut self.audit) {
            wake.hs = true;
            let ev = match msgs::Install::decode(self.buf.get(..n).unwrap_or(&[])) {
                Ok(m) => match self.data.install(&m) {
                    InstallOutcome::Installed => Event::SessionInstalled,
                    InstallOutcome::IndexCollision => Event::SessionCollision,
                    InstallOutcome::PeerOutOfRange => Event::HandshakeOther,
                },
                Err(_) => Event::BadDescriptor,
            };
            // Key material: wipe the private copy (the sender scrubs the
            // shared buffer when it comes back).
            self.buf.fill(0);
            self.audit.record(ev);
        }
    }

    fn inbound(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_ingress, &mut self.buf, &mut self.audit) {
            wake.ingress = true;
            let Ok(t) = msgs::Transport::decode(self.buf.get(..n).unwrap_or(&[])) else {
                self.audit.record(Event::BadDescriptor);
                continue;
            };
            let Self { data, out, to_ingress, to_inner, scratch, audit, .. } = self;
            match data.inbound(&Config, t.src, t.msg, cpu::now_ns(), out) {
                InboundOutcome::Authenticated { peer, endpoint, promoted, payload } => {
                    if promoted {
                        audit.record(Event::SessionPromoted);
                    }
                    if let Some(endpoint) = endpoint {
                        wake.ingress |=
                            send_to_ingress(to_ingress, scratch, audit, ToIngress::EndpointUpdate { peer, endpoint });
                    }
                    match payload {
                        Payload::Keepalive => {}
                        Payload::Forward(p) => {
                            let mut copy = [0u8; layout::NET_BUF_SIZE];
                            let len = p.len();
                            if let Some(dst) = copy.get_mut(..len) {
                                dst.copy_from_slice(p);
                                wake.inner |= pdkit::send(to_inner, scratch, copy.get(..len).unwrap_or(&[]), audit);
                            }
                            copy.fill(0);
                        }
                        Payload::SpoofedSource => audit.record(Event::SpoofedSource),
                        Payload::Invalid(r) => audit.record(Event::FrameDropped { reason: r as u16 }),
                    }
                }
                InboundOutcome::Malformed(_) | InboundOutcome::UnknownIndex | InboundOutcome::Rejected(_) => {
                    audit.record(Event::TransportRejected)
                }
            }
            self.out.fill(0);
        }
    }

    fn outbound(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_inner, &mut self.buf, &mut self.audit) {
            wake.inner = true;
            let r = self.data.outbound(&Config, self.buf.get(..n).unwrap_or(&[]), cpu::now_ns(), &mut self.msg);
            self.buf.fill(0);
            match r {
                OutboundOutcome::Sealed { peer, len } => {
                    let mut sealed = [0u8; layout::NET_BUF_SIZE];
                    if let (Some(dst), Some(src)) = (sealed.get_mut(..len), self.msg.get(..len)) {
                        dst.copy_from_slice(src);
                        let m = ToIngress::Outbound { peer, msg: sealed.get(..len).unwrap_or(&[]) };
                        wake.ingress |= send_to_ingress(&mut self.to_ingress, &mut self.scratch, &mut self.audit, m);
                    }
                }
                OutboundOutcome::Dropped(reason) => self.audit.record(Event::FrameDropped { reason: reason as u16 }),
                OutboundOutcome::NoPeer | OutboundOutcome::NoSession | OutboundOutcome::Rejected(_) => {
                    self.audit.record(Event::NoSession)
                }
                OutboundOutcome::TooLarge => self.audit.record(Event::FrameTooLong),
            }
        }
    }
}

impl Handler for DataPd {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        let mut wake = Wake::default();
        if channels.contains(TIMER) {
            for _ in 0..self.data.tick(cpu::now_ns()) {
                self.audit.record(Event::SessionExpired);
            }
        }
        // Installs first, so a session is known before its first packet
        // (plan, Ordering).
        self.installs(&mut wake);
        self.inbound(&mut wake);
        self.outbound(&mut wake);
        if wake.hs {
            HS.notify();
        }
        if wake.ingress {
            INGRESS.notify();
        }
        if wake.inner {
            INNER.notify();
        }
        self.audit.flush();
        Ok(())
    }
}
