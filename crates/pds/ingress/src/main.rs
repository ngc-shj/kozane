//! `ingress` v2 (plan C14): the outside NIC's only consumer. Answers ARP,
//! hands vetted initiations to `hs` and transport messages to `data`, and
//! frames their replies to the peers' endpoints, which it alone tracks.
//! Holds no secret (law L1).

#![no_std]
#![no_main]

use audit_event::Event;
use ingress_core::{Buckets, Config, Endpoint, Mac1, Outcome, emit_udp, respond};
use layout::ingress as ch;
use msgs::ToIngress;
use pdkit::{Audit, Buf, Rx, Tx};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain};
use wg_core::crypto;
use wg_core::noise::LABEL_MAC1;
use wg_core::wire::{INITIATION_LEN, INITIATION_MAC1_OFFSET};

const ETH_OUT: Channel = Channel::new(ch::CH_ETH_OUT);
const HS: Channel = Channel::new(ch::CH_HS);
const DATA: Channel = Channel::new(ch::CH_DATA);
const MAX_PEERS: usize = 61;
const BUCKETS: usize = 64;

const CONFIG: Config = Config {
    mac: config::OUTSIDE_MAC,
    ipv4: config::OUTSIDE_IP,
    router_mac: config::OUTSIDE_ROUTER_MAC,
    port: config::LISTEN_PORT,
};

/// mac1 = MAC(HASH(LABEL_MAC1 ‖ S_pub), msg[..116]).
struct GatewayMac1 {
    key: [u8; 32],
}

impl Mac1 for GatewayMac1 {
    fn verify(&self, msg: &[u8; INITIATION_LEN]) -> bool {
        let (covered, rest) = msg.split_at(INITIATION_MAC1_OFFSET);
        match (crypto::mac(&self.key, &[covered]), rest.get(..16)) {
            (Ok(m), Some(got)) => crypto::ct_eq(&m, got),
            _ => false,
        }
    }
}

struct Ingress {
    from_driver: Rx,
    to_driver: Tx,
    to_hs: Tx,
    from_hs: Rx,
    to_data: Tx,
    from_data: Rx,
    audit: Audit,
    mac1: GatewayMac1,
    buckets: Buckets<BUCKETS>,
    endpoints: [Option<Endpoint>; MAX_PEERS],
    frame: Buf,
    reply: Buf,
    msg: Buf,
    scratch: Buf,
}

#[protection_domain]
fn init() -> Ingress {
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout`; receive data regions are read-only here.
    let (from_driver, to_driver, to_hs, from_hs, to_data, from_data, audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(net_rx_used: *mut u8),
                memory_region_symbol!(net_rx_free: *mut u8),
                memory_region_symbol!(net_rx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(net_tx_used: *mut u8),
                memory_region_symbol!(net_tx_free: *mut u8),
                memory_region_symbol!(net_tx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(ih_used: *mut u8),
                memory_region_symbol!(ih_free: *mut u8),
                memory_region_symbol!(ih_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(hi_used: *mut u8),
                memory_region_symbol!(hi_free: *mut u8),
                memory_region_symbol!(hi_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(id_used: *mut u8),
                memory_region_symbol!(id_free: *mut u8),
                memory_region_symbol!(id_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(di_used: *mut u8),
                memory_region_symbol!(di_free: *mut u8),
                memory_region_symbol!(di_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_ingress: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    let key = crypto::hash(&[LABEL_MAC1, &config::GATEWAY_PUBLIC]).unwrap_or_else(|_| panic!("ingress: mac1 key"));
    debug_println!("ingress: ready");
    Ingress {
        from_driver,
        to_driver,
        to_hs,
        from_hs,
        to_data,
        from_data,
        audit,
        mac1: GatewayMac1 { key },
        buckets: Buckets::default(),
        endpoints: [None; MAX_PEERS],
        frame: [0; layout::NET_BUF_SIZE],
        reply: [0; layout::NET_BUF_SIZE],
        msg: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
    }
}

/// Which peers to notify after a pass.
#[derive(Default)]
struct Wake {
    driver: bool,
    hs: bool,
    data: bool,
}

impl Ingress {
    fn to_peer(&mut self, dst: Endpoint, payload: &[u8], wake: &mut Wake) {
        match emit_udp(&CONFIG, dst, payload, &mut self.reply) {
            Ok(n) => {
                let frame = self.reply.get(..n).unwrap_or(&[]);
                wake.driver |= pdkit::send(&mut self.to_driver, &mut self.scratch, frame, &mut self.audit);
            }
            Err(_) => self.audit.record(Event::TxNoBuffer),
        }
    }

    fn from_outside(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_driver, &mut self.frame, &mut self.audit) {
            wake.driver = true;
            let frame = self.frame.get(..n).unwrap_or(&[]);
            let mut msg_len = None;
            let target = match respond(&CONFIG, &self.mac1, &mut self.buckets, cpu::now_ns(), frame, &mut self.reply) {
                Outcome::ArpReplied(len) => {
                    let reply = self.reply.get(..len).unwrap_or(&[]);
                    if pdkit::send(&mut self.to_driver, &mut self.scratch, reply, &mut self.audit) {
                        self.audit.record(Event::ArpReplied);
                    }
                    continue;
                }
                Outcome::Initiation { src, msg } => {
                    msg_len = msgs::Initiation { src: ep(src), msg }.encode(&mut self.msg);
                    Some(true)
                }
                Outcome::Transport { src, msg } => {
                    msg_len = msgs::Transport { src: ep(src), msg }.encode(&mut self.msg);
                    Some(false)
                }
                Outcome::Dropped(reason) => {
                    self.audit.record(Event::FrameDropped { reason: reason as u16 });
                    None
                }
                Outcome::NotForUs => {
                    self.audit.record(Event::NotForUs);
                    None
                }
                Outcome::NoService => {
                    self.audit.record(Event::NoService);
                    None
                }
                Outcome::Spoofed => {
                    self.audit.record(Event::Spoofed);
                    None
                }
                Outcome::BadMessage => {
                    self.audit.record(Event::WgBadMessage);
                    None
                }
                Outcome::BadMac1 => {
                    self.audit.record(Event::WgBadMac1);
                    None
                }
                Outcome::RateLimited => {
                    self.audit.record(Event::WgRateLimited);
                    None
                }
            };
            let (Some(to_hs), Some(len)) = (target, msg_len) else { continue };
            let msg = self.msg.get(..len).unwrap_or(&[]);
            if to_hs {
                wake.hs |= pdkit::send(&mut self.to_hs, &mut self.scratch, msg, &mut self.audit);
            } else {
                wake.data |= pdkit::send(&mut self.to_data, &mut self.scratch, msg, &mut self.audit);
            }
        }
    }

    fn from_hs(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_hs, &mut self.msg, &mut self.audit) {
            wake.hs = true;
            let Ok(r) = msgs::Response::decode(self.msg.get(..n).unwrap_or(&[])) else {
                self.audit.record(Event::BadDescriptor);
                continue;
            };
            let (dst, payload) = (Endpoint { ip: r.dst.ip, port: r.dst.port }, *r.msg);
            self.to_peer(dst, &payload, wake);
        }
    }

    fn from_data(&mut self, wake: &mut Wake) {
        while let Some(n) = pdkit::recv(&mut self.from_data, &mut self.msg, &mut self.audit) {
            wake.data = true;
            let len = n.min(self.msg.len());
            let mut payload = [0u8; layout::NET_BUF_SIZE];
            let (dst, plen) = match ToIngress::decode(self.msg.get(..len).unwrap_or(&[])) {
                Ok(ToIngress::Outbound { peer, msg }) => {
                    let Some(dst) = self.endpoints.get(usize::from(peer)).copied().flatten() else {
                        self.audit.record(Event::NoSession);
                        continue;
                    };
                    let Some(p) = payload.get_mut(..msg.len()) else { continue };
                    p.copy_from_slice(msg);
                    (dst, msg.len())
                }
                Ok(ToIngress::EndpointUpdate { peer, endpoint }) => {
                    if usize::from(peer) < config::PEERS.len()
                        && let Some(slot) = self.endpoints.get_mut(usize::from(peer))
                    {
                        *slot = Some(Endpoint { ip: endpoint.ip, port: endpoint.port });
                    }
                    continue;
                }
                Err(_) => {
                    self.audit.record(Event::BadDescriptor);
                    continue;
                }
            };
            self.to_peer(dst, payload.get(..plen).unwrap_or(&[]), wake);
        }
    }
}

fn ep(e: Endpoint) -> msgs::Endpoint {
    msgs::Endpoint { ip: e.ip, port: e.port }
}

impl Handler for Ingress {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let mut wake = Wake::default();
        self.from_hs(&mut wake);
        self.from_data(&mut wake);
        self.from_outside(&mut wake);
        if wake.driver {
            ETH_OUT.notify();
        }
        if wake.hs {
            HS.notify();
        }
        if wake.data {
            DATA.notify();
        }
        self.audit.flush();
        Ok(())
    }
}
