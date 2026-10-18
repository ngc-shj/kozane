//! `ingress` v1: every frame is copied in from the driver's region and
//! decided by `ingress_core::respond`. Holds no secret (law L1).

#![no_std]
#![no_main]

use core::ptr::NonNull;

use audit_event::{Coalescer, Event, Record};
use ingress_core::{Config, Outcome, respond};
use layout::{AUDIT_RING_SLOTS, NET_BUF_SIZE, NET_BUFFERS, NET_REGION_SIZE, NET_RING_SLOTS, ingress as ch};
use ring::Producer;
use ring::link::{LinkError, Receiver, Sender};
use ring::shmem::{Region, ShmRing};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain};

const ETH_OUT: Channel = Channel::new(ch::CH_ETH_OUT);
const AUDIT: Channel = Channel::new(ch::CH_AUDIT);

/// QEMU's default MAC for the first NIC and the user-net guest address.
const CONFIG: Config = Config { mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], ipv4: [10, 0, 2, 15], echo_port: 7 };

type NetRing = ShmRing<ring::Desc, NET_RING_SLOTS>;
type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;

struct Ingress {
    from_driver: Receiver<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    to_driver: Sender<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    audit: Producer<AuditRing, Record, AUDIT_RING_SLOTS>,
    coalescer: Coalescer,
    frame: [u8; NET_BUF_SIZE],
    reply: [u8; NET_BUF_SIZE],
    scratch: [u8; NET_BUF_SIZE],
    audit_pending: bool,
}

fn region_ptr(p: NonNull<u8>) -> *mut u8 {
    p.as_ptr()
}

#[protection_domain]
fn init() -> Ingress {
    // SAFETY: the .system maps each region into this PD and `eth_out` only,
    // sized as in `layout`; the rx data region is mapped read-only here.
    let (from_driver, to_driver, audit) = unsafe {
        (
            Receiver::new(
                NetRing::consumer(region_ptr(memory_region_symbol!(net_rx_used: *mut u8))),
                NetRing::producer(region_ptr(memory_region_symbol!(net_rx_free: *mut u8))),
                Region::new(region_ptr(memory_region_symbol!(net_rx_data: *mut u8)), NET_REGION_SIZE),
            ),
            Sender::new(
                NetRing::producer(region_ptr(memory_region_symbol!(net_tx_used: *mut u8))),
                NetRing::consumer(region_ptr(memory_region_symbol!(net_tx_free: *mut u8))),
                Region::new(region_ptr(memory_region_symbol!(net_tx_data: *mut u8)), NET_REGION_SIZE),
            ),
            Producer::new(AuditRing::producer(region_ptr(memory_region_symbol!(audit_ingress: *mut u8)))),
        )
    };
    debug_println!("ingress: ready");
    Ingress {
        from_driver,
        to_driver,
        audit,
        coalescer: Coalescer::new(),
        frame: [0; NET_BUF_SIZE],
        reply: [0; NET_BUF_SIZE],
        scratch: [0; NET_BUF_SIZE],
        audit_pending: false,
    }
}

impl Ingress {
    fn audit(&mut self, ev: Event) {
        let audit = &mut self.audit;
        // Notify on every offer, including a full ring (see Coalescer::record).
        self.audit_pending |= self.coalescer.record(ev, |r| audit.push(r).is_ok());
    }

    fn audit_link_error(&mut self, e: LinkError) {
        self.audit(match e {
            LinkError::Corrupt => Event::RingCorrupt,
            LinkError::BadDesc(_) => Event::BadDescriptor,
            LinkError::NoBuffer => Event::TxNoBuffer,
        });
    }

    fn send_reply(&mut self, n: usize) -> bool {
        if let Err(e) = self.to_driver.reclaim() {
            self.audit_link_error(e);
        }
        let reply = &self.reply;
        let r = self.to_driver.send_with(&mut self.scratch, |s| {
            s.get_mut(..n)?.copy_from_slice(reply.get(..n)?);
            Some(n)
        });
        match r {
            Ok(sent) => sent,
            Err(e) => {
                self.audit_link_error(e);
                false
            }
        }
    }

    /// Handles every queued frame. Returns (sent a reply, returned a buffer).
    fn poll(&mut self) -> (bool, bool) {
        let (mut sent, mut returned) = (false, false);
        loop {
            let n = match self.from_driver.recv_into(&mut self.frame) {
                Ok(Some(n)) => n,
                Ok(None) => break,
                Err(LinkError::Corrupt) => {
                    self.audit(Event::RingCorrupt);
                    break;
                }
                Err(e) => {
                    self.audit_link_error(e);
                    continue;
                }
            };
            returned = true;
            let frame = self.frame.get(..n).unwrap_or(&[]);
            match respond(&CONFIG, frame, &mut self.reply) {
                Outcome::ArpReplied(len) => {
                    if self.send_reply(len) {
                        sent = true;
                        self.audit(Event::ArpReplied);
                    }
                }
                Outcome::UdpEchoed(len) => {
                    if self.send_reply(len) {
                        sent = true;
                        self.audit(Event::UdpEchoed);
                    }
                }
                Outcome::Dropped(reason) => self.audit(Event::FrameDropped { reason: reason as u16 }),
                Outcome::NotForUs => self.audit(Event::NotForUs),
                Outcome::NoService => self.audit(Event::NoService),
            }
        }
        (sent, returned)
    }
}

impl Handler for Ingress {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        let (sent, returned) = self.poll();
        if sent || returned {
            ETH_OUT.notify();
        }
        if core::mem::take(&mut self.audit_pending) {
            AUDIT.notify();
        }
        Ok(())
    }
}
