//! `audit`: drains event rings from untrusted producers (threat A3) and
//! prints them. Bounded work per notification; unknown codes share one
//! counter so a hostile producer cannot flood the log by cycling codes.

#![no_std]
#![no_main]

use core::ptr::NonNull;

use audit_event::{Decoded, Record, UnknownCodes, decode};
use layout::{AUDIT_RING_SLOTS, audit as ch};
use ring::shmem::ShmRing;
use ring::{Consumer, RingError};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain};
use wire::DropReason;

type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;

struct Source {
    name: &'static str,
    channel: Channel,
    ring: Consumer<AuditRing, Record, AUDIT_RING_SLOTS>,
    reported_corrupt: bool,
}

struct Audit {
    sources: [Source; 2],
    unknown: UnknownCodes,
}

fn region_ptr(p: NonNull<u8>) -> *mut u8 {
    p.as_ptr()
}

#[protection_domain]
fn init() -> Audit {
    // SAFETY: each ring is mapped into this PD and exactly one producer.
    let (ingress, eth_out) = unsafe {
        (
            AuditRing::consumer(region_ptr(memory_region_symbol!(audit_ingress: *mut u8))),
            AuditRing::consumer(region_ptr(memory_region_symbol!(audit_eth_out: *mut u8))),
        )
    };
    debug_println!("audit: ready");
    Audit {
        sources: [
            Source {
                name: "ingress",
                channel: Channel::new(ch::CH_INGRESS),
                ring: Consumer::new(ingress),
                reported_corrupt: false,
            },
            Source {
                name: "eth_out",
                channel: Channel::new(ch::CH_ETH_OUT),
                ring: Consumer::new(eth_out),
                reported_corrupt: false,
            },
        ],
        unknown: UnknownCodes::new(),
    }
}

fn drop_reason(r: u16) -> Option<DropReason> {
    DropReason::ALL.iter().copied().find(|d| *d as u16 == r)
}

impl Audit {
    fn print(&mut self, src: &'static str, r: Record) {
        let named = match decode(r.code) {
            Decoded::Fixed(ev) => {
                debug_println!("audit: src={} {} total={} lost={}", src, ev.name(), r.a, r.b);
                true
            }
            Decoded::FrameDropped(reason) => match drop_reason(reason) {
                Some(d) => {
                    debug_println!("audit: src={} FrameDropped({:?}) total={} lost={}", src, d, r.a, r.b);
                    true
                }
                None => false,
            },
            Decoded::Unknown => false,
        };
        if !named && let Some(total) = self.unknown.record() {
            debug_println!("audit: src={} unknown code={:#06x} unknown_total={}", src, r.code, total);
        }
    }
}

impl Handler for Audit {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        for i in 0..self.sources.len() {
            let Some(src) = self.sources.get(i) else { continue };
            if !channels.contains(src.channel) {
                continue;
            }
            let name = src.name;
            // Drain at most one ring's worth: bounded work per notification,
            // yet everything queued when we woke is printed, so a producer
            // that goes quiet never leaves records stranded.
            for _ in 0..AUDIT_RING_SLOTS {
                let Some(src) = self.sources.get_mut(i) else { break };
                match src.ring.pop() {
                    Ok(Some(r)) => self.print(name, r),
                    Ok(None) => break,
                    Err(RingError::Corrupt | RingError::Full) => {
                        if !core::mem::replace(&mut src.reported_corrupt, true) {
                            debug_println!("audit: src={} ring corrupt, ignoring producer", name);
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
