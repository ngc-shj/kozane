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
    sources: [Source; 7],
    unknown: UnknownCodes,
}

fn source(name: &'static str, channel: usize, region: NonNull<u8>) -> Source {
    // SAFETY: each ring is mapped into this PD and exactly one producer.
    let ring = unsafe { AuditRing::consumer(region.as_ptr()) };
    Source { name, channel: Channel::new(channel), ring: Consumer::new(ring), reported_corrupt: false }
}

#[protection_domain]
fn init() -> Audit {
    let sources = [
        source("ingress", ch::CH_INGRESS, memory_region_symbol!(audit_ingress: *mut u8)),
        source("eth_out", ch::CH_ETH_OUT, memory_region_symbol!(audit_eth_out: *mut u8)),
        source("eth_in", ch::CH_ETH_IN, memory_region_symbol!(audit_eth_in: *mut u8)),
        source("inner", ch::CH_INNER, memory_region_symbol!(audit_inner: *mut u8)),
        source("hs", ch::CH_HS, memory_region_symbol!(audit_hs: *mut u8)),
        source("data", ch::CH_DATA, memory_region_symbol!(audit_data: *mut u8)),
        source("pq", ch::CH_PQ, memory_region_symbol!(audit_pq: *mut u8)),
    ];
    debug_println!("audit: ready");
    Audit { sources, unknown: UnknownCodes::new() }
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
            Decoded::CostHighWater => {
                debug_println!("audit: src={} RpCostHighWater us={} lost={}", src, r.a, r.b);
                true
            }
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
