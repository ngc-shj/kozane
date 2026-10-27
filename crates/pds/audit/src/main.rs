//! `audit`: drains event rings from untrusted producers (threat A3) and
//! prints them. Bounded work per notification; unknown codes share one
//! counter so a hostile producer cannot flood the log by cycling codes.
//!
//! The only console (M5 plan C6): it writes its lines straight to the PL011
//! transmit FIFO, polling the FIFO-full flag before each byte. It has no
//! interrupt and no receive path; no PD prints through the kernel, and a
//! release kernel has no debug printing at all.

#![no_std]
#![no_main]

use core::fmt::{self, Write};
use core::ptr::NonNull;

use audit_event::{
    Decoded, HTTP_REFUSED_NAMES, Record, TCP_LIMIT_NAMES, TLS_CLOSED_NAMES, TLS_REFUSED_NAMES, TLS_TIMEOUT_NAMES,
    UnknownCodes, decode,
};
use layout::{AUDIT_RING_SLOTS, audit as ch};
use ring::shmem::ShmRing;
use ring::{Consumer, RingError};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, memory_region_symbol, protection_domain, var};
use wire::DropReason;

type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;

// PL011 registers (ARM DDI 0183): data and flags. Nothing else is touched.
const UARTDR: usize = 0x000;
const UARTFR: usize = 0x018;
const FR_TXFF: u32 = 1 << 5;

/// Marks an image built with `fault-inject` (M7 plan C8): tools/release.py
/// refuses one that holds it.
#[cfg(feature = "fault-inject")]
#[used]
static FAULT_INJECT_VARIANT: [u8; 27] = *b"KOZANE-FAULT-INJECT-VARIANT";

/// The PL011's transmit side.
struct Uart {
    base: NonNull<u32>,
}

impl Uart {
    fn put(&self, byte: u8) {
        // SAFETY: `base` is this PD's uncached mapping of the PL011 page (law
        // L5: mapped into `audit` alone) and both offsets are registers in it.
        unsafe {
            while self.base.byte_add(UARTFR).read_volatile() & FR_TXFF != 0 {
                core::hint::spin_loop();
            }
            self.base.byte_add(UARTDR).write_volatile(u32::from(byte));
        }
    }
}

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.put(b'\r');
            }
            self.put(b);
        }
        Ok(())
    }
}

/// One line to the console; formatting into the UART cannot fail.
macro_rules! println {
    ($uart:expr, $($arg:tt)*) => {
        let _ = writeln!($uart, $($arg)*);
    };
}

struct Source {
    name: &'static str,
    channel: Channel,
    ring: Consumer<AuditRing, Record, AUDIT_RING_SLOTS>,
    reported_corrupt: bool,
}

struct Audit {
    sources: [Source; 8],
    unknown: UnknownCodes,
    uart: Uart,
    /// The supervisor's record page (M7 plan C8), read-only here, and the
    /// last record printed.
    record: NonNull<[u64; supervisor_core::RECORD_WORDS]>,
    last_seq: u64,
}

fn source(name: &'static str, channel: usize, region: NonNull<u8>) -> Source {
    // SAFETY: each ring is mapped into this PD and exactly one producer.
    let ring = unsafe { AuditRing::consumer(region.as_ptr()) };
    Source { name, channel: Channel::new(channel), ring: Consumer::new(ring), reported_corrupt: false }
}

#[protection_domain]
fn init() -> Audit {
    boot_stage::run_init(|_| start())
}

fn start() -> Audit {
    let vaddr = *var!(uart_mmio_vaddr: usize = 0);
    // Without a console nothing could be reported; stop (fail-closed).
    let base = NonNull::new(vaddr as *mut u32).unwrap_or_else(|| panic!("audit: no uart mapping"));
    let mut uart = Uart { base };
    let sources = [
        source("ingress", ch::CH_INGRESS, memory_region_symbol!(audit_ingress: *mut u8)),
        source("eth_out", ch::CH_ETH_OUT, memory_region_symbol!(audit_eth_out: *mut u8)),
        source("eth_in", ch::CH_ETH_IN, memory_region_symbol!(audit_eth_in: *mut u8)),
        source("inner", ch::CH_INNER, memory_region_symbol!(audit_inner: *mut u8)),
        source("hs", ch::CH_HS, memory_region_symbol!(audit_hs: *mut u8)),
        source("data", ch::CH_DATA, memory_region_symbol!(audit_data: *mut u8)),
        source("pq", ch::CH_PQ, memory_region_symbol!(audit_pq: *mut u8)),
        source("tls", ch::CH_TLS, memory_region_symbol!(audit_tls: *mut u8)),
    ];
    println!(uart, "audit: ready");
    let record = memory_region_symbol!(supervisor_record: *mut [u64; supervisor_core::RECORD_WORDS]);
    Audit { sources, unknown: UnknownCodes::new(), uart, record, last_seq: 0 }
}

fn drop_reason(r: u16) -> Option<DropReason> {
    DropReason::ALL.iter().copied().find(|d| *d as u16 == r)
}

/// A coalesced kind whose value has a name in `names`: its line, or false
/// (an unnamed value counts as an unknown code).
fn named(uart: &mut Uart, src: &str, kind: &str, names: &[&str], v: u16, r: Record) -> bool {
    match names.get(usize::from(v)) {
        Some(name) => {
            println!(uart, "audit: src={} {}({}) total={} lost={}", src, kind, name, r.a, r.b);
            true
        }
        None => false,
    }
}

impl Audit {
    fn print(&mut self, src: &'static str, r: Record) {
        let uart = &mut self.uart;
        let named = match decode(r.code) {
            // The readiness line keeps the form the PDs printed themselves
            // before C6, which the integration waits read.
            Decoded::Fixed(audit_event::Event::Ready) => {
                if r.b == 0 {
                    println!(uart, "{}: ready", src);
                } else {
                    println!(uart, "{}: ready lost={}", src, r.b);
                }
                true
            }
            Decoded::Fixed(ev) => {
                println!(uart, "audit: src={} {} total={} lost={}", src, ev.name(), r.a, r.b);
                // M7 plan C8's selftest variant: audit itself faults, once
                // the line that triggers it is out.
                #[cfg(feature = "fault-inject")]
                if src == "ingress" && ev == audit_event::Event::WgBadMessage {
                    panic!("fault-inject: audit");
                }
                true
            }
            Decoded::FrameDropped(reason) => match drop_reason(reason) {
                Some(d) => {
                    println!(uart, "audit: src={} FrameDropped({:?}) total={} lost={}", src, d, r.a, r.b);
                    true
                }
                None => false,
            },
            Decoded::TcpLimited(kind) => named(uart, src, "TcpLimited", &TCP_LIMIT_NAMES, kind, r),
            Decoded::TlsRefused(v) => named(uart, src, "TlsRefused", &TLS_REFUSED_NAMES, v, r),
            Decoded::TlsClosed(v) => named(uart, src, "TlsClosed", &TLS_CLOSED_NAMES, v, r),
            Decoded::HttpRefused(v) => named(uart, src, "HttpRefused", &HTTP_REFUSED_NAMES, v, r),
            Decoded::TlsTimeout(v) => named(uart, src, "TlsTimeout", &TLS_TIMEOUT_NAMES, v, r),
            Decoded::TlsSignHighWater => {
                println!(uart, "audit: src={} TlsSignHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::CostHighWater => {
                println!(uart, "audit: src={} RpCostHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::StackHighWater => {
                println!(uart, "audit: src={} StackHighWater bytes={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyStackHighWater => {
                println!(uart, "audit: src={} KeyStackHighWater bytes={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyWaitHighWater => {
                println!(uart, "audit: src={} KeyWaitHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::Halted => {
                println!(uart, "audit: src={} Halted reason={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyUnavailable => {
                println!(uart, "audit: src={} KeyUnavailable code={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::Unknown => false,
        };
        if !named && let Some(total) = self.unknown.record() {
            println!(uart, "audit: src={} unknown code={:#06x} unknown_total={}", src, r.code, total);
        }
    }
}

impl Handler for Audit {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(Channel::new(ch::CH_SUPERVISOR)) {
            // SAFETY: the record page is mapped r into this PD and rw into
            // the supervisor alone (laws), page-aligned, for the life of
            // the system. Read once: the supervisor resets right after.
            let r = supervisor_core::Record::decode(unsafe { self.record.as_ptr().read_volatile() });
            if r.seq != 0 && r.seq != self.last_seq {
                self.last_seq = r.seq;
                match r.child_name() {
                    Some(pd) => {
                        println!(self.uart, "supervisor: fault pd={} label={} lost={}", pd, r.label, r.lost);
                    }
                    None => {
                        println!(self.uart, "supervisor: fault child={} label={} lost={}", r.child, r.label, r.lost);
                    }
                }
            }
        }
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
                            println!(self.uart, "audit: src={} ring corrupt, ignoring producer", name);
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
