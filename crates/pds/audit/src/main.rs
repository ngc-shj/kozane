//! `audit`: drains event rings from untrusted producers (threat A3) and
//! prints them. Bounded work per notification; unknown codes share one
//! counter so a hostile producer cannot flood the log by cycling codes.
//!
//! The only console (M5 plan C6): it writes its lines straight to the PL011
//! transmit FIFO, polling the FIFO-full flag before each byte. It has no
//! interrupt and no receive path; no PD prints through the kernel, and a
//! release kernel has no debug printing at all.
//!
//! The export (M8 plan C10): every line ends in ` seq=<n>` and extends the
//! hash chain (`audit_core::Chain`); `audit_core::Checkpoints` decides when
//! a checkpoint line is due and when `auditkey` may be called. Its one PPC
//! is `sign`, made only for that machine's `Action::Call`, which exists only
//! after `auditkey`'s notification (`audit_core::ready_input`, F32).
//!
//! The heartbeat (M9 plan C3): `timer` notifies it once a second, and every
//! `layout::audit::HEARTBEAT_S` ticks it prints `audit: Heartbeat ticks=<n>`,
//! chained like every other line.

#![no_std]
#![no_main]

use core::fmt::{self, Write};
use core::ptr::NonNull;

use audit_core::{Action, Chain, Checkpoints, Heartbeat, Line, Outcome};
use audit_event::{
    Decoded, HEARTBEAT, HTTP_REFUSED_NAMES, INNER_REASON_NAMES, POLICY_REASON_NAMES, POLICY_SLOT_NAMES,
    POLICY_STATE_REFUSED, Record, TCP_LIMIT_NAMES, TLS_CLOSED_NAMES, TLS_REFUSED_NAMES, TLS_TIMEOUT_NAMES, UnknownCodes,
    decode, log,
};
use auditkey_core::{CHAIN_LEN, Reply};
use layout::auditkey::{SIGN, SIGN_REPLY_WORDS, SIGN_REQ_WORDS};
use layout::{AUDIT_RING_SLOTS, audit as ch};
use ring::shmem::ShmRing;
use ring::{Consumer, RingError};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, var, with_msg_regs,
    with_msg_regs_mut,
};
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

/// One line on its way out: each byte to the UART and into the line's
/// hash. No line holds a CR or LF (every field is a number or a name from a
/// closed table); `Console::emit` ends it.
struct LineWriter<'a> {
    uart: &'a Uart,
    line: Line,
}

impl Write for LineWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.uart.put(b);
        }
        self.line.update(s.as_bytes());
        Ok(())
    }
}

/// Bytes as lowercase hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// An IPv4 address carried big-endian in a record's `a`, as `a.b.c.d`.
struct Ipv4(u32);

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0.to_be_bytes();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// The console: the UART, the chain over every line printed, the running
/// total of every source's `lost`, and the checkpoint schedule.
struct Console {
    uart: Uart,
    chain: Chain,
    lost: u64,
    checkpoints: Checkpoints,
}

/// `audit`'s one PPC (M8 plan C10, F32): `SIGN` to `auditkey` with the
/// words of `audit_core`'s `Action::Call`, its only caller. Returns the
/// reply label and how many reply words landed in `reply` (none if
/// `auditkey` claims more than a reply holds). The registers are zeroed.
fn sign(words: &[u64; SIGN_REQ_WORDS], reply: &mut [u64; SIGN_REPLY_WORDS]) -> (u64, usize) {
    with_msg_regs_mut(|mrs| {
        for (dst, src) in mrs.iter_mut().zip(words) {
            *dst = *src;
        }
    });
    let info = Channel::new(ch::CH_AUDITKEY).pp_call(MessageInfo::new(SIGN, SIGN_REQ_WORDS));
    let count = info.count();
    let n = if count <= SIGN_REPLY_WORDS { count } else { 0 };
    with_msg_regs(|mrs| {
        for (dst, src) in reply.iter_mut().zip(mrs.iter().take(n)) {
            *dst = *src;
        }
    });
    with_msg_regs_mut(|mrs| mrs.iter_mut().take(SIGN_REPLY_WORDS).for_each(|w| *w = 0));
    (info.label(), n)
}

impl Console {
    /// Prints one line with its ` seq=` trailer and CRLF, and extends the
    /// chain over it (trailer included, CRLF not). Formatting cannot fail.
    fn emit(&mut self, args: fmt::Arguments) {
        let mut w = LineWriter { uart: &self.uart, line: self.chain.begin() };
        let _ = w.write_fmt(args);
        let LineWriter { uart, line } = w;
        self.chain.end(line, |t| t.iter().for_each(|b| uart.put(*b)));
        uart.put(b'\r');
        uart.put(b'\n');
    }

    /// One line, then any checkpoint it made due.
    fn line(&mut self, args: fmt::Arguments) {
        self.emit(args);
        self.checkpoint();
    }

    /// The checkpoint due before the next line, if any: signed through the
    /// one `sign` call when `audit_core` says so, else unsigned. Its own
    /// line carries the seq the request named, the chain before it and the
    /// lost total.
    fn checkpoint(&mut self) {
        let chain = self.chain.head();
        let lost = self.lost;
        let outcome = match self.checkpoints.poll(self.chain.next_seq(), chain, lost) {
            Action::Idle => return,
            Action::Call(words) => {
                let mut reply = [0u64; SIGN_REPLY_WORDS];
                let (label, n) = sign(&words, &mut reply);
                self.checkpoints.reply(label, reply.get(..n).unwrap_or(&[]))
            }
            Action::Unsigned(reason) => Outcome::Unsigned(reason),
        };
        self.checkpoint_line(outcome, &chain, lost);
    }

    fn checkpoint_line(&mut self, outcome: Outcome, chain: &[u8; CHAIN_LEN], lost: u64) {
        match outcome {
            Outcome::Signed(Reply { signature, identity: id }) => self.emit(format_args!(
                "audit: checkpoint srk={} boot={} reset={} restart={} chain={} lost={} sig={}",
                Hex(&id.srk_name),
                Hex(&id.boot_id),
                id.reset,
                id.restart,
                Hex(chain),
                lost,
                Hex(&signature)
            )),
            Outcome::Unsigned(reason) => self.emit(format_args!(
                "audit: checkpoint boot=unavailable chain={} lost={} sig=unavailable reason={}",
                Hex(chain),
                lost,
                reason
            )),
        }
    }
}

/// One line to the console (`Console::line`).
macro_rules! println {
    ($console:expr, $($arg:tt)*) => {
        $console.line(format_args!($($arg)*))
    };
}

struct Source {
    name: &'static str,
    channel: Channel,
    ring: Consumer<AuditRing, Record, AUDIT_RING_SLOTS>,
    reported_corrupt: bool,
}

/// `policy`'s log page (M8 plan C10), mapped read-only here: the count it
/// published and how far this PD printed, which only this PD knows.
struct PolicyLog {
    page: NonNull<u64>,
    printed: usize,
}

/// The ring sources, then `policy`'s log page: the ready checkpoint waits
/// for each one's `Ready`.
const RING_SOURCES: usize = 8;
const POLICY_SOURCE: usize = RING_SOURCES;
const SOURCES: usize = RING_SOURCES + 1;

struct Audit {
    sources: [Source; RING_SOURCES],
    policy: PolicyLog,
    unknown: UnknownCodes,
    console: Console,
    /// The supervisor's record page (M7 plan C8), read-only here, and the
    /// last record printed.
    record: NonNull<[u64; supervisor_core::RECORD_WORDS]>,
    last_seq: u64,
    heartbeat: Heartbeat,
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
    let uart = Uart { base };
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
    let policy = PolicyLog { page: memory_region_symbol!(audit_policy: *mut [u64; log::WORDS]).cast(), printed: 0 };
    let mut console = Console { uart, chain: Chain::new(), lost: 0, checkpoints: Checkpoints::new(SOURCES) };
    println!(console, "audit: ready");
    let record = memory_region_symbol!(supervisor_record: *mut [u64; supervisor_core::RECORD_WORDS]);
    Audit { sources, policy, unknown: UnknownCodes::new(), console, record, last_seq: 0, heartbeat: Heartbeat::new() }
}

fn drop_reason(r: u16) -> Option<DropReason> {
    DropReason::ALL.iter().copied().find(|d| *d as u16 == r)
}

/// A coalesced kind whose value has a name in `names`: its line, or false
/// (an unnamed value counts as an unknown code).
fn named(console: &mut Console, src: &str, kind: &str, names: &[&str], v: u16, r: Record) -> bool {
    match names.get(usize::from(v)) {
        Some(name) => {
            println!(console, "audit: src={} {}({}) total={} lost={}", src, kind, name, r.a, r.b);
            true
        }
        None => false,
    }
}

impl Audit {
    /// Prints source `index`'s record `r` (`index` < `SOURCES`).
    fn print(&mut self, index: usize, src: &'static str, r: Record) {
        let console = &mut self.console;
        // Every source's lost count, whatever the record (M8 plan C10).
        console.lost = console.lost.saturating_add(u64::from(r.b));
        let named = match decode(r.code) {
            // The readiness line keeps the form the PDs printed themselves
            // before C6, which the integration waits read. The source counts
            // as ready before its line, so the ready checkpoint follows it.
            Decoded::Fixed(audit_event::Event::Ready) => {
                console.checkpoints.source_ready(index);
                if r.b == 0 {
                    println!(console, "{}: ready", src);
                } else {
                    println!(console, "{}: ready lost={}", src, r.b);
                }
                true
            }
            Decoded::Fixed(ev) => {
                println!(console, "audit: src={} {} total={} lost={}", src, ev.name(), r.a, r.b);
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
                    println!(console, "audit: src={} FrameDropped({:?}) total={} lost={}", src, d, r.a, r.b);
                    true
                }
                None => false,
            },
            Decoded::TcpLimited(kind) => named(console, src, "TcpLimited", &TCP_LIMIT_NAMES, kind, r),
            Decoded::TlsRefused(v) => named(console, src, "TlsRefused", &TLS_REFUSED_NAMES, v, r),
            Decoded::TlsClosed(v) => named(console, src, "TlsClosed", &TLS_CLOSED_NAMES, v, r),
            Decoded::HttpRefused(v) => named(console, src, "HttpRefused", &HTTP_REFUSED_NAMES, v, r),
            Decoded::TlsTimeout(v) => named(console, src, "TlsTimeout", &TLS_TIMEOUT_NAMES, v, r),
            Decoded::TlsSignHighWater => {
                println!(console, "audit: src={} TlsSignHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::CostHighWater => {
                println!(console, "audit: src={} RpCostHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::StackHighWater => {
                println!(console, "audit: src={} StackHighWater bytes={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyStackHighWater => {
                println!(console, "audit: src={} KeyStackHighWater bytes={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyWaitHighWater => {
                println!(console, "audit: src={} KeyWaitHighWater us={} lost={}", src, r.a, r.b);
                true
            }
            // A boot stop is a source's last word: it counts as ready, or a
            // boot whose barrier PDs halt (policy Unavailable) would never
            // sign the checkpoint that verifies its `policy:` lines.
            Decoded::Halted => {
                console.checkpoints.source_ready(index);
                println!(console, "audit: src={} Halted reason={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::KeyUnavailable => {
                println!(console, "audit: src={} KeyUnavailable code={} lost={}", src, r.a, r.b);
                true
            }
            // M8 plan C9: the version lines the runbook reads.
            Decoded::PolicyAccepted(slot) => match POLICY_SLOT_NAMES.get(usize::from(slot)) {
                Some(slot) => {
                    println!(console, "{}: accepted version={} slot={} lost={}", src, r.a, slot, r.b);
                    true
                }
                None => false,
            },
            Decoded::ReleaseSeq => {
                println!(console, "{}: release_seq={} lost={}", src, r.a, r.b);
                true
            }
            Decoded::PolicyUnavailable(reason) => match POLICY_REASON_NAMES.get(usize::from(reason)) {
                // No current version is known when the state was refused,
                // whatever `a` holds.
                Some(name) if reason == POLICY_STATE_REFUSED => {
                    println!(console, "{}: unavailable reason={} current=unknown lost={}", src, name, r.b);
                    true
                }
                Some(name) => {
                    println!(console, "{}: unavailable reason={} current={} lost={}", src, name, r.a, r.b);
                    true
                }
                None => false,
            },
            Decoded::PolicyRejected { slot, reason } => {
                match (POLICY_SLOT_NAMES.get(usize::from(slot)), POLICY_REASON_NAMES.get(usize::from(reason))) {
                    // The version only where the slot held a verified
                    // bundle; `policy` sends 0 otherwise, which is also v0.
                    (Some(slot), Some(name)) if matches!(*name, "RolledBack" | "Skipped" | "BelowFloor") => {
                        println!(console, "{}: rejected slot={} reason={} version={} lost={}", src, slot, name, r.a, r.b);
                        true
                    }
                    (Some(slot), Some(name)) => {
                        println!(console, "{}: rejected slot={} reason={} version=- lost={}", src, slot, name, r.b);
                        true
                    }
                    _ => false,
                }
            }
            // M8 plan C8: `inner`'s group-authorization drops, per peer.
            Decoded::InnerDenied { peer, reason } => match INNER_REASON_NAMES.get(usize::from(reason)) {
                Some(name) => {
                    println!(console, "audit: src={} InnerDenied({}) peer={} total={} lost={}", src, name, peer, r.a, r.b);
                    true
                }
                None => false,
            },
            // M8 plan C12: who connected, and from where. An endpoint
            // change is two records, printed as two adjacent lines of the
            // same source: the IP, then the port (a line is one record).
            Decoded::PeerHandshake(peer) => {
                println!(console, "audit: src={} PeerHandshake peer={} index={:#010x} lost={}", src, peer, r.a, r.b);
                true
            }
            Decoded::PeerEndpointIp(peer) => {
                println!(console, "audit: src={} PeerEndpoint peer={} ip={} lost={}", src, peer, Ipv4(r.a), r.b);
                true
            }
            // A port above 65535 is no port: counted as an unknown code.
            Decoded::PeerEndpointPort(peer) => match u16::try_from(r.a) {
                Ok(port) => {
                    println!(console, "audit: src={} PeerEndpoint peer={} port={} lost={}", src, peer, port, r.b);
                    true
                }
                Err(_) => false,
            },
            Decoded::Unknown => false,
        };
        if !named && let Some(total) = self.unknown.record() {
            println!(console, "audit: src={} unknown code={:#06x} unknown_total={}", src, r.code, total);
        }
    }
}

impl Audit {
    /// Prints what `policy` published since the last read: at most
    /// `log::SLOTS` records, whatever the page's count says.
    fn drain_policy(&mut self) {
        let page = self.policy.page;
        // SAFETY: the page is mapped r into this PD and rw into `policy`
        // alone (laws), page-aligned, at least `log::WORDS` words, for the
        // life of the system; every index read is below `log::WORDS`.
        let read = |at: usize| if at < log::WORDS { unsafe { page.add(at).read_volatile() } } else { 0 };
        let pending = log::pending(read(0), self.policy.printed);
        self.policy.printed = pending.end;
        for i in pending {
            let at = log::slot_word(i);
            self.print(POLICY_SOURCE, "policy", log::decode([read(at), read(at.saturating_add(1))]));
        }
    }
}

impl Handler for Audit {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if audit_core::ready_input(channels.iter().map(|c| c.index())) {
            self.console.checkpoints.notified();
        }
        if channels.contains(Channel::new(ch::CH_POLICY)) {
            self.drain_policy();
        }
        if channels.contains(Channel::new(ch::CH_SUPERVISOR)) {
            // SAFETY: the record page is mapped r into this PD and rw into
            // the supervisor alone (laws), page-aligned, for the life of
            // the system. Read once: the supervisor resets right after.
            let r = supervisor_core::Record::decode(unsafe { self.record.as_ptr().read_volatile() });
            if r.seq != 0 && r.seq != self.last_seq {
                self.last_seq = r.seq;
                self.console.lost = self.console.lost.saturating_add(r.lost);
                match r.child_name() {
                    Some(pd) => {
                        println!(self.console, "supervisor: fault pd={} label={} lost={}", pd, r.label, r.lost);
                    }
                    None => {
                        println!(self.console, "supervisor: fault child={} label={} lost={}", r.child, r.label, r.lost);
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
                    Ok(Some(r)) => self.print(i, name, r),
                    Ok(None) => break,
                    Err(RingError::Corrupt | RingError::Full) => {
                        if !core::mem::replace(&mut src.reported_corrupt, true) {
                            println!(self.console, "audit: src={} ring corrupt, ignoring producer", name);
                        }
                        break;
                    }
                }
            }
        }
        if channels.contains(Channel::new(ch::CH_TIMER)) && let Some(ticks) = self.heartbeat.tick() {
            println!(self.console, "audit: {} ticks={}", HEARTBEAT, ticks);
        }
        // The ready checkpoint can fall due on the notification alone.
        self.console.checkpoint();
        Ok(())
    }
}
