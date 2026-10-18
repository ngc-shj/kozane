//! Audit events: a closed set of codes plus two integers (law L10).
//!
//! No variant carries bytes, so nothing attacker-supplied or secret can
//! reach the log through this channel. Producers coalesce: each event kind
//! is emitted on its 1st occurrence and every 64th after (running totals
//! 1, 65, 129, ...), so a flood of K events yields about K/64 records.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

/// Wire format of one event in the audit ring. Every bit pattern is valid,
/// as required for ring slots written by an untrusted producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Record {
    pub code: u16,
    pub _reserved: u16,
    /// Running total of this event kind.
    pub a: u32,
    /// Events lost to a full audit ring since the last successful push.
    pub b: u32,
}

pub const COALESCE_EVERY: u32 = 64;

/// Code ranges. `FRAME_DROPPED_BASE + reason` encodes a `wire::DropReason`.
pub const FRAME_DROPPED_BASE: u16 = 0x0100;
const MAX_DROP_REASON: u16 = 0x3f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ArpReplied,
    UdpEchoed,
    /// `reason` is a `wire::DropReason` discriminant (< 64).
    FrameDropped { reason: u16 },
    RingCorrupt,
    RxNoBuffer,
    TxNoBuffer,
    BadDescriptor,
    /// Valid frame addressed to another host.
    NotForUs,
    /// Valid frame for us, but no service handles it.
    NoService,
    /// Frame forging our address or an inconsistent ARP sender.
    Spoofed,
    /// The NIC broke the virtqueue protocol; the driver stopped using it.
    DeviceFault,
    /// The NIC delivered a frame longer than a ring buffer.
    FrameTooLong,
}

impl Event {
    pub const fn code(self) -> u16 {
        match self {
            Event::ArpReplied => 0x0001,
            Event::UdpEchoed => 0x0002,
            Event::RingCorrupt => 0x0010,
            Event::RxNoBuffer => 0x0011,
            Event::TxNoBuffer => 0x0012,
            Event::BadDescriptor => 0x0013,
            Event::NotForUs => 0x0014,
            Event::NoService => 0x0015,
            Event::Spoofed => 0x0016,
            Event::DeviceFault => 0x0017,
            Event::FrameTooLong => 0x0018,
            Event::FrameDropped { reason } => {
                FRAME_DROPPED_BASE | (if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason })
            }
        }
    }

    /// Every variant except the parameterised `FrameDropped`.
    pub const FIXED: [Event; 11] = [
        Event::ArpReplied,
        Event::UdpEchoed,
        Event::RingCorrupt,
        Event::RxNoBuffer,
        Event::TxNoBuffer,
        Event::BadDescriptor,
        Event::NotForUs,
        Event::NoService,
        Event::Spoofed,
        Event::DeviceFault,
        Event::FrameTooLong,
    ];

    /// Display name; exhaustive, so a new variant fails to compile here.
    pub const fn name(self) -> &'static str {
        match self {
            Event::ArpReplied => "ArpReplied",
            Event::UdpEchoed => "UdpEchoed",
            Event::RingCorrupt => "RingCorrupt",
            Event::RxNoBuffer => "RxNoBuffer",
            Event::TxNoBuffer => "TxNoBuffer",
            Event::BadDescriptor => "BadDescriptor",
            Event::NotForUs => "NotForUs",
            Event::NoService => "NoService",
            Event::Spoofed => "Spoofed",
            Event::DeviceFault => "DeviceFault",
            Event::FrameTooLong => "FrameTooLong",
            Event::FrameDropped { .. } => "FrameDropped",
        }
    }

    /// Decodes a fixed (non-`FrameDropped`) code from a record.
    pub fn from_fixed_code(code: u16) -> Option<Event> {
        Event::FIXED.iter().copied().find(|e| e.code() == code)
    }

    /// Counter slot for coalescing; distinct for every distinct code.
    const fn slot(self) -> usize {
        match self {
            Event::ArpReplied => 0,
            Event::UdpEchoed => 1,
            Event::RingCorrupt => 2,
            Event::RxNoBuffer => 3,
            Event::TxNoBuffer => 4,
            Event::BadDescriptor => 5,
            Event::NotForUs => 6,
            Event::NoService => 7,
            Event::Spoofed => 8,
            Event::DeviceFault => 9,
            Event::FrameTooLong => 10,
            Event::FrameDropped { reason } => {
                // FIXED_SLOTS..FIXED_SLOTS+64, clamped like `code`.
                let r = if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason };
                FIXED_SLOTS.saturating_add(r as usize)
            }
        }
    }
}

const FIXED_SLOTS: usize = 11;
const SLOTS: usize = FIXED_SLOTS + MAX_DROP_REASON as usize + 1;

/// Per-producer coalescing state.
pub struct Coalescer {
    totals: [u32; SLOTS],
    overflow: u32,
}

impl Default for Coalescer {
    fn default() -> Self {
        Self::new()
    }
}

impl Coalescer {
    pub const fn new() -> Self {
        Self { totals: [0; SLOTS], overflow: 0 }
    }

    /// Counts `ev` and, when it is due, offers a record to `push`, which
    /// returns false if the audit ring is full. Never blocks.
    ///
    /// Returns whether a record was offered, pushed or not. The caller must
    /// notify `audit` whenever this is true: notifying only on success would
    /// leave a full ring undrained forever, since nothing would wake `audit`.
    #[must_use]
    pub fn record(&mut self, ev: Event, push: impl FnOnce(Record) -> bool) -> bool {
        let Some(total) = self.totals.get_mut(ev.slot()) else {
            return false;
        };
        *total = total.saturating_add(1);
        if !total.wrapping_sub(1).is_multiple_of(COALESCE_EVERY) {
            return false;
        }
        let rec = Record { code: ev.code(), _reserved: 0, a: *total, b: self.overflow };
        if push(rec) {
            self.overflow = 0;
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
        true
    }

    pub fn overflow(&self) -> u32 {
        self.overflow
    }
}

/// What `audit` prints for a record code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Fixed(Event),
    /// `wire::DropReason` discriminant.
    FrameDropped(u16),
    Unknown,
}

pub fn decode(code: u16) -> Decoded {
    if let Some(ev) = Event::from_fixed_code(code) {
        return Decoded::Fixed(ev);
    }
    match code.checked_sub(FRAME_DROPPED_BASE) {
        Some(r) if r <= MAX_DROP_REASON => Decoded::FrameDropped(r),
        _ => Decoded::Unknown,
    }
}

/// One shared counter for every code `audit` cannot name, coalesced like
/// producers, so a hostile producer cycling through 65 536 codes yields
/// about 1/64 as many log lines.
#[derive(Default)]
pub struct UnknownCodes {
    total: u32,
}

impl UnknownCodes {
    pub const fn new() -> Self {
        Self { total: 0 }
    }

    /// Counts one unknown record; returns the running total when a line is due.
    pub fn record(&mut self) -> Option<u32> {
        self.total = self.total.saturating_add(1);
        self.total.wrapping_sub(1).is_multiple_of(COALESCE_EVERY).then_some(self.total)
    }
}

#[cfg(test)]
mod tests;
