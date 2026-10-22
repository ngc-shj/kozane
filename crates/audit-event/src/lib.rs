//! Audit events: a closed set of codes plus two integers (law L10).
//!
//! No variant carries bytes, so nothing attacker-supplied or secret can
//! reach the log through this channel. Producers coalesce: each event kind
//! is emitted on its 1st occurrence and every 64th after (running totals
//! 1, 65, 129, ...), so a flood of K events yields about K/64 records.
//! The few kinds for which `Event::is_coalesced` is false are emitted on
//! every occurrence; producers raise them only on state edges, never at a
//! rate an attacker drives.
//!
//! One kind carries a value instead of a running total:
//! `RpCostHighWater`'s `a` is the measured cost in µs, and `CostHighWater`
//! gates how often it fires.

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
    /// Running total of this event kind (`RpCostHighWater`: its value).
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
    /// A handshake completed; a session was handed to `data`.
    HandshakeOk,
    /// Initiation from a static key not in the configuration.
    HandshakeUnknownPeer,
    /// Initiation's encrypted static or timestamp failed to authenticate.
    HandshakeDecrypt,
    /// Initiation's TAI64N was not newer than the peer's last one.
    HandshakeReplay,
    /// Initiation within 1/50 s of the peer's last accepted one.
    HandshakeFlood,
    /// `key` refused a request (rate limit or invalid point).
    HandshakeKeyRefused,
    /// Any other handshake rejection (malformed, zero DH, entropy).
    HandshakeOther,
    /// WireGuard type/length a responder does not accept.
    WgBadMessage,
    /// Initiation with an invalid mac1.
    WgBadMac1,
    /// Initiation over its source's rate budget.
    WgRateLimited,
    /// `data` installed a session as `next`.
    SessionInstalled,
    /// Install whose index collides with a live session.
    SessionCollision,
    /// Transport packet with an unknown index, bad tag, replayed or expired.
    TransportRejected,
    /// Decrypted packet whose source is outside the peer's allowed IPs.
    SpoofedSource,
    /// Outbound packet with no peer or no current session.
    NoSession,
    /// Decrypted packet for a host that is not a static neighbor.
    UnknownNeighbor,
    /// First authenticated packet confirmed a `next` session.
    SessionPromoted,
    /// A session reached REJECT_AFTER_TIME and was zeroized.
    SessionExpired,
    /// `key` refused a request because `hs`'s call budget was exhausted.
    HandshakeKeyRateLimited,
    /// Transport packet for a receiver index with no live session.
    TransportUnknownIndex,
    /// `ingress` entered the under-load state (edge; never coalesced).
    WgUnderLoad,
    /// `ingress` left the under-load state (edge; never coalesced).
    WgLoadCleared,
    /// Under load, an initiation without a valid mac2 drew a cookie reply.
    WgCookieSent,
    /// A cookie reply was due but not sent (TX reserve or seal failure).
    WgCookieSuppressed,
    /// A cookie reply was due but no usable cookie secret was held.
    WgCookieDropped,
    /// Under load, an initiation with a valid mac2 was forwarded to `hs`.
    WgMac2Accepted,
    /// The cookie secret reached its maximum age unrotated (edge; never
    /// coalesced).
    CookieSecretExpired,
    /// The cookie secret could not be generated (edge; never coalesced).
    CookieSecretUnavailable,
    /// An ARP reply was due but the TX reserve was reached.
    ArpSuppressed,
    HandshakePskMissing,
    HandshakePskStale,
    RpBadMac,
    RpRateLimited,
    RpTypeDropped,
    RpInitHello,
    RpBiscuitReplay,
    RpPskExported,
    RpPskInstallFailed,
    RpRngFailed,
    RpDecapsRateLimited,
    /// `pq` could not enqueue a completion record, so it keeps the input
    /// held and stops its Rosenpass path for good (M3b plan C3; never
    /// coalesced, raised once).
    RpPqRecordStuck,
    /// `ingress` found `pq`'s completion records and buffer returns out of
    /// step and stopped relaying for good (M3b plan, `pq_sync_dead`; never
    /// coalesced, raised once).
    RpPqSyncDead,
    /// The Rosenpass cookie gate engaged: a meter refused an InitHello, or
    /// the global InitHello meter fell below half (M3b; never coalesced).
    RpUnderLoad,
    /// The Rosenpass cookie gate disengaged (never coalesced).
    RpLoadCleared,
    /// The Rosenpass cookie secret reached its maximum age (never coalesced).
    RpCookieSecretExpired,
    /// No Rosenpass cookie secret: its rotation failed (never coalesced).
    RpCookieSecretUnavailable,
    /// A Rosenpass CookieReply went out.
    RpCookieReplySent,
    /// An InitHello with a valid cookie passed the gate under load.
    RpCookieAccepted,
    /// A Rosenpass CookieReply was due but found no TX room or failed to seal.
    RpCookieSuppressed,
    /// `pq`'s handshake cost rose to a new high-water mark; `us` travels as
    /// the record's `a` (never coalesced; `CostHighWater` bounds it).
    RpCostHighWater { us: u32 },
    /// A PD's stack reached a new high-water mark; `bytes` (used below the
    /// stack top) travels as the record's `a` (never coalesced; raised only
    /// when deeper). `pq` reports it this way rather than printing, so its
    /// line cannot interleave with `audit`'s on the console (M4 plan C8).
    StackHighWater { bytes: u32 },
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
            Event::HandshakeOk => 0x0020,
            Event::HandshakeUnknownPeer => 0x0021,
            Event::HandshakeDecrypt => 0x0022,
            Event::HandshakeReplay => 0x0023,
            Event::HandshakeFlood => 0x0024,
            Event::HandshakeKeyRefused => 0x0025,
            Event::HandshakeOther => 0x0026,
            Event::WgBadMessage => 0x0027,
            Event::WgBadMac1 => 0x0028,
            Event::WgRateLimited => 0x0029,
            Event::SessionInstalled => 0x002a,
            Event::SessionCollision => 0x002b,
            Event::TransportRejected => 0x002c,
            Event::SpoofedSource => 0x002d,
            Event::NoSession => 0x002e,
            Event::UnknownNeighbor => 0x002f,
            Event::SessionPromoted => 0x0030,
            Event::SessionExpired => 0x0031,
            Event::HandshakeKeyRateLimited => 0x0032,
            Event::TransportUnknownIndex => 0x0033,
            Event::WgUnderLoad => 0x0034,
            Event::WgLoadCleared => 0x0035,
            Event::WgCookieSent => 0x0036,
            Event::WgCookieSuppressed => 0x0037,
            Event::WgCookieDropped => 0x0038,
            Event::WgMac2Accepted => 0x0039,
            Event::CookieSecretExpired => 0x003a,
            Event::CookieSecretUnavailable => 0x003b,
            Event::ArpSuppressed => 0x003c,
            Event::HandshakePskMissing => 0x003d,
            Event::HandshakePskStale => 0x003e,
            Event::RpBadMac => 0x003f,
            Event::RpRateLimited => 0x0040,
            Event::RpTypeDropped => 0x0041,
            Event::RpInitHello => 0x0042,
            Event::RpBiscuitReplay => 0x0043,
            Event::RpPskExported => 0x0044,
            Event::RpPskInstallFailed => 0x0045,
            Event::RpRngFailed => 0x0046,
            Event::RpDecapsRateLimited => 0x0047,
            Event::RpPqRecordStuck => 0x0049,
            Event::RpPqSyncDead => 0x004a,
            Event::RpUnderLoad => 0x004b,
            Event::RpLoadCleared => 0x004c,
            Event::RpCookieSecretExpired => 0x004d,
            Event::RpCookieSecretUnavailable => 0x004e,
            Event::RpCookieReplySent => 0x004f,
            Event::RpCookieAccepted => 0x0050,
            Event::RpCookieSuppressed => 0x0051,
            Event::RpCostHighWater { .. } => COST_HIGH_WATER,
            Event::StackHighWater { .. } => STACK_HIGH_WATER,
            Event::FrameDropped { reason } => {
                FRAME_DROPPED_BASE | (if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason })
            }
        }
    }

    /// Every variant except the parameterised `FrameDropped`,
    /// `RpCostHighWater` and `StackHighWater`.
    pub const FIXED: [Event; 60] = [
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
        Event::HandshakeOk,
        Event::HandshakeUnknownPeer,
        Event::HandshakeDecrypt,
        Event::HandshakeReplay,
        Event::HandshakeFlood,
        Event::HandshakeKeyRefused,
        Event::HandshakeOther,
        Event::WgBadMessage,
        Event::WgBadMac1,
        Event::WgRateLimited,
        Event::SessionInstalled,
        Event::SessionCollision,
        Event::TransportRejected,
        Event::SpoofedSource,
        Event::NoSession,
        Event::UnknownNeighbor,
        Event::SessionPromoted,
        Event::SessionExpired,
        Event::HandshakeKeyRateLimited,
        Event::TransportUnknownIndex,
        Event::WgUnderLoad,
        Event::WgLoadCleared,
        Event::WgCookieSent,
        Event::WgCookieSuppressed,
        Event::WgCookieDropped,
        Event::WgMac2Accepted,
        Event::CookieSecretExpired,
        Event::CookieSecretUnavailable,
        Event::ArpSuppressed,
        Event::HandshakePskMissing,
        Event::HandshakePskStale,
        Event::RpBadMac,
        Event::RpRateLimited,
        Event::RpTypeDropped,
        Event::RpInitHello,
        Event::RpBiscuitReplay,
        Event::RpPskExported,
        Event::RpPskInstallFailed,
        Event::RpRngFailed,
        Event::RpDecapsRateLimited,
        Event::RpPqRecordStuck,
        Event::RpPqSyncDead,
        Event::RpUnderLoad,
        Event::RpLoadCleared,
        Event::RpCookieSecretExpired,
        Event::RpCookieSecretUnavailable,
        Event::RpCookieReplySent,
        Event::RpCookieAccepted,
        Event::RpCookieSuppressed,
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
            Event::HandshakeOk => "HandshakeOk",
            Event::HandshakeUnknownPeer => "HandshakeUnknownPeer",
            Event::HandshakeDecrypt => "HandshakeDecrypt",
            Event::HandshakeReplay => "HandshakeReplay",
            Event::HandshakeFlood => "HandshakeFlood",
            Event::HandshakeKeyRefused => "HandshakeKeyRefused",
            Event::HandshakeOther => "HandshakeOther",
            Event::WgBadMessage => "WgBadMessage",
            Event::WgBadMac1 => "WgBadMac1",
            Event::WgRateLimited => "WgRateLimited",
            Event::SessionInstalled => "SessionInstalled",
            Event::SessionCollision => "SessionCollision",
            Event::TransportRejected => "TransportRejected",
            Event::SpoofedSource => "SpoofedSource",
            Event::NoSession => "NoSession",
            Event::UnknownNeighbor => "UnknownNeighbor",
            Event::SessionPromoted => "SessionPromoted",
            Event::SessionExpired => "SessionExpired",
            Event::HandshakeKeyRateLimited => "HandshakeKeyRateLimited",
            Event::TransportUnknownIndex => "TransportUnknownIndex",
            Event::WgUnderLoad => "WgUnderLoad",
            Event::WgLoadCleared => "WgLoadCleared",
            Event::WgCookieSent => "WgCookieSent",
            Event::WgCookieSuppressed => "WgCookieSuppressed",
            Event::WgCookieDropped => "WgCookieDropped",
            Event::WgMac2Accepted => "WgMac2Accepted",
            Event::CookieSecretExpired => "CookieSecretExpired",
            Event::CookieSecretUnavailable => "CookieSecretUnavailable",
            Event::ArpSuppressed => "ArpSuppressed",
            Event::HandshakePskMissing => "HandshakePskMissing",
            Event::HandshakePskStale => "HandshakePskStale",
            Event::RpBadMac => "RpBadMac",
            Event::RpRateLimited => "RpRateLimited",
            Event::RpTypeDropped => "RpTypeDropped",
            Event::RpInitHello => "RpInitHello",
            Event::RpBiscuitReplay => "RpBiscuitReplay",
            Event::RpPskExported => "RpPskExported",
            Event::RpPskInstallFailed => "RpPskInstallFailed",
            Event::RpRngFailed => "RpRngFailed",
            Event::RpDecapsRateLimited => "RpDecapsRateLimited",
            Event::RpPqRecordStuck => "RpPqRecordStuck",
            Event::RpPqSyncDead => "RpPqSyncDead",
            Event::RpUnderLoad => "RpUnderLoad",
            Event::RpLoadCleared => "RpLoadCleared",
            Event::RpCookieSecretExpired => "RpCookieSecretExpired",
            Event::RpCookieSecretUnavailable => "RpCookieSecretUnavailable",
            Event::RpCookieReplySent => "RpCookieReplySent",
            Event::RpCookieAccepted => "RpCookieAccepted",
            Event::RpCookieSuppressed => "RpCookieSuppressed",
            Event::RpCostHighWater { .. } => "RpCostHighWater",
            Event::StackHighWater { .. } => "StackHighWater",
            Event::FrameDropped { .. } => "FrameDropped",
        }
    }

    /// False for kinds emitted on every occurrence. Exhaustive, so a new
    /// variant must be classified here.
    pub const fn is_coalesced(self) -> bool {
        match self {
            Event::WgUnderLoad
            | Event::WgLoadCleared
            | Event::CookieSecretExpired
            | Event::CookieSecretUnavailable
            | Event::RpPqRecordStuck
            | Event::RpPqSyncDead
            | Event::RpUnderLoad
            | Event::RpLoadCleared
            | Event::RpCookieSecretExpired
            | Event::RpCookieSecretUnavailable
            | Event::RpCostHighWater { .. }
            | Event::StackHighWater { .. } => false,
            Event::ArpReplied
            | Event::UdpEchoed
            | Event::FrameDropped { .. }
            | Event::RingCorrupt
            | Event::RxNoBuffer
            | Event::TxNoBuffer
            | Event::BadDescriptor
            | Event::NotForUs
            | Event::NoService
            | Event::Spoofed
            | Event::DeviceFault
            | Event::FrameTooLong
            | Event::HandshakeOk
            | Event::HandshakeUnknownPeer
            | Event::HandshakeDecrypt
            | Event::HandshakeReplay
            | Event::HandshakeFlood
            | Event::HandshakeKeyRefused
            | Event::HandshakeOther
            | Event::WgBadMessage
            | Event::WgBadMac1
            | Event::WgRateLimited
            | Event::SessionInstalled
            | Event::SessionCollision
            | Event::TransportRejected
            | Event::SpoofedSource
            | Event::NoSession
            | Event::UnknownNeighbor
            | Event::SessionPromoted
            | Event::SessionExpired
            | Event::HandshakeKeyRateLimited
            | Event::TransportUnknownIndex
            | Event::WgCookieSent
            | Event::WgCookieSuppressed
            | Event::WgCookieDropped
            | Event::WgMac2Accepted
            | Event::ArpSuppressed
            | Event::HandshakePskMissing
            | Event::HandshakePskStale
            | Event::RpBadMac
            | Event::RpRateLimited
            | Event::RpTypeDropped
            | Event::RpInitHello
            | Event::RpBiscuitReplay
            | Event::RpPskExported
            | Event::RpPskInstallFailed
            | Event::RpRngFailed
            | Event::RpDecapsRateLimited
            | Event::RpCookieReplySent
            | Event::RpCookieAccepted
            | Event::RpCookieSuppressed => true,
        }
    }

    /// The value a record carries in place of the running total.
    pub const fn value(self) -> Option<u32> {
        match self {
            Event::RpCostHighWater { us } => Some(us),
            Event::StackHighWater { bytes } => Some(bytes),
            _ => None,
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
            Event::HandshakeOk => 11,
            Event::HandshakeUnknownPeer => 12,
            Event::HandshakeDecrypt => 13,
            Event::HandshakeReplay => 14,
            Event::HandshakeFlood => 15,
            Event::HandshakeKeyRefused => 16,
            Event::HandshakeOther => 17,
            Event::WgBadMessage => 18,
            Event::WgBadMac1 => 19,
            Event::WgRateLimited => 20,
            Event::SessionInstalled => 21,
            Event::SessionCollision => 22,
            Event::TransportRejected => 23,
            Event::SpoofedSource => 24,
            Event::NoSession => 25,
            Event::UnknownNeighbor => 26,
            Event::SessionPromoted => 27,
            Event::SessionExpired => 28,
            Event::HandshakeKeyRateLimited => 29,
            Event::TransportUnknownIndex => 30,
            Event::WgUnderLoad => 31,
            Event::WgLoadCleared => 32,
            Event::WgCookieSent => 33,
            Event::WgCookieSuppressed => 34,
            Event::WgCookieDropped => 35,
            Event::WgMac2Accepted => 36,
            Event::CookieSecretExpired => 37,
            Event::CookieSecretUnavailable => 38,
            Event::ArpSuppressed => 39,
            Event::HandshakePskMissing => 40,
            Event::HandshakePskStale => 41,
            Event::RpBadMac => 42,
            Event::RpRateLimited => 43,
            Event::RpTypeDropped => 44,
            Event::RpInitHello => 45,
            Event::RpBiscuitReplay => 46,
            Event::RpPskExported => 47,
            Event::RpPskInstallFailed => 48,
            Event::RpRngFailed => 49,
            Event::RpDecapsRateLimited => 50,
            Event::RpPqRecordStuck => 51,
            Event::RpPqSyncDead => 52,
            Event::RpUnderLoad => 53,
            Event::RpLoadCleared => 54,
            Event::RpCookieSecretExpired => 55,
            Event::RpCookieSecretUnavailable => 56,
            Event::RpCookieReplySent => 57,
            Event::RpCookieAccepted => 58,
            Event::RpCookieSuppressed => 59,
            Event::RpCostHighWater { .. } => COST_HIGH_WATER_SLOT,
            Event::StackHighWater { .. } => STACK_HIGH_WATER_SLOT,
            Event::FrameDropped { reason } => {
                // FIXED_SLOTS..FIXED_SLOTS+64, clamped like `code`.
                let r = if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason };
                FIXED_SLOTS.saturating_add(r as usize)
            }
        }
    }
}

const FIXED_SLOTS: usize = 60;
const COST_HIGH_WATER_SLOT: usize = FIXED_SLOTS + MAX_DROP_REASON as usize + 1;
const STACK_HIGH_WATER_SLOT: usize = COST_HIGH_WATER_SLOT + 1;
const SLOTS: usize = STACK_HIGH_WATER_SLOT + 1;

/// `RpCostHighWater`'s code, the first after the fixed range.
pub const COST_HIGH_WATER: u16 = 0x0048;
/// `StackHighWater`'s code, after the fixed range's last.
pub const STACK_HIGH_WATER: u16 = 0x0052;

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
        if ev.is_coalesced() && !total.wrapping_sub(1).is_multiple_of(COALESCE_EVERY) {
            return false;
        }
        let a = match ev.value() {
            Some(v) => v,
            None => *total,
        };
        let rec = Record { code: ev.code(), _reserved: 0, a, b: self.overflow };
        if push(rec) {
            self.overflow = 0;
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
        true
    }

    /// `record`, also reporting whether a record reached the ring:
    /// (offered, delivered). Delivered is false when the event was
    /// coalesced away or `push` failed.
    #[must_use]
    pub fn record_delivered(&mut self, ev: Event, push: impl FnOnce(Record) -> bool) -> (bool, bool) {
        let mut delivered = false;
        let offered = self.record(ev, |r| {
            delivered = push(r);
            delivered
        });
        (offered, delivered)
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
    /// `RpCostHighWater`: the record's `a` is the cost in µs.
    CostHighWater,
    /// `StackHighWater`: the record's `a` is the bytes used.
    StackHighWater,
    Unknown,
}

pub fn decode(code: u16) -> Decoded {
    if let Some(ev) = Event::from_fixed_code(code) {
        return Decoded::Fixed(ev);
    }
    if code == COST_HIGH_WATER {
        return Decoded::CostHighWater;
    }
    if code == STACK_HIGH_WATER {
        return Decoded::StackHighWater;
    }
    match code.checked_sub(FRAME_DROPPED_BASE) {
        Some(r) if r <= MAX_DROP_REASON => Decoded::FrameDropped(r),
        _ => Decoded::Unknown,
    }
}

/// `pq`'s gate for `RpCostHighWater` (M3 plan VE10): the first
/// measurement always fires, later ones only when the cost exceeds the
/// last *emitted* value by at least 1/8. A boot therefore emits at most
/// about log₁.₁₂₅(max/min) + 1 of them (L10; one more if the first cost
/// is 0 µs), and the last one emitted is less than 1/8 below the true
/// maximum. The record carries the exact cost; the rule only gates.
#[derive(Default)]
pub struct CostHighWater {
    last: Option<u32>,
}

impl CostHighWater {
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// The event to record for a handshake that cost `us`, if one is due,
    /// counted as emitted. A producer whose record can be lost uses
    /// `observe_with`.
    pub fn observe(&mut self, us: u32) -> Option<Event> {
        let mut ev = None;
        self.observe_with(us, |e| {
            ev = Some(e);
            true
        });
        ev
    }

    /// Offers the due event to `deliver`, and moves the mark only if it
    /// reports the record delivered: a record lost to a full ring leaves the
    /// mark where it was, so the next cost at or above it is offered again.
    pub fn observe_with(&mut self, us: u32, deliver: impl FnOnce(Event) -> bool) {
        let due = match self.last {
            None => true,
            // 8·us ≥ 9·last, i.e. us ≥ last + last/8 without rounding; the
            // strict `>` keeps a run of zeros from firing every time.
            Some(last) => us > last && u64::from(us).saturating_mul(8) >= u64::from(last).saturating_mul(9),
        };
        if due && deliver(Event::RpCostHighWater { us }) {
            self.last = Some(us);
        }
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
