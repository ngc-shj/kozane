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
//! Some kinds carry a value instead of a running total: `RpCostHighWater`'s,
//! `KeyWaitHighWater`'s and `TlsSignHighWater`'s `a` is the measured time in
//! µs (`CostHighWater` gates how often each fires), the stack marks' `a` is bytes, `Halted`'s a reason code closed
//! per producer and `KeyUnavailable`'s the key PD's boot error code. The
//! per-peer kinds (`PeerHandshake`, `PeerEndpointIp`, `PeerEndpointPort`)
//! carry a receiver index, an IPv4 address or a port.
//!
//! No kind names its producer: the producer is the audit ring a record
//! arrived on (M5 plan C6), so a PD cannot report on another's behalf.

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
/// `TCP_LIMITED_BASE + kind` (M6 plan C2): which of `ingress`'s TCP
/// buckets refused a segment to the HTTPS port, one coalesced code each.
pub const TCP_LIMITED_BASE: u16 = 0x0200;
const MAX_TCP_LIMIT: u16 = 0x1f;
/// SYN without ACK over its source's bucket.
pub const TCP_LIMIT_SYN_SOURCE: u16 = 0;
/// SYN without ACK over the global SYN bucket.
pub const TCP_LIMIT_SYN_GLOBAL: u16 = 1;
/// Any other segment over the global TCP data bucket.
pub const TCP_LIMIT_DATA: u16 = 2;
/// `audit`'s names for the kinds, indexed by kind.
pub const TCP_LIMIT_NAMES: [&str; 3] = ["SynSource", "SynGlobal", "Data"];
/// The `tls` PD's coalesced kinds (M6 plan C10), 32 codes each: base +
/// `tls_wire::Refusal::code`, `tls_core::conn::Closed::code`,
/// `http_wire::Status::index` and `tls_core::conn::Timeout` respectively.
/// The name tables below are `audit`'s; `tls` asserts at compile time that
/// they match those enums (this crate depends on none of them).
pub const TLS_REFUSED_BASE: u16 = 0x0220;
pub const TLS_CLOSED_BASE: u16 = 0x0240;
pub const HTTP_REFUSED_BASE: u16 = 0x0260;
pub const TLS_TIMEOUT_BASE: u16 = 0x0280;
const MAX_TLS_KIND: u16 = 0x1f;
/// The one code a `tls` kind's out-of-range value encodes to: outside all
/// four ranges and every name table, so a bad value is never reported as a
/// real refusal, close, status or timeout (`TlsRefused` fills all 32 of
/// its codes, so no in-range code is free to clamp onto). It decodes as
/// `Decoded::Unknown`, which `audit` prints as an unknown code.
pub const TLS_KIND_UNKNOWN: u16 = 0x02a0;
/// `tls_wire::Refusal`'s variants, by code.
pub const TLS_REFUSED_NAMES: [&str; 32] = [
    "RecordType",
    "RecordVersion",
    "RecordOverflow",
    "BadChangeCipherSpec",
    "UnexpectedChangeCipherSpec",
    "InnerAllZero",
    "InnerType",
    "HandshakeTooLong",
    "NotAtRecordBoundary",
    "UnexpectedMessage",
    "Decode",
    "LegacyVersion",
    "SessionIdTooLong",
    "NoChaCha",
    "Compression",
    "DuplicateExtension",
    "NoTls13",
    "NoPqGroup",
    "NoPqShare",
    "KeyShareLength",
    "DuplicateKeyShare",
    "NoSignatureAlgorithm",
    "NoApplicationProtocol",
    "PskNotLast",
    "PskWithoutModes",
    "BadKeyShare",
    "DecryptError",
    "BadRecordMac",
    "KeyUpdateValue",
    "Internal",
    "PeerAlert",
    "Closed",
];
/// `tls_core::conn::Closed`'s variants, by code.
pub const TLS_CLOSED_NAMES: [&str; 9] = [
    "BackendFin",
    "SelfResponse",
    "BackendRst",
    "ClientClosed",
    "Error",
    "SlotsFull",
    "PerSource",
    "PeerReset",
    "HandshakeCap",
];
/// `http_wire::Status` by index: the status codes.
pub const HTTP_REFUSED_NAMES: [&str; 5] = ["400", "413", "417", "431", "501"];
/// `tls_core::conn::Timeout`'s variants, by stage.
pub const TLS_TIMEOUT_NAMES: [&str; 5] = ["Handshake", "Head", "BackendConnect", "Idle", "Lifetime"];

/// The `policy` PD's boot lines (M8 plan C9, C10, F41): each a value-carrying
/// edge, raised at most once per boot, with the reason and slot riding in
/// code ranges as `FRAME_DROPPED_BASE + reason` does, so `Record.b` stays
/// the producer's lost count. Every range keeps its last code as its own
/// unknown (`Decoded::Unknown`), so an out-of-range slot or reason is never
/// clamped onto a real one (F45).
///
/// The slots, A and B (`policy_wire::Slot`), by index.
pub const POLICY_SLOTS: u16 = 2;
pub const POLICY_SLOT_NAMES: [&str; POLICY_SLOTS as usize] = ["A", "B"];
/// `policy_wire::Reject`'s variants, by code; `policy` asserts at compile
/// time that this table matches the enum (this crate depends on neither).
pub const POLICY_REASONS: u16 = 12;
pub const POLICY_REASON_NAMES: [&str; POLICY_REASONS as usize] = [
    "Malformed",
    "WrongFleet",
    "BadSignature",
    "RolledBack",
    "Skipped",
    "BelowFloor",
    "PrevMismatch",
    "Equivocation",
    "Empty",
    "MeasureMismatch",
    "AdvanceFailed",
    "StateRefused",
];
/// `StateRefused`'s code: `tpm` refused the state, so no current version
/// is known, and its line says `current=unknown` whatever `a` holds.
pub const POLICY_STATE_REFUSED: u16 = 11;
/// `POLICY_ACCEPTED_BASE + slot`, `a` = the accepted version; the code
/// after slot B is the range's unknown.
pub const POLICY_ACCEPTED_BASE: u16 = 0x0300;
/// This release's `RELEASE_SEQ`, `a` = its value.
pub const RELEASE_SEQ: u16 = 0x0308;
/// `POLICY_UNAVAILABLE_BASE + reason`, `a` = the current version; the code
/// after the last reason is the range's unknown.
pub const POLICY_UNAVAILABLE_BASE: u16 = 0x0310;
/// `POLICY_REJECTED_BASE + slot × POLICY_REASON_CODES + reason`, `a` = the
/// slot's version (0 unless its signatures verified): per slot, the reasons
/// and that slot's unknown; after both slots, the code an out-of-range slot
/// encodes to, `POLICY_REJECTED_UNKNOWN`.
pub const POLICY_REJECTED_BASE: u16 = 0x0320;
/// Codes per slot in the rejected range: every reason and its unknown.
pub const POLICY_REASON_CODES: u16 = POLICY_REASONS + 1;
pub const POLICY_REJECTED_UNKNOWN: u16 = POLICY_REJECTED_BASE + POLICY_SLOTS * POLICY_REASON_CODES;
/// The last code of every policy range: the rejected range's unknown.
const POLICY_LAST_CODE: u16 = POLICY_REJECTED_UNKNOWN;
/// Codes of both slots' reasons and unknowns, before `POLICY_REJECTED_UNKNOWN`.
const POLICY_REJECTED_CODES: u16 = POLICY_REJECTED_UNKNOWN - POLICY_REJECTED_BASE;
// The ranges, in order, each within its own block and none past the next.
const _: () = assert!(POLICY_ACCEPTED_BASE + POLICY_SLOTS < RELEASE_SEQ);
const _: () = assert!(RELEASE_SEQ < POLICY_UNAVAILABLE_BASE);
const _: () = assert!(POLICY_UNAVAILABLE_BASE + POLICY_REASONS < POLICY_REJECTED_BASE);
const _: () = assert!(POLICY_LAST_CODE < 0x0340);

/// `inner`'s group-authorization drops (M8 plan C8, C9 F43), coalesced per
/// peer and reason: `INNER_DENIED_BASE + peer × INNER_REASONS + reason`, `a`
/// the running total and `b` the lost count as for every coalesced kind.
/// Each peer's block keeps its last code as its own unknown, and a peer id
/// at or above `INNER_PEERS` encodes to `INNER_DENIED_UNKNOWN`, outside every
/// block (F45). `inner_core::flow::Denied`'s variants, by code; `inner`
/// asserts at compile time that this table matches the enum and that
/// `INNER_PEERS` is `limits::MAX_PEERS` (this crate depends on neither).
pub const INNER_REASON_NAMES: [&str; 4] = ["NoRule", "UnknownPeer", "NoFlow", "IcmpError"];
/// Codes per peer: every reason and the block's unknown.
pub const INNER_REASONS: u16 = INNER_REASON_CODES_REAL + 1;
/// The real reasons; the next code in a peer's block is its unknown.
const INNER_REASON_CODES_REAL: u16 = INNER_REASON_NAMES.len() as u16;
pub const INNER_PEERS: u16 = PEERS;
pub const INNER_DENIED_BASE: u16 = 0x0340;
pub const INNER_DENIED_UNKNOWN: u16 = INNER_DENIED_BASE + INNER_PEERS * INNER_REASONS;
const _: () = assert!(INNER_DENIED_UNKNOWN < PEER_HANDSHAKE_BASE);

/// Peer ids every per-peer range covers; each PD that raises a per-peer
/// kind asserts at compile time that this is `limits::MAX_PEERS`.
pub const PEERS: u16 = 8;
/// Per-peer attribution (M8 plan C12, "who, from where, when"): edges, never
/// coalesced, one code per peer, `a` the value and `b` the lost count. Each
/// range's code after the last peer is its unknown, the one a peer id at or
/// above `PEERS` encodes to (F45). `PEER_HANDSHAKE_BASE + peer`, `a` = the
/// receiver index `hs` chose for the session.
pub const PEER_HANDSHAKE_BASE: u16 = 0x0380;
pub const PEER_HANDSHAKE_UNKNOWN: u16 = PEER_HANDSHAKE_BASE + PEERS;
/// `PEER_ENDPOINT_IP_BASE + peer`, `a` = the peer's new outer IPv4 address,
/// big-endian (`a.b.c.d` is `a << 24 | ...`).
pub const PEER_ENDPOINT_IP_BASE: u16 = 0x0390;
pub const PEER_ENDPOINT_IP_UNKNOWN: u16 = PEER_ENDPOINT_IP_BASE + PEERS;
/// `PEER_ENDPOINT_PORT_BASE + peer`, `a` = its new outer UDP port; raised
/// right after the IP record of the same change.
pub const PEER_ENDPOINT_PORT_BASE: u16 = 0x03a0;
pub const PEER_ENDPOINT_PORT_UNKNOWN: u16 = PEER_ENDPOINT_PORT_BASE + PEERS;
const PEER_LAST_CODE: u16 = PEER_ENDPOINT_PORT_UNKNOWN;
const _: () = assert!(PEER_HANDSHAKE_UNKNOWN < PEER_ENDPOINT_IP_BASE);
const _: () = assert!(PEER_ENDPOINT_IP_UNKNOWN < PEER_ENDPOINT_PORT_BASE);
const _: () = assert!(PEER_LAST_CODE < 0x03b0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ArpReplied,
    UdpEchoed,
    /// `reason` is a `wire::DropReason` discriminant (< 64).
    FrameDropped { reason: u16 },
    /// `kind` is a `TCP_LIMIT_*` value (< 32).
    TcpLimited { kind: u16 },
    /// `tls` refused a connection's record or handshake; `reason` is a
    /// `tls_wire::Refusal` code (< 32).
    TlsRefused { reason: u16 },
    /// `tls` ended a connection; `reason` is a `tls_core::conn::Closed`
    /// code (< 32).
    TlsClosed { reason: u16 },
    /// `tls` answered a request head with a refusal status; `status` is an
    /// `http_wire::Status` index (< 32).
    HttpRefused { status: u16 },
    /// A `tls` connection timer fired; `stage` is a
    /// `tls_core::conn::Timeout` (< 32).
    TlsTimeout { stage: u16 },
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
    /// The producer finished init (edge; never coalesced). `audit` prints
    /// it as `<pd>: ready`, the line the PDs printed themselves before the
    /// release kernel took debug printing away (M5 plan C6).
    Ready,
    /// The producer stops for good; `reason` (the record's `a`) is a code
    /// from the producer's own closed table, documented where it is raised
    /// (never coalesced; raised once, just before the PD halts).
    Halted { reason: u32 },
    /// The key PD the producer calls answered with its boot error `code`
    /// (the record's `a`): it failed validation and holds no secret
    /// (never coalesced; raised the first time, once per boot).
    KeyUnavailable { code: u32 },
    /// The stack high-water mark of the key PD the producer calls, which
    /// has no audit ring of its own; `bytes` is the record's `a` (never
    /// coalesced; `pq` raises it once, for `pqkey`'s boot mark).
    KeyStackHighWater { bytes: u32 },
    /// The longest a call into the key PD has taken, wall time, rose to a
    /// new high-water mark; `us` travels as the record's `a` (never
    /// coalesced; `CostHighWater` bounds it). `hs` raises it: recorded, not
    /// bounded, since `key` serves `hs` alone (M6 plan C5, C12).
    KeyWaitHighWater { us: u32 },
    /// `tls` could not reach the backend for a request (its connect refused
    /// or reset, or the connect timeout) and answered 502 (M6 plan C10).
    BackendUnavailable,
    /// The longest `TlsSign` call into `tlskey`, wall time, rose to a new
    /// high-water mark; `us` travels as the record's `a` (never coalesced;
    /// `CostHighWater` bounds it). `tls` raises it: the signing latency it
    /// bears on its own budget (M6 plan C12, RM6-8).
    TlsSignHighWater { us: u32 },
    /// The Rosenpass cookie gate engaged because uncookied InitHellos whose
    /// exchange did not complete drained the unfinished meter, recorded
    /// alongside `RpUnderLoad` so tests and operators can tell that trigger
    /// from the meters (post-M6 plan P1, A1; never coalesced, raised only on
    /// that edge).
    RpUnfinishedLoad,
    /// The key PD the producer calls unsealed its secrets but `tpm` could
    /// not confirm the cap of PCR 8, so the key PD released nothing and the
    /// producer halts (post-M6 plan P3). Raised after `KeyUnavailable`,
    /// once per boot (an edge; never coalesced).
    TpmCapFailed,
    /// `policy` accepted the bundle in `slot` (0 = A, 1 = B) at `version`,
    /// which travels as `a` (M8 plan C9; never coalesced, once per boot).
    PolicyAccepted { slot: u16, version: u32 },
    /// The release's `RELEASE_SEQ`, as `a` (M8 plan C9; never coalesced,
    /// once per boot, beside `PolicyAccepted`).
    ReleaseSeq { seq: u32 },
    /// `policy` has no usable bundle this boot: `reason` is a
    /// `policy_wire::Reject` code, `current` (`a`) the logical version
    /// `tpm` reported (meaningless for `StateRefused`; never coalesced).
    PolicyUnavailable { reason: u16, current: u32 },
    /// `policy` refused the bundle in `slot` for `reason`; `version` (`a`)
    /// is the slot's version if its signatures verified, else 0 (never
    /// coalesced, at most once per slot and boot).
    PolicyRejected { slot: u16, reason: u16, version: u32 },
    /// `inner` dropped a packet from or for peer `peer` (the bundle index)
    /// for `reason`, an `inner_core::flow::Denied` code (coalesced per peer
    /// and reason, M8 plan C8).
    InnerDenied { peer: u16, reason: u16 },
    /// `hs` completed a handshake with peer `peer` (the bundle index) and
    /// handed the session to `data`; `index` (`a`) is the receiver index it
    /// chose, which the response carries in clear as its sender index and
    /// every transport packet from the peer as its receiver index. Never
    /// coalesced: at most one per peer per 1/50 s (`HandshakeFlood`), and
    /// only from a peer holding its static key and current PSK.
    PeerHandshake { peer: u16, index: u32 },
    /// `ingress` set or changed peer `peer`'s outer endpoint (from `data`'s
    /// `EndpointUpdate`): its IPv4 address, big-endian, as `a`. Never
    /// coalesced: one per change, and a change needs an authenticated
    /// packet with a new highest counter from another source.
    PeerEndpointIp { peer: u16, ip: u32 },
    /// The same change's UDP port, as `a`, recorded right after its
    /// `PeerEndpointIp`.
    PeerEndpointPort { peer: u16, port: u16 },
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
            Event::Ready => 0x0053,
            Event::BackendUnavailable => 0x0059,
            Event::RpUnfinishedLoad => 0x005a,
            Event::TpmCapFailed => 0x005b,
            Event::RpCostHighWater { .. } => COST_HIGH_WATER,
            Event::StackHighWater { .. } => STACK_HIGH_WATER,
            Event::Halted { .. } => HALTED,
            Event::KeyUnavailable { .. } => KEY_UNAVAILABLE,
            Event::KeyStackHighWater { .. } => KEY_STACK_HIGH_WATER,
            Event::KeyWaitHighWater { .. } => KEY_WAIT_HIGH_WATER,
            Event::TlsSignHighWater { .. } => TLS_SIGN_HIGH_WATER,
            Event::FrameDropped { reason } => {
                FRAME_DROPPED_BASE | (if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason })
            }
            Event::TcpLimited { kind } => TCP_LIMITED_BASE | (if kind > MAX_TCP_LIMIT { MAX_TCP_LIMIT } else { kind }),
            Event::TlsRefused { reason } => tls_code(TLS_REFUSED_BASE, reason),
            Event::TlsClosed { reason } => tls_code(TLS_CLOSED_BASE, reason),
            Event::HttpRefused { status } => tls_code(HTTP_REFUSED_BASE, status),
            Event::TlsTimeout { stage } => tls_code(TLS_TIMEOUT_BASE, stage),
            // Bounded below each range's width (asserted below), so the
            // wrapping operations never wrap.
            Event::PolicyAccepted { slot, .. } => {
                POLICY_ACCEPTED_BASE.wrapping_add(if slot < POLICY_SLOTS { slot } else { POLICY_SLOTS })
            }
            Event::ReleaseSeq { .. } => RELEASE_SEQ,
            Event::PolicyUnavailable { reason, .. } => POLICY_UNAVAILABLE_BASE.wrapping_add(policy_reason(reason)),
            Event::PolicyRejected { slot, reason, .. } => {
                if slot < POLICY_SLOTS {
                    POLICY_REJECTED_BASE.wrapping_add(slot.wrapping_mul(POLICY_REASON_CODES)).wrapping_add(policy_reason(reason))
                } else {
                    POLICY_REJECTED_UNKNOWN
                }
            }
            Event::InnerDenied { peer, reason } => inner_denied_code(peer, reason),
            Event::PeerHandshake { peer, .. } => peer_code(PEER_HANDSHAKE_BASE, peer),
            Event::PeerEndpointIp { peer, .. } => peer_code(PEER_ENDPOINT_IP_BASE, peer),
            Event::PeerEndpointPort { peer, .. } => peer_code(PEER_ENDPOINT_PORT_BASE, peer),
        }
    }

    /// Every variant except the parameterised `FrameDropped`, `TcpLimited`
    /// and `tls` kinds and the value-carrying ones (`Event::value` is `Some`).
    pub const FIXED: [Event; 64] = [
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
        Event::Ready,
        Event::BackendUnavailable,
        Event::RpUnfinishedLoad,
        Event::TpmCapFailed,
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
            Event::Ready => "Ready",
            Event::BackendUnavailable => "BackendUnavailable",
            Event::RpUnfinishedLoad => "RpUnfinishedLoad",
            Event::TpmCapFailed => "TpmCapFailed",
            Event::RpCostHighWater { .. } => "RpCostHighWater",
            Event::StackHighWater { .. } => "StackHighWater",
            Event::Halted { .. } => "Halted",
            Event::KeyUnavailable { .. } => "KeyUnavailable",
            Event::KeyStackHighWater { .. } => "KeyStackHighWater",
            Event::KeyWaitHighWater { .. } => "KeyWaitHighWater",
            Event::TlsSignHighWater { .. } => "TlsSignHighWater",
            Event::FrameDropped { .. } => "FrameDropped",
            Event::TcpLimited { .. } => "TcpLimited",
            Event::TlsRefused { .. } => "TlsRefused",
            Event::TlsClosed { .. } => "TlsClosed",
            Event::HttpRefused { .. } => "HttpRefused",
            Event::TlsTimeout { .. } => "TlsTimeout",
            Event::PolicyAccepted { .. } => "PolicyAccepted",
            Event::ReleaseSeq { .. } => "ReleaseSeq",
            Event::PolicyUnavailable { .. } => "PolicyUnavailable",
            Event::PolicyRejected { .. } => "PolicyRejected",
            Event::InnerDenied { .. } => "InnerDenied",
            Event::PeerHandshake { .. } => "PeerHandshake",
            Event::PeerEndpointIp { .. } => "PeerEndpointIp",
            Event::PeerEndpointPort { .. } => "PeerEndpointPort",
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
            | Event::RpUnfinishedLoad
            | Event::RpCookieSecretExpired
            | Event::RpCookieSecretUnavailable
            | Event::RpCostHighWater { .. }
            | Event::StackHighWater { .. }
            | Event::Ready
            | Event::TpmCapFailed
            | Event::Halted { .. }
            | Event::KeyUnavailable { .. }
            | Event::KeyStackHighWater { .. }
            | Event::KeyWaitHighWater { .. }
            | Event::TlsSignHighWater { .. }
            | Event::PolicyAccepted { .. }
            | Event::ReleaseSeq { .. }
            | Event::PolicyUnavailable { .. }
            | Event::PolicyRejected { .. }
            | Event::PeerHandshake { .. }
            | Event::PeerEndpointIp { .. }
            | Event::PeerEndpointPort { .. } => false,
            Event::ArpReplied
            | Event::UdpEchoed
            | Event::FrameDropped { .. }
            | Event::InnerDenied { .. }
            | Event::TcpLimited { .. }
            | Event::TlsRefused { .. }
            | Event::TlsClosed { .. }
            | Event::HttpRefused { .. }
            | Event::TlsTimeout { .. }
            | Event::BackendUnavailable
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
            Event::Halted { reason } => Some(reason),
            Event::KeyUnavailable { code } => Some(code),
            Event::KeyStackHighWater { bytes } => Some(bytes),
            Event::KeyWaitHighWater { us } => Some(us),
            Event::TlsSignHighWater { us } => Some(us),
            Event::PolicyAccepted { version, .. } => Some(version),
            Event::ReleaseSeq { seq } => Some(seq),
            Event::PolicyUnavailable { current, .. } => Some(current),
            Event::PolicyRejected { version, .. } => Some(version),
            Event::PeerHandshake { index, .. } => Some(index),
            Event::PeerEndpointIp { ip, .. } => Some(ip),
            Event::PeerEndpointPort { port, .. } => Some(port as u32),
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
            Event::Ready => 60,
            Event::BackendUnavailable => 61,
            Event::RpUnfinishedLoad => 62,
            Event::TpmCapFailed => 63,
            Event::RpCostHighWater { .. } => COST_HIGH_WATER_SLOT,
            Event::StackHighWater { .. } => STACK_HIGH_WATER_SLOT,
            Event::Halted { .. } => HALTED_SLOT,
            Event::KeyUnavailable { .. } => KEY_UNAVAILABLE_SLOT,
            Event::KeyStackHighWater { .. } => KEY_STACK_HIGH_WATER_SLOT,
            Event::KeyWaitHighWater { .. } => KEY_WAIT_HIGH_WATER_SLOT,
            Event::TlsSignHighWater { .. } => TLS_SIGN_HIGH_WATER_SLOT,
            Event::TlsRefused { reason } => tls_slot(TLS_REFUSED_SLOT, reason),
            Event::TlsClosed { reason } => tls_slot(TLS_CLOSED_SLOT, reason),
            Event::HttpRefused { status } => tls_slot(HTTP_REFUSED_SLOT, status),
            Event::TlsTimeout { stage } => tls_slot(TLS_TIMEOUT_SLOT, stage),
            Event::FrameDropped { reason } => {
                // FIXED_SLOTS..FIXED_SLOTS+64, clamped like `code`.
                let r = if reason > MAX_DROP_REASON { MAX_DROP_REASON } else { reason };
                FIXED_SLOTS.saturating_add(r as usize)
            }
            Event::TcpLimited { kind } => {
                // TCP_LIMITED_SLOT..TCP_LIMITED_SLOT+32, clamped like `code`.
                let k = if kind > MAX_TCP_LIMIT { MAX_TCP_LIMIT } else { kind };
                TCP_LIMITED_SLOT.saturating_add(k as usize)
            }
            // One slot per policy code, POLICY_SLOT..: `code` keeps every
            // policy event inside POLICY_ACCEPTED_BASE..=POLICY_LAST_CODE.
            Event::PolicyAccepted { .. }
            | Event::ReleaseSeq { .. }
            | Event::PolicyUnavailable { .. }
            | Event::PolicyRejected { .. } => {
                POLICY_SLOT.saturating_add(self.code().saturating_sub(POLICY_ACCEPTED_BASE) as usize)
            }
            // One slot per code, INNER_SLOT..: `code` keeps the event inside
            // INNER_DENIED_BASE..=INNER_DENIED_UNKNOWN.
            Event::InnerDenied { .. } => INNER_SLOT.saturating_add(self.code().saturating_sub(INNER_DENIED_BASE) as usize),
            // One slot per code, PEER_SLOT..: `code` keeps the three kinds
            // inside PEER_HANDSHAKE_BASE..=PEER_LAST_CODE.
            Event::PeerHandshake { .. } | Event::PeerEndpointIp { .. } | Event::PeerEndpointPort { .. } => {
                PEER_SLOT.saturating_add(self.code().saturating_sub(PEER_HANDSHAKE_BASE) as usize)
            }
        }
    }
}

const FIXED_SLOTS: usize = 64;
const COST_HIGH_WATER_SLOT: usize = FIXED_SLOTS + MAX_DROP_REASON as usize + 1;
const STACK_HIGH_WATER_SLOT: usize = COST_HIGH_WATER_SLOT + 1;
const HALTED_SLOT: usize = STACK_HIGH_WATER_SLOT + 1;
const KEY_UNAVAILABLE_SLOT: usize = HALTED_SLOT + 1;
const KEY_STACK_HIGH_WATER_SLOT: usize = KEY_UNAVAILABLE_SLOT + 1;
const TCP_LIMITED_SLOT: usize = KEY_STACK_HIGH_WATER_SLOT + 1;
const KEY_WAIT_HIGH_WATER_SLOT: usize = TCP_LIMITED_SLOT + MAX_TCP_LIMIT as usize + 1;
const TLS_SIGN_HIGH_WATER_SLOT: usize = KEY_WAIT_HIGH_WATER_SLOT + 1;
// Each `tls` kind: TLS_*_SLOT..+32; an out-of-range value of any of them
// counts in TLS_KIND_UNKNOWN_SLOT, as `code` maps it to TLS_KIND_UNKNOWN.
const TLS_REFUSED_SLOT: usize = TLS_SIGN_HIGH_WATER_SLOT + 1;
const TLS_CLOSED_SLOT: usize = TLS_REFUSED_SLOT + MAX_TLS_KIND as usize + 1;
const HTTP_REFUSED_SLOT: usize = TLS_CLOSED_SLOT + MAX_TLS_KIND as usize + 1;
const TLS_TIMEOUT_SLOT: usize = HTTP_REFUSED_SLOT + MAX_TLS_KIND as usize + 1;
const TLS_KIND_UNKNOWN_SLOT: usize = TLS_TIMEOUT_SLOT + MAX_TLS_KIND as usize + 1;
const POLICY_SLOT: usize = TLS_KIND_UNKNOWN_SLOT + 1;
const INNER_SLOT: usize = POLICY_SLOT + (POLICY_LAST_CODE - POLICY_ACCEPTED_BASE) as usize + 1;
const PEER_SLOT: usize = INNER_SLOT + (INNER_DENIED_UNKNOWN - INNER_DENIED_BASE) as usize + 1;
const SLOTS: usize = PEER_SLOT + (PEER_LAST_CODE - PEER_HANDSHAKE_BASE) as usize + 1;

/// A per-peer kind's code: `base + peer`, or the range's unknown, `base +
/// PEERS`, for a peer id out of range (never clamped onto a real peer).
const fn peer_code(base: u16, peer: u16) -> u16 {
    // Bounded by PEERS (each range asserted inside its block), so the
    // wrapping operation never wraps.
    base.wrapping_add(if peer < PEERS { peer } else { PEERS })
}

/// `InnerDenied`'s code: the peer's block and the reason in it, the block's
/// unknown for an out-of-range reason, `INNER_DENIED_UNKNOWN` for an
/// out-of-range peer (never clamped onto a real peer or reason).
const fn inner_denied_code(peer: u16, reason: u16) -> u16 {
    if peer >= INNER_PEERS {
        return INNER_DENIED_UNKNOWN;
    }
    // Bounded by INNER_PEERS × INNER_REASONS (asserted below 0x0380), so
    // the wrapping operations never wrap.
    let r = if reason < INNER_REASON_CODES_REAL { reason } else { INNER_REASON_CODES_REAL };
    INNER_DENIED_BASE.wrapping_add(peer.wrapping_mul(INNER_REASONS)).wrapping_add(r)
}

/// A policy reason inside its range: the reason, or the range's unknown.
const fn policy_reason(reason: u16) -> u16 {
    if reason < POLICY_REASONS { reason } else { POLICY_REASONS }
}

/// A `tls` kind's code: `base + v` inside its 32 codes, else
/// `TLS_KIND_UNKNOWN` (never clamped onto a real code).
const fn tls_code(base: u16, v: u16) -> u16 {
    if v > MAX_TLS_KIND { TLS_KIND_UNKNOWN } else { base | v }
}

/// A `tls` kind's counter slot, unknown values sharing one as in `tls_code`.
const fn tls_slot(base: usize, v: u16) -> usize {
    if v > MAX_TLS_KIND { TLS_KIND_UNKNOWN_SLOT } else { base.saturating_add(v as usize) }
}

/// `RpCostHighWater`'s code, the first after the fixed range.
pub const COST_HIGH_WATER: u16 = 0x0048;
/// `StackHighWater`'s code, after the fixed range's last.
pub const STACK_HIGH_WATER: u16 = 0x0052;
/// The M5 value-carrying codes, after `Ready` (0x0053).
pub const HALTED: u16 = 0x0054;
pub const KEY_UNAVAILABLE: u16 = 0x0055;
pub const KEY_STACK_HIGH_WATER: u16 = 0x0056;
/// M6 plan C5: `hs`'s key-call wait.
pub const KEY_WAIT_HIGH_WATER: u16 = 0x0057;
/// M6 plan C5: `tls`'s `TlsSign` call time.
pub const TLS_SIGN_HIGH_WATER: u16 = 0x0058;

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
    /// `TCP_LIMIT_*` value.
    TcpLimited(u16),
    /// `RpCostHighWater`: the record's `a` is the cost in µs.
    CostHighWater,
    /// `StackHighWater`: the record's `a` is the bytes used.
    StackHighWater,
    /// `Halted`: the record's `a` is the producer's reason code.
    Halted,
    /// `KeyUnavailable`: the record's `a` is the key PD's boot error code.
    KeyUnavailable,
    /// `KeyStackHighWater`: the record's `a` is the bytes used.
    KeyStackHighWater,
    /// `KeyWaitHighWater`: the record's `a` is the wait in µs.
    KeyWaitHighWater,
    /// `TlsSignHighWater`: the record's `a` is the call's time in µs.
    TlsSignHighWater,
    /// `tls_wire::Refusal` code.
    TlsRefused(u16),
    /// `tls_core::conn::Closed` code.
    TlsClosed(u16),
    /// `http_wire::Status` index.
    HttpRefused(u16),
    /// `tls_core::conn::Timeout` stage.
    TlsTimeout(u16),
    /// `PolicyAccepted`: the slot (< `POLICY_SLOTS`); `a` is the version.
    PolicyAccepted(u16),
    /// `ReleaseSeq`: `a` is the release's sequence number.
    ReleaseSeq,
    /// `PolicyUnavailable`: the reason (< `POLICY_REASONS`); `a` is the
    /// current version unless the reason is `POLICY_STATE_REFUSED`.
    PolicyUnavailable(u16),
    /// `PolicyRejected`: the slot and the reason; `a` is the slot's version.
    PolicyRejected { slot: u16, reason: u16 },
    /// `InnerDenied`: the peer (< `INNER_PEERS`) and the reason (an index
    /// into `INNER_REASON_NAMES`); `a` is the running total.
    InnerDenied { peer: u16, reason: u16 },
    /// `PeerHandshake`: the peer (< `PEERS`); `a` is the receiver index.
    PeerHandshake(u16),
    /// `PeerEndpointIp`: the peer; `a` is the IPv4 address, big-endian.
    PeerEndpointIp(u16),
    /// `PeerEndpointPort`: the peer; `a` is the UDP port.
    PeerEndpointPort(u16),
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
    if code == HALTED {
        return Decoded::Halted;
    }
    if code == KEY_UNAVAILABLE {
        return Decoded::KeyUnavailable;
    }
    if code == KEY_STACK_HIGH_WATER {
        return Decoded::KeyStackHighWater;
    }
    if code == KEY_WAIT_HIGH_WATER {
        return Decoded::KeyWaitHighWater;
    }
    if code == TLS_SIGN_HIGH_WATER {
        return Decoded::TlsSignHighWater;
    }
    if let Some(k) = code.checked_sub(TCP_LIMITED_BASE).filter(|k| *k <= MAX_TCP_LIMIT) {
        return Decoded::TcpLimited(k);
    }
    let tls_kind = |base: u16| code.checked_sub(base).filter(|v| *v <= MAX_TLS_KIND);
    if let Some(v) = tls_kind(TLS_REFUSED_BASE) {
        return Decoded::TlsRefused(v);
    }
    if let Some(v) = tls_kind(TLS_CLOSED_BASE) {
        return Decoded::TlsClosed(v);
    }
    if let Some(v) = tls_kind(HTTP_REFUSED_BASE) {
        return Decoded::HttpRefused(v);
    }
    if let Some(v) = tls_kind(TLS_TIMEOUT_BASE) {
        return Decoded::TlsTimeout(v);
    }
    if code == RELEASE_SEQ {
        return Decoded::ReleaseSeq;
    }
    if let Some(slot) = code.checked_sub(POLICY_ACCEPTED_BASE).filter(|s| *s < POLICY_SLOTS) {
        return Decoded::PolicyAccepted(slot);
    }
    if let Some(reason) = code.checked_sub(POLICY_UNAVAILABLE_BASE).filter(|r| *r < POLICY_REASONS) {
        return Decoded::PolicyUnavailable(reason);
    }
    if let Some(i) = code.checked_sub(POLICY_REJECTED_BASE).filter(|i| *i < POLICY_REJECTED_CODES)
        && let (Some(slot), Some(reason)) = (i.checked_div(POLICY_REASON_CODES), i.checked_rem(POLICY_REASON_CODES))
        && reason < POLICY_REASONS
    {
        return Decoded::PolicyRejected { slot, reason };
    }
    if let Some(i) = code.checked_sub(INNER_DENIED_BASE).filter(|i| *i < INNER_DENIED_UNKNOWN - INNER_DENIED_BASE)
        && let (Some(peer), Some(reason)) = (i.checked_div(INNER_REASONS), i.checked_rem(INNER_REASONS))
        && reason < INNER_REASON_CODES_REAL
    {
        return Decoded::InnerDenied { peer, reason };
    }
    let peer = |base: u16| code.checked_sub(base).filter(|p| *p < PEERS);
    if let Some(p) = peer(PEER_HANDSHAKE_BASE) {
        return Decoded::PeerHandshake(p);
    }
    if let Some(p) = peer(PEER_ENDPOINT_IP_BASE) {
        return Decoded::PeerEndpointIp(p);
    }
    if let Some(p) = peer(PEER_ENDPOINT_PORT_BASE) {
        return Decoded::PeerEndpointPort(p);
    }
    match code.checked_sub(FRAME_DROPPED_BASE) {
        Some(r) if r <= MAX_DROP_REASON => Decoded::FrameDropped(r),
        _ => Decoded::Unknown,
    }
}

/// `pq`'s gate for `RpCostHighWater` (M3 plan VE10), `hs`'s for
/// `KeyWaitHighWater` and `tls`'s for `TlsSignHighWater` (M6 plan C5): the first measurement always fires,
/// later ones only when the cost exceeds the last *emitted* value by at
/// least 1/8. A boot therefore emits at most about log₁.₁₂₅(max/min) + 1 of
/// them (L10; one more if the first cost is 0 µs), and the last one emitted
/// is less than 1/8 below the true maximum. The record carries the exact
/// cost; the rule only gates.
pub struct CostHighWater {
    last: Option<u32>,
    event: fn(u32) -> Event,
}

impl Default for CostHighWater {
    fn default() -> Self {
        Self::new()
    }
}

impl CostHighWater {
    /// `pq`'s Rosenpass handshake cost.
    pub const fn new() -> Self {
        Self { last: None, event: |us| Event::RpCostHighWater { us } }
    }

    /// `hs`'s wait for a key call.
    pub const fn key_wait() -> Self {
        Self { last: None, event: |us| Event::KeyWaitHighWater { us } }
    }

    /// `tls`'s time for a `TlsSign` call.
    pub const fn tls_sign() -> Self {
        Self { last: None, event: |us| Event::TlsSignHighWater { us } }
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
        if due && deliver((self.event)(us)) {
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

pub mod log;

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
