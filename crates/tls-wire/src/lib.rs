//! TLS 1.3 record and handshake parsing and serialization for the `tls`
//! PD (M6 plan C6): one suite (TLS_CHACHA20_POLY1305_SHA256), one group
//! (X25519MLKEM768), one signature algorithm (ecdsa_secp256r1_sha256).
//!
//! - [`record`]: record headers, the change_cipher_spec body, protected
//!   records' inner plaintext (RFC 8446 section 5).
//! - [`framing`]: handshake message reassembly across records (section 5.1).
//! - [`hello`]: the ClientHello parser and its extension walker (section 4.1.2,
//!   4.2).
//! - [`emit`]: the server's messages, written into caller buffers.
//! - [`der`]: the DER `ECDSA-Sig-Value` CertificateVerify carries.
//!
//! Every refusal is a [`Refusal`]; [`Refusal::alert`] names the alert it
//! answers with. The crate has no state machine: `tls-core` decides which
//! message may come when.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[cfg(test)]
extern crate std;

pub mod der;
pub mod emit;
pub mod framing;
pub mod hello;
pub mod record;

mod reader;

/// Content type, legacy version and length (RFC 8446 section 5.1).
pub const RECORD_HEADER_LEN: usize = 5;
/// Largest plaintext a record may carry (RFC 8446 section 5.1).
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Largest protected record body (RFC 8446 section 5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// Largest handshake message, its 4-byte header included (M6 plan C6:
/// reassembly and the ClientHello are bounded by 8 KiB).
pub const MAX_HANDSHAKE: usize = 8 * 1024;
/// Handshake type and 24-bit length.
pub const HANDSHAKE_HEADER_LEN: usize = 4;
/// legacy_session_id is echoed and at most this long (section 4.1.2).
pub const MAX_SESSION_ID: usize = 32;
/// Our bound on the extensions of one ClientHello (duplicates are found
/// within it); real clients send about twenty.
pub const MAX_EXTENSIONS: usize = 64;
/// Our bound on key_share entries (real clients send one to three).
pub const MAX_KEY_SHARES: usize = 16;

/// `legacy_record_version` and `legacy_version`.
pub const TLS12: u16 = 0x0303;
/// Allowed as `legacy_record_version` on the first record only.
pub const TLS10: u16 = 0x0301;
/// supported_versions' TLS 1.3.
pub const TLS13: u16 = 0x0304;
/// The one cipher suite.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// The one key-exchange group (L14): X25519MLKEM768.
pub const X25519MLKEM768: u16 = 0x11ec;
/// The one signature scheme.
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// The client's share: ML-KEM-768 encapsulation key, then X25519 public.
pub const CLIENT_SHARE_LEN: usize = 1184 + 32;
/// The server's share: ML-KEM-768 ciphertext, then X25519 public.
pub const SERVER_SHARE_LEN: usize = 1088 + 32;
/// The one application protocol (M6 plan D4).
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
/// SHA-256's output: Finished's verify_data, transcript hashes.
pub const HASH_LEN: usize = 32;

/// Record content types (section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// Handshake message types (section 4) this server reads or writes.
pub mod hs {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
}

/// Extension types (section 4.2) the ClientHello walker reads.
pub mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const KEY_SHARE: u16 = 51;
}

/// Alert descriptions this server sends (section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    IllegalParameter = 47,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InternalError = 80,
    MissingExtension = 109,
    NoApplicationProtocol = 120,
}

/// Why a connection is refused. `code` is stable: `tls` audits it as
/// `TLS_REFUSED_BASE + code` (M6 plan C10), so variants are only appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A content type outside the four of section 5.1.
    RecordType,
    /// legacy_record_version not 0x0303 (0x0301 on the first record).
    RecordVersion,
    /// A record longer than 2^14 (plaintext) or 2^14 + 256 (protected).
    RecordOverflow,
    /// A change_cipher_spec record that is not exactly the byte 0x01.
    BadChangeCipherSpec,
    /// A change_cipher_spec outside ClientHello..client Finished, or a
    /// second one (M6 plan C6, S11a).
    UnexpectedChangeCipherSpec,
    /// A protected record whose inner plaintext is all zeros.
    InnerAllZero,
    /// A protected record's inner type outside handshake, alert and
    /// application_data.
    InnerType,
    /// A handshake message longer than [`MAX_HANDSHAKE`].
    HandshakeTooLong,
    /// A ClientHello, client Finished or KeyUpdate not ending at a record
    /// boundary (the key changes after it).
    NotAtRecordBoundary,
    /// A message or record this state does not accept.
    UnexpectedMessage,
    /// Malformed lengths, vectors or trailing bytes.
    Decode,
    /// ClientHello legacy_version not 0x0303.
    LegacyVersion,
    /// legacy_session_id longer than 32 bytes.
    SessionIdTooLong,
    /// The cipher suites lack TLS_CHACHA20_POLY1305_SHA256.
    NoChaCha,
    /// legacy_compression_methods other than exactly [0].
    Compression,
    /// An extension type twice in one ClientHello, or more than
    /// [`MAX_EXTENSIONS`] extensions.
    DuplicateExtension,
    /// No supported_versions, or it lacks TLS 1.3 (a TLS 1.2-only client).
    NoTls13,
    /// supported_groups absent or without X25519MLKEM768 (L14).
    NoPqGroup,
    /// X25519MLKEM768 supported but no key share for it (no HRR, RM6-6).
    NoPqShare,
    /// The X25519MLKEM768 share is not 1216 bytes.
    KeyShareLength,
    /// One group twice in key_share (section 4.2.8).
    DuplicateKeyShare,
    /// signature_algorithms absent or without ecdsa_secp256r1_sha256.
    NoSignatureAlgorithm,
    /// ALPN offered without http/1.1.
    NoApplicationProtocol,
    /// pre_shared_key not the last extension (section 4.2.11).
    PskNotLast,
    /// pre_shared_key without psk_key_exchange_modes (section 4.2.9).
    PskWithoutModes,
    /// The share fails the ML-KEM encapsulation-key check, or X25519
    /// yields the all-zero secret.
    BadKeyShare,
    /// The client Finished does not verify.
    DecryptError,
    /// A protected record fails deprotection.
    BadRecordMac,
    /// KeyUpdate request_update other than 0 or 1.
    KeyUpdateValue,
    /// No randomness (L9), an output buffer too small, a sequence number
    /// at its limit: nothing the peer can fix.
    Internal,
    /// The peer sent a fatal alert; nothing is answered.
    PeerAlert,
    /// A record or alert received after close_notify, or other input the
    /// closed connection ignores.
    Closed,
}

impl Refusal {
    /// The alert sent before closing, or None (the peer's own alert).
    pub const fn alert(self) -> Option<Alert> {
        Some(match self {
            Self::RecordType
            | Self::BadChangeCipherSpec
            | Self::UnexpectedChangeCipherSpec
            | Self::InnerAllZero
            | Self::InnerType
            | Self::NotAtRecordBoundary
            | Self::UnexpectedMessage => Alert::UnexpectedMessage,
            Self::RecordVersion | Self::HandshakeTooLong | Self::Decode | Self::SessionIdTooLong => Alert::DecodeError,
            Self::RecordOverflow => Alert::RecordOverflow,
            Self::LegacyVersion | Self::NoTls13 => Alert::ProtocolVersion,
            Self::NoChaCha | Self::NoPqGroup | Self::NoPqShare | Self::NoSignatureAlgorithm => Alert::HandshakeFailure,
            Self::Compression
            | Self::DuplicateExtension
            | Self::KeyShareLength
            | Self::DuplicateKeyShare
            | Self::PskNotLast
            | Self::BadKeyShare
            | Self::KeyUpdateValue => Alert::IllegalParameter,
            Self::NoApplicationProtocol => Alert::NoApplicationProtocol,
            Self::PskWithoutModes => Alert::MissingExtension,
            Self::DecryptError => Alert::DecryptError,
            Self::BadRecordMac => Alert::BadRecordMac,
            Self::Internal => Alert::InternalError,
            Self::PeerAlert | Self::Closed => return None,
        })
    }

    /// Every variant, in code order.
    pub const ALL: [Refusal; 32] = [
        Self::RecordType,
        Self::RecordVersion,
        Self::RecordOverflow,
        Self::BadChangeCipherSpec,
        Self::UnexpectedChangeCipherSpec,
        Self::InnerAllZero,
        Self::InnerType,
        Self::HandshakeTooLong,
        Self::NotAtRecordBoundary,
        Self::UnexpectedMessage,
        Self::Decode,
        Self::LegacyVersion,
        Self::SessionIdTooLong,
        Self::NoChaCha,
        Self::Compression,
        Self::DuplicateExtension,
        Self::NoTls13,
        Self::NoPqGroup,
        Self::NoPqShare,
        Self::KeyShareLength,
        Self::DuplicateKeyShare,
        Self::NoSignatureAlgorithm,
        Self::NoApplicationProtocol,
        Self::PskNotLast,
        Self::PskWithoutModes,
        Self::BadKeyShare,
        Self::DecryptError,
        Self::BadRecordMac,
        Self::KeyUpdateValue,
        Self::Internal,
        Self::PeerAlert,
        Self::Closed,
    ];

    /// The audit code: the variant's index in [`Refusal::ALL`], below 32
    /// (the width reserved for `TLS_REFUSED_BASE`).
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
