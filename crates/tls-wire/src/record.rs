//! The record layer (RFC 8446 section 5): headers, the change_cipher_spec
//! body and the inner plaintext of protected records. Which record may come
//! when (CCS window, keys) is `tls-core`'s state machine.

use crate::{ContentType, MAX_CIPHERTEXT, MAX_PLAINTEXT, RECORD_HEADER_LEN, Refusal, TLS10, TLS12};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub content_type: ContentType,
    /// The body length that follows the header.
    pub len: usize,
}

/// A record header. `first`: the connection's first record, which may carry
/// legacy_record_version 0x0301 (section 5.1, D.4). application_data
/// records are protected and may be 256 bytes longer than the others; a
/// zero-length handshake, alert or change_cipher_spec record is malformed.
pub fn header(bytes: &[u8; RECORD_HEADER_LEN], first: bool) -> Result<Header, Refusal> {
    let [t, v0, v1, l0, l1] = *bytes;
    let content_type = ContentType::from_u8(t).ok_or(Refusal::RecordType)?;
    let version = u16::from_be_bytes([v0, v1]);
    if version != TLS12 && !(first && version == TLS10) {
        return Err(Refusal::RecordVersion);
    }
    let len = usize::from(u16::from_be_bytes([l0, l1]));
    let max = if content_type == ContentType::ApplicationData { MAX_CIPHERTEXT } else { MAX_PLAINTEXT };
    if len > max {
        return Err(Refusal::RecordOverflow);
    }
    if len == 0 && content_type != ContentType::ApplicationData {
        return Err(Refusal::Decode);
    }
    Ok(Header { content_type, len })
}

/// A change_cipher_spec body: exactly the byte 0x01 (section 5).
pub fn change_cipher_spec(body: &[u8]) -> Result<(), Refusal> {
    if body == [1] { Ok(()) } else { Err(Refusal::BadChangeCipherSpec) }
}

/// A decrypted TLSInnerPlaintext (section 5.4): the zero padding stripped,
/// the real content type is the last non-zero byte and must be handshake,
/// alert or application_data. An all-zero plaintext has no type. Handshake
/// and alert content may not be empty.
pub fn inner_plaintext(plain: &[u8]) -> Result<(ContentType, &[u8]), Refusal> {
    // TLSInnerPlaintext is at most 2^14 + 1 bytes (section 5.4).
    if plain.len() > MAX_PLAINTEXT.saturating_add(1) {
        return Err(Refusal::RecordOverflow);
    }
    let at = plain.iter().rposition(|&b| b != 0).ok_or(Refusal::InnerAllZero)?;
    let (content, rest) = plain.split_at_checked(at).ok_or(Refusal::InnerAllZero)?;
    let ty = match rest.first().copied().and_then(ContentType::from_u8) {
        Some(ty @ (ContentType::Handshake | ContentType::Alert | ContentType::ApplicationData)) => ty,
        _ => return Err(Refusal::InnerType),
    };
    if content.is_empty() && ty != ContentType::ApplicationData {
        return Err(Refusal::Decode);
    }
    Ok((ty, content))
}

/// An alert body: level and description (section 6).
pub fn alert(body: &[u8]) -> Result<(u8, u8), Refusal> {
    match body {
        [level, desc] => Ok((*level, *desc)),
        _ => Err(Refusal::Decode),
    }
}
