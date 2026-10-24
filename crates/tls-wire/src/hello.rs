//! The ClientHello (RFC 8446 section 4.1.2) and its extensions (section
//! 4.2), under M6 plan C6's profile. Every field is borrowed from the
//! message; nothing is copied.

use crate::reader::{Reader, u16s};
use crate::{
    ALPN_HTTP11, CLIENT_SHARE_LEN, ECDSA_SECP256R1_SHA256, HANDSHAKE_HEADER_LEN, MAX_EXTENSIONS, MAX_HANDSHAKE,
    MAX_KEY_SHARES, MAX_SESSION_ID, Refusal, TLS12, TLS13, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768, ext,
};

/// What the server uses from an accepted ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub random: &'a [u8; 32],
    /// Echoed in the ServerHello; at most 32 bytes.
    pub session_id: &'a [u8],
    /// The X25519MLKEM768 share: ML-KEM-768 encapsulation key ‖ X25519.
    pub key_share: &'a [u8; CLIENT_SHARE_LEN],
    /// ALPN was offered (with http/1.1): the server selects http/1.1.
    pub alpn: bool,
    /// The first host_name, parsed and otherwise unused.
    pub server_name: Option<&'a [u8]>,
    /// early_data was offered: records that fail deprotection before the
    /// first that succeeds may be skipped (section 4.2.10; `tls-core`).
    pub early_data: bool,
}

/// The extension blocks the profile reads, located by the walker. Every
/// slice lies inside the extensions block; no type occurs twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Extensions<'a> {
    pub supported_versions: Option<&'a [u8]>,
    pub supported_groups: Option<&'a [u8]>,
    pub key_share: Option<&'a [u8]>,
    pub signature_algorithms: Option<&'a [u8]>,
    pub alpn: Option<&'a [u8]>,
    pub server_name: Option<&'a [u8]>,
    pub psk_modes: Option<&'a [u8]>,
    pub pre_shared_key: Option<&'a [u8]>,
    pub early_data: bool,
}

/// Walks an extensions block (the bytes inside its two-byte length) by
/// length: each extension lies within the block, a type seen twice is
/// refused, as is a block of more than [`MAX_EXTENSIONS`]; pre_shared_key
/// must be last (section 4.2.11). Unknown types are skipped.
pub fn walk(block: &[u8]) -> Result<Extensions<'_>, Refusal> {
    let mut r = Reader::new(block);
    let mut seen = [0u16; MAX_EXTENSIONS];
    let mut count = 0usize;
    let mut out = Extensions::default();
    while !r.is_empty() {
        if out.pre_shared_key.is_some() {
            return Err(Refusal::PskNotLast);
        }
        let ty = r.u16()?;
        let data = r.vec16()?;
        if seen.get(..count).ok_or(Refusal::Internal)?.contains(&ty) {
            return Err(Refusal::DuplicateExtension);
        }
        *seen.get_mut(count).ok_or(Refusal::DuplicateExtension)? = ty;
        count = count.saturating_add(1);
        match ty {
            ext::SUPPORTED_VERSIONS => out.supported_versions = Some(data),
            ext::SUPPORTED_GROUPS => out.supported_groups = Some(data),
            ext::KEY_SHARE => out.key_share = Some(data),
            ext::SIGNATURE_ALGORITHMS => out.signature_algorithms = Some(data),
            ext::ALPN => out.alpn = Some(data),
            ext::SERVER_NAME => out.server_name = Some(data),
            ext::PSK_KEY_EXCHANGE_MODES => out.psk_modes = Some(data),
            ext::PRE_SHARED_KEY => out.pre_shared_key = Some(data),
            ext::EARLY_DATA => {
                // Empty in a ClientHello (section 4.2.10).
                if !data.is_empty() {
                    return Err(Refusal::Decode);
                }
                out.early_data = true;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// A ClientHello body (after the 4-byte handshake header), refused unless
/// it offers TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768 with a
/// 1216-byte share, and ecdsa_secp256r1_sha256. The checks run in the order
/// that names the most specific reason: version, suite, group, share,
/// signature, ALPN.
pub fn client_hello(body: &[u8]) -> Result<ClientHello<'_>, Refusal> {
    if body.len() > MAX_HANDSHAKE.saturating_sub(HANDSHAKE_HEADER_LEN) {
        return Err(Refusal::HandshakeTooLong);
    }
    let mut r = Reader::new(body);
    let legacy_version = r.u16()?;
    let random: &[u8; 32] = r.take(32)?.try_into().map_err(|_| Refusal::Decode)?;
    let session_id = r.vec8()?;
    if session_id.len() > MAX_SESSION_ID {
        return Err(Refusal::SessionIdTooLong);
    }
    let suites = r.vec16()?;
    if suites.is_empty() {
        return Err(Refusal::Decode);
    }
    let compression = r.vec8()?;
    let exts = walk(r.vec16()?)?;
    r.end()?;

    // A TLS 1.2-only client: no supported_versions (section 4.2.1).
    let versions = exts.supported_versions.ok_or(Refusal::NoTls13)?;
    if !list8_u16(versions)?.any(|v| v == TLS13) {
        return Err(Refusal::NoTls13);
    }
    if legacy_version != TLS12 {
        return Err(Refusal::LegacyVersion);
    }
    if !u16s(suites)?.any(|s| s == TLS_CHACHA20_POLY1305_SHA256) {
        return Err(Refusal::NoChaCha);
    }
    if compression != [0] {
        return Err(Refusal::Compression);
    }
    let groups = exts.supported_groups.ok_or(Refusal::NoPqGroup)?;
    if !list16_u16(groups)?.any(|g| g == X25519MLKEM768) {
        return Err(Refusal::NoPqGroup);
    }
    let key_share = pq_share(exts.key_share.ok_or(Refusal::NoPqShare)?)?;
    let sigs = exts.signature_algorithms.ok_or(Refusal::NoSignatureAlgorithm)?;
    if !list16_u16(sigs)?.any(|s| s == ECDSA_SECP256R1_SHA256) {
        return Err(Refusal::NoSignatureAlgorithm);
    }
    let alpn = match exts.alpn {
        Some(list) => {
            if !alpn_has_http11(list)? {
                return Err(Refusal::NoApplicationProtocol);
            }
            true
        }
        None => false,
    };
    let server_name = exts.server_name.map(host_name).transpose()?.flatten();
    if let Some(modes) = exts.psk_modes {
        let mut m = Reader::new(modes);
        if m.vec8()?.is_empty() {
            return Err(Refusal::Decode);
        }
        m.end()?;
    }
    // pre_shared_key is ignored (no ticket is ever issued), but only after
    // its structural rules: last (the walker) and with modes (4.2.9).
    if exts.pre_shared_key.is_some() && exts.psk_modes.is_none() {
        return Err(Refusal::PskWithoutModes);
    }
    Ok(ClientHello { random, session_id, key_share, alpn, server_name, early_data: exts.early_data })
}

/// A u8-length list of u16s that is non-empty and fills its extension.
fn list8_u16(data: &[u8]) -> Result<impl Iterator<Item = u16> + '_, Refusal> {
    let mut r = Reader::new(data);
    let list = r.vec8()?;
    r.end()?;
    if list.is_empty() {
        return Err(Refusal::Decode);
    }
    u16s(list)
}

/// A u16-length list of u16s that is non-empty and fills its extension.
fn list16_u16(data: &[u8]) -> Result<impl Iterator<Item = u16> + '_, Refusal> {
    let mut r = Reader::new(data);
    let list = r.vec16()?;
    r.end()?;
    if list.is_empty() {
        return Err(Refusal::Decode);
    }
    u16s(list)
}

/// key_share's client_shares (section 4.2.8): every entry well formed, no
/// group twice, at most [`MAX_KEY_SHARES`] entries, and exactly one
/// X25519MLKEM768 entry of 1216 bytes.
fn pq_share(data: &[u8]) -> Result<&[u8; CLIENT_SHARE_LEN], Refusal> {
    let mut outer = Reader::new(data);
    let shares = outer.vec16()?;
    outer.end()?;
    let mut r = Reader::new(shares);
    let mut groups = [0u16; MAX_KEY_SHARES];
    let mut count = 0usize;
    let mut found = None;
    while !r.is_empty() {
        let group = r.u16()?;
        let key = r.vec16()?;
        if key.is_empty() {
            return Err(Refusal::Decode);
        }
        if groups.get(..count).ok_or(Refusal::Internal)?.contains(&group) {
            return Err(Refusal::DuplicateKeyShare);
        }
        *groups.get_mut(count).ok_or(Refusal::Decode)? = group;
        count = count.saturating_add(1);
        if group == X25519MLKEM768 {
            found = Some(key);
        }
    }
    let key = found.ok_or(Refusal::NoPqShare)?;
    key.try_into().map_err(|_| Refusal::KeyShareLength)
}

/// ALPN's protocol_name_list (RFC 7301 section 3.1): non-empty names in a
/// non-empty list; true when http/1.1 is among them.
fn alpn_has_http11(data: &[u8]) -> Result<bool, Refusal> {
    let mut outer = Reader::new(data);
    let list = outer.vec16()?;
    outer.end()?;
    if list.is_empty() {
        return Err(Refusal::Decode);
    }
    let mut r = Reader::new(list);
    let mut found = false;
    while !r.is_empty() {
        let name = r.vec8()?;
        if name.is_empty() {
            return Err(Refusal::Decode);
        }
        found |= name == ALPN_HTTP11;
    }
    Ok(found)
}

/// server_name's list (RFC 6066 section 3): well formed; the first
/// host_name (type 0), if any.
fn host_name(data: &[u8]) -> Result<Option<&[u8]>, Refusal> {
    let mut outer = Reader::new(data);
    let list = outer.vec16()?;
    outer.end()?;
    let mut r = Reader::new(list);
    let mut first = None;
    while !r.is_empty() {
        let ty = r.u8()?;
        let name = r.vec16()?;
        if ty == 0 && first.is_none() {
            if name.is_empty() {
                return Err(Refusal::Decode);
            }
            first = Some(name);
        }
    }
    Ok(first)
}
