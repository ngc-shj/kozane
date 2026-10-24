//! The server's messages (RFC 8446 section 4), each written as a whole
//! handshake message (header included) into a caller buffer. A buffer too
//! small is `Refusal::Internal`; nothing is written past `out`.

use crate::der::{MAX_SIG_LEN, ecdsa_sig_value};
use crate::{
    ALPN_HTTP11, Alert, ContentType, ECDSA_SECP256R1_SHA256, HANDSHAKE_HEADER_LEN, HASH_LEN, MAX_SESSION_ID,
    RECORD_HEADER_LEN, Refusal, SERVER_SHARE_LEN, TLS12, TLS13, TLS_CHACHA20_POLY1305_SHA256, X25519MLKEM768, ext, hs,
};

/// Largest certificate the Certificate message carries: its 24-bit field.
pub const MAX_CERT_LEN: usize = (1 << 24) - 1 - 3 - 2;

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let end = self.at.checked_add(bytes.len()).ok_or(Refusal::Internal)?;
        self.out.get_mut(self.at..end).ok_or(Refusal::Internal)?.copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn u16(&mut self, v: u16) -> Result<(), Refusal> {
        self.put(&v.to_be_bytes())
    }

    fn u24(&mut self, v: usize) -> Result<(), Refusal> {
        let v = u32::try_from(v).ok().filter(|&v| v < 1 << 24).ok_or(Refusal::Internal)?;
        let [_, a, b, c] = v.to_be_bytes();
        self.put(&[a, b, c])
    }

    fn len16(n: usize) -> Result<u16, Refusal> {
        u16::try_from(n).map_err(|_| Refusal::Internal)
    }

    /// A handshake header whose length is the bytes written by `body`.
    fn message(mut self, msg_type: u8, body: impl FnOnce(&mut Self) -> Result<(), Refusal>) -> Result<usize, Refusal> {
        let start = self.at;
        self.put(&[msg_type, 0, 0, 0])?;
        body(&mut self)?;
        let len = self.at.checked_sub(start).and_then(|n| n.checked_sub(HANDSHAKE_HEADER_LEN)).ok_or(Refusal::Internal)?;
        let v = u32::try_from(len).ok().filter(|&v| v < 1 << 24).ok_or(Refusal::Internal)?;
        let [_, a, b, c] = v.to_be_bytes();
        let field = start.checked_add(1).ok_or(Refusal::Internal)?;
        let end = field.checked_add(3).ok_or(Refusal::Internal)?;
        self.out.get_mut(field..end).ok_or(Refusal::Internal)?.copy_from_slice(&[a, b, c]);
        Ok(self.at)
    }
}

/// ServerHello (section 4.1.3): legacy_version 0x0303, the session id
/// echoed, TLS_CHACHA20_POLY1305_SHA256, no compression, supported_versions
/// TLS 1.3 and the X25519MLKEM768 key share.
pub fn server_hello(
    out: &mut [u8],
    random: &[u8; 32],
    session_id: &[u8],
    share: &[u8; SERVER_SHARE_LEN],
) -> Result<usize, Refusal> {
    if session_id.len() > MAX_SESSION_ID {
        return Err(Refusal::Internal);
    }
    Writer::new(out).message(hs::SERVER_HELLO, |w| {
        w.u16(TLS12)?;
        w.put(random)?;
        w.put(&[u8::try_from(session_id.len()).map_err(|_| Refusal::Internal)?])?;
        w.put(session_id)?;
        w.u16(TLS_CHACHA20_POLY1305_SHA256)?;
        w.put(&[0])?;
        // supported_versions (6) and key_share (4 + 4 + share).
        let share_ext = SERVER_SHARE_LEN + 4;
        w.u16(Writer::len16(6 + 4 + share_ext)?)?;
        w.u16(ext::SUPPORTED_VERSIONS)?;
        w.u16(2)?;
        w.u16(TLS13)?;
        w.u16(ext::KEY_SHARE)?;
        w.u16(Writer::len16(share_ext)?)?;
        w.u16(X25519MLKEM768)?;
        w.u16(Writer::len16(SERVER_SHARE_LEN)?)?;
        w.put(share)
    })
}

/// EncryptedExtensions (section 4.3.1): ALPN with http/1.1 when the client
/// offered ALPN, else empty.
pub fn encrypted_extensions(out: &mut [u8], alpn: bool) -> Result<usize, Refusal> {
    Writer::new(out).message(hs::ENCRYPTED_EXTENSIONS, |w| {
        if !alpn {
            return w.u16(0);
        }
        const NAME: usize = ALPN_HTTP11.len();
        // ext type, ext len, list len, name len, name.
        w.u16(Writer::len16(4 + 2 + 1 + NAME)?)?;
        w.u16(ext::ALPN)?;
        w.u16(Writer::len16(2 + 1 + NAME)?)?;
        w.u16(Writer::len16(1 + NAME)?)?;
        w.put(&[u8::try_from(NAME).map_err(|_| Refusal::Internal)?])?;
        w.put(ALPN_HTTP11)
    })
}

/// Certificate (section 4.4.2): empty context, one X.509 entry, no
/// extensions.
pub fn certificate(out: &mut [u8], der: &[u8]) -> Result<usize, Refusal> {
    if der.is_empty() || der.len() > MAX_CERT_LEN {
        return Err(Refusal::Internal);
    }
    Writer::new(out).message(hs::CERTIFICATE, |w| {
        w.put(&[0])?;
        w.u24(der.len().checked_add(5).ok_or(Refusal::Internal)?)?;
        w.u24(der.len())?;
        w.put(der)?;
        w.u16(0)
    })
}

/// CertificateVerify (section 4.4.3): ecdsa_secp256r1_sha256 and the DER
/// signature from r ‖ s.
pub fn certificate_verify(out: &mut [u8], r_s: &[u8; 64]) -> Result<usize, Refusal> {
    let mut sig = [0u8; MAX_SIG_LEN];
    let n = ecdsa_sig_value(r_s, &mut sig)?;
    let sig = sig.get(..n).ok_or(Refusal::Internal)?;
    Writer::new(out).message(hs::CERTIFICATE_VERIFY, |w| {
        w.u16(ECDSA_SECP256R1_SHA256)?;
        w.u16(Writer::len16(sig.len())?)?;
        w.put(sig)
    })
}

/// Finished (section 4.4.4).
pub fn finished(out: &mut [u8], verify_data: &[u8; HASH_LEN]) -> Result<usize, Refusal> {
    Writer::new(out).message(hs::FINISHED, |w| w.put(verify_data))
}

/// KeyUpdate (section 4.6.3) with request_update 0 or 1.
pub fn key_update(out: &mut [u8], request_update: bool) -> Result<usize, Refusal> {
    Writer::new(out).message(hs::KEY_UPDATE, |w| w.put(&[u8::from(request_update)]))
}

/// An alert body: close_notify is a warning, every other alert fatal.
pub const fn alert(desc: Alert) -> [u8; 2] {
    let level = if matches!(desc, Alert::CloseNotify) { 1 } else { 2 };
    [level, desc as u8]
}

/// A record header with legacy_record_version 0x0303.
pub fn record_header(content_type: ContentType, len: usize) -> Result<[u8; RECORD_HEADER_LEN], Refusal> {
    let [a, b] = u16::try_from(len).map_err(|_| Refusal::Internal)?.to_be_bytes();
    let [v0, v1] = TLS12.to_be_bytes();
    Ok([content_type as u8, v0, v1, a, b])
}
