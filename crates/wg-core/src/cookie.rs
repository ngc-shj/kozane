//! Responder side of WireGuard cookies (whitepaper section 5.4.7):
//! `cookie = MAC(secret, ip || port_be16)`, mac2 = MAC(cookie, msg[..132])
//! with the 16-byte cookie as the key, and the type-3 cookie reply.
//!
//! The port's byte order is local and opaque to the initiator; we use
//! big-endian, as the Linux module does. The reply nonce is
//! `HASH(secret || counter_le64)[..24]`, unique per counter within one
//! secret's lifetime, so RNDR is read only to make a secret.

use wg_wire::{COOKIE_REPLY_LEN, CookieReply, INITIATION_LEN, INITIATION_MAC2_OFFSET};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, CryptoError, KEY_LEN, Key32, MAC_LEN, XNONCE_LEN};
use crate::noise::LABEL_COOKIE;

/// HASH("cookie--" || S_pub): the cookie reply key. Public, like the mac1 key.
pub fn cookie_key(gw_public: &[u8; KEY_LEN]) -> Result<Key32, CryptoError> {
    crypto::hash(&[LABEL_COOKIE, gw_public]).map(Key32::from_bytes)
}

/// The cookie secret, filled in place. Valid only after a successful
/// `fill`; without that flag a zeroed secret would let anyone compute
/// cookies. Not `Copy`/`Clone`/`Debug`; zeroized on drop.
pub struct CookieSecret {
    bytes: [u8; KEY_LEN],
    valid: bool,
}

impl CookieSecret {
    pub const fn new() -> Self {
        Self { bytes: [0; KEY_LEN], valid: false }
    }

    /// Runs `fill` on the secret's own storage. On `false` the secret is
    /// zeroed and stays invalid.
    pub fn fill(&mut self, fill: impl FnOnce(&mut [u8; KEY_LEN]) -> bool) -> bool {
        self.valid = false;
        let ok = fill(&mut self.bytes);
        if !ok {
            self.bytes.zeroize();
        }
        self.valid = ok;
        ok
    }

    pub fn clear(&mut self) {
        self.valid = false;
        self.bytes.zeroize();
    }

    fn get(&self) -> Option<&[u8; KEY_LEN]> {
        self.valid.then_some(&self.bytes)
    }
}

impl Default for CookieSecret {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CookieSecret {
    fn drop(&mut self) {
        self.clear();
    }
}

impl ZeroizeOnDrop for CookieSecret {}

/// A cookie: a bearer token for one (ip, port). Not `Copy`/`Clone`/`Debug`;
/// zeroized on drop.
pub struct Cookie([u8; MAC_LEN]);

impl Drop for Cookie {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Cookie {}

/// `None` without a valid secret.
pub fn make_cookie(secret: &CookieSecret, ip: [u8; 4], port: u16) -> Option<Cookie> {
    crypto::mac(secret.get()?, &[&ip, &port.to_be_bytes()]).ok().map(Cookie)
}

/// Fail-closed: an error in the MAC counts as invalid.
pub fn mac2_valid(cookie: &Cookie, msg: &[u8; INITIATION_LEN]) -> bool {
    let Some((covered, mac2)) = msg.split_at_checked(INITIATION_MAC2_OFFSET) else {
        return false;
    };
    crypto::mac16(&cookie.0, &[covered]).is_ok_and(|m| crypto::ct_eq(&m, mac2))
}

/// `None` without a valid secret.
pub fn reply_nonce(secret: &CookieSecret, counter: u64) -> Option<[u8; XNONCE_LEN]> {
    let h = crypto::hash(&[secret.get()?, &counter.to_le_bytes()]).ok()?;
    h.first_chunk::<XNONCE_LEN>().copied()
}

/// The full type-3 message: header, `receiver` (the initiation's sender
/// index), `nonce`, then XAEAD(key, nonce, cookie, aad = initiation mac1).
pub fn seal_cookie_reply(
    key: &Key32,
    receiver: u32,
    nonce: &[u8; XNONCE_LEN],
    cookie: &Cookie,
    mac1: &[u8; MAC_LEN],
) -> Result<[u8; COOKIE_REPLY_LEN], CryptoError> {
    let mut reply = CookieReply { receiver, nonce: *nonce, encrypted_cookie: [0; MAC_LEN + crypto::TAG_LEN] };
    crypto::xaead_seal(key, nonce, &cookie.0, mac1, &mut reply.encrypted_cookie)?;
    let mut out = [0u8; COOKIE_REPLY_LEN];
    reply.emit(&mut out).map_err(|_| CryptoError::Buffer)?;
    Ok(out)
}
