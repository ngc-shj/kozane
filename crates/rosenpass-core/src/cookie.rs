//! Rosenpass's cookie mechanism (M3b plan C1; upstream `9e72f1eb`
//! `hash_domains.rs` cookie domains, `protocol.rs` `handle_msg_under_load`
//! and `handle_cookie_reply`).
//!
//! Cookies always hash with keyed SHAKE256, whatever the protocol version
//! (whitepaper L610), so this is a hash tree of its own, rooted at the
//! SHAKE256 protocol string and separate from `Domains::v02`'s BLAKE2b tree.
//! `KH(k, d)` is SHAKE256(k ‖ d) read out to 32 bytes; `mix(x)` replaces
//! the key with `KH(key, x)`, as upstream's `HashDomain::mix`.

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::Secret;
use crate::crypto::{self, CryptoError, KEY_LEN, TAG_LEN, XNONCE_LEN};

/// The protocol string of the cookie tree (`hash_domains::protocol` with
/// SHAKE256 and Kyber-512, as upstream's cookie code passes them).
pub const PROTOCOL_SHAKE: &[u8] = b"Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 SHAKE256";

/// `COOKIE_SECRET_LEN`, `COOKIE_VALUE_LEN` and the envelope cookie field
/// are all upstream's `MAC_SIZE`.
pub const COOKIE_SECRET_LEN: usize = 16;
pub const COOKIE_VALUE_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;
pub const MAC_LEN: usize = 16;

/// The responder's identification of a sender: the IPv4-mapped IPv6
/// address and the port, big-endian. Upstream leaves its encoding to the
/// responder (whitepaper L610), so this need only be unambiguous.
pub const HOST_INFO_LEN: usize = 18;

/// The CookieReply: `type ‖ reserved[3] ‖ sid[4] ‖ nonce[24] ‖
/// XAEAD(cookie_value) ‖ tag[16]`, zero-padded to the InitHello's length
/// so it never amplifies (upstream `msgs.rs` `CookieReply`).
pub const COOKIE_REPLY_LEN: usize = rosenpass_wire::INIT_HELLO_LEN;
pub const MSG_COOKIE_REPLY: u8 = rosenpass_wire::MSG_COOKIE_REPLY;
const SID_AT: usize = 4;
const SEALED_AT: usize = 8;
const SEALED_LEN: usize = XNONCE_LEN + COOKIE_VALUE_LEN + TAG_LEN;

const _: () = assert!(SEALED_AT + SEALED_LEN <= COOKIE_REPLY_LEN);

/// KH over keyed SHAKE256 (upstream `SHAKE256Core::keyed_hash`).
fn kh_shake(key: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; KEY_LEN]) {
    let mut h = Shake256::default();
    h.update(key);
    h.update(data);
    h.finalize_xof().read(out);
}

/// A key on the cookie tree, `mix`ed from the root down.
struct Shake([u8; KEY_LEN]);

impl Shake {
    fn root() -> Self {
        Self([0; KEY_LEN]).mix(PROTOCOL_SHAKE)
    }

    fn mix(self, v: &[u8]) -> Self {
        let mut next = [0u8; KEY_LEN];
        kh_shake(&self.0, v, &mut next);
        Self(next)
    }
}

/// The tree's root, for the golden-vector test only.
#[cfg(test)]
pub(crate) fn cookie_key_root_for_test() -> [u8; KEY_LEN] {
    Shake::root().0
}

/// `cookie_key = root.mix("cookie-key").mix(spkm)`: public, like the mac
/// key. The initiator derives the same from its `spkt`.
pub fn cookie_key(spkm: &[u8; crate::SPK_LEN]) -> [u8; KEY_LEN] {
    Shake::root().mix(b"cookie-key").mix(spkm).0
}

/// `cookie_value = root.mix("cookie-value").mix(secret).mix(host)[..16]`.
pub fn cookie_value(secret: &Secret<COOKIE_SECRET_LEN>, host: &[u8; HOST_INFO_LEN]) -> Secret<COOKIE_VALUE_LEN> {
    let mut full = Shake::root().mix(b"cookie-value").mix(secret.expose()).mix(host).0;
    let mut v = Secret::zero();
    if let Some(head) = full.first_chunk::<COOKIE_VALUE_LEN>() {
        v.expose_mut().copy_from_slice(head);
    }
    zeroize::Zeroize::zeroize(&mut full);
    v
}

/// `cookie = root.mix("cookie").mix(value).mix(msg[..cookie])[..16]`: the
/// envelope's cookie field for a message whose bytes before that field are
/// `msg_before_cookie`.
pub fn cookie_field(value: &Secret<COOKIE_VALUE_LEN>, msg_before_cookie: &[u8]) -> [u8; COOKIE_LEN] {
    let full = Shake::root().mix(b"cookie").mix(value.expose()).mix(msg_before_cookie).0;
    let mut c = [0u8; COOKIE_LEN];
    if let Some(head) = full.first_chunk::<COOKIE_LEN>() {
        c = *head;
    }
    c
}

/// Whether `msg`'s envelope cookie field is valid for `host` under either
/// secret (the current one, and the previous one for one epoch).
///
/// Constant time per secret, and both are always evaluated: no early exit
/// says which secret matched. An absent secret, or a message too short to
/// hold a cookie, is invalid (M3b plan C1, S3).
pub fn cookie_valid(
    secrets: [Option<&Secret<COOKIE_SECRET_LEN>>; 2],
    host: &[u8; HOST_INFO_LEN],
    msg: &[u8],
) -> bool {
    let Some(cut) = msg.len().checked_sub(COOKIE_LEN) else {
        return false;
    };
    let (before, got) = msg.split_at(cut);
    let mut ok = false;
    for secret in secrets.into_iter().flatten() {
        let want = cookie_field(&cookie_value(secret, host), before);
        ok |= crypto::ct_eq(&want, got);
    }
    ok
}

/// Writes the CookieReply to a message whose sender id is `sidi` and whose
/// envelope mac is `mac`: the cookie value sealed under the public cookie
/// key with that mac as associated data, so only a holder of the message's
/// mac (its sender, or an on-path observer) can open it.
pub fn seal_cookie_reply(
    key: &[u8; KEY_LEN],
    sidi: [u8; 4],
    nonce: &[u8; XNONCE_LEN],
    value: &Secret<COOKIE_VALUE_LEN>,
    mac: &[u8; MAC_LEN],
    out: &mut [u8; COOKIE_REPLY_LEN],
) -> Result<(), CryptoError> {
    out.fill(0);
    let head = out.first_chunk_mut::<SEALED_AT>().ok_or(CryptoError::Buffer)?;
    if let Some(t) = head.first_mut() {
        *t = MSG_COOKIE_REPLY;
    }
    let sid = head.get_mut(SID_AT..SEALED_AT).ok_or(CryptoError::Buffer)?;
    sid.copy_from_slice(&sidi);
    let sealed = out.get_mut(SEALED_AT..SEALED_AT + SEALED_LEN).ok_or(CryptoError::Buffer)?;
    crypto::xaead_seal(&Secret::copy_from(key), nonce, mac, value.expose(), sealed)
}

/// The CookieReply nonce for the `counter`-th reply under `secret`: never
/// repeated under one secret, and unpredictable without it. Local to the
/// responder (upstream draws a random one), so it carries a kozane label.
pub fn reply_nonce(secret: &Secret<COOKIE_SECRET_LEN>, counter: u64) -> [u8; XNONCE_LEN] {
    let full = Shake::root().mix(b"kozane cookie reply nonce").mix(secret.expose()).mix(&counter.to_le_bytes()).0;
    let mut n = [0u8; XNONCE_LEN];
    if let Some(head) = full.first_chunk::<XNONCE_LEN>() {
        n = *head;
    }
    n
}

/// Encodes a sender's endpoint as `host_info`.
pub fn host_info(ip: [u8; 4], port: u16) -> [u8; HOST_INFO_LEN] {
    let mut h = [0u8; HOST_INFO_LEN];
    // ::ffff:a.b.c.d
    let [a, b, c, d] = ip;
    if let Some(mapped) = h.get_mut(10..16) {
        mapped.copy_from_slice(&[0xff, 0xff, a, b, c, d]);
    }
    if let Some(p) = h.get_mut(16..18) {
        p.copy_from_slice(&port.to_be_bytes());
    }
    h
}
