//! The PD's `RpCookieCheck` (M3b plan C3): owns the current and previous
//! Rosenpass cookie secrets, which never leave this struct, and plugs
//! rosenpass-core's cookie functions into `RpGate`. Free of seL4 and of
//! ingress-core's PD types, so it builds on the host.

use ingress_core::{Endpoint, RP_COOKIE_REPLY_LEN, RP_INIT_HELLO_LEN, RpCookieCheck};
use rosenpass_core::cookie::{self, COOKIE_SECRET_LEN, MAC_LEN};
use rosenpass_core::{SPK_LEN, Secret};
use rosenpass_wire::{SID_LEN, mac_offset};

pub struct RpCookieAdapter {
    current: Option<Secret<COOKIE_SECRET_LEN>>,
    /// Accepted for one epoch after a rotation, so a client's 120 s cookie
    /// survives the gateway's rotation (upstream does the same).
    previous: Option<Secret<COOKIE_SECRET_LEN>>,
    /// `KH("cookie-key", spkm)`: public, like the mac key.
    key: [u8; 32],
    /// Replies sealed under the current secret; the nonce's input.
    counter: u64,
    /// Fills the secret in place; returns false on failure.
    fill: fn(&mut [u8]) -> bool,
}

impl RpCookieAdapter {
    /// Holds no secret until the first successful `rotate`.
    pub fn new(spkm: &[u8; SPK_LEN], fill: fn(&mut [u8]) -> bool) -> Self {
        Self { current: None, previous: None, key: cookie::cookie_key(spkm), counter: 0, fill }
    }
}

fn host(src: Endpoint) -> [u8; cookie::HOST_INFO_LEN] {
    cookie::host_info(src.ip, src.port)
}

impl RpCookieCheck for RpCookieAdapter {
    fn valid(&self, src: Endpoint, msg: &[u8; RP_INIT_HELLO_LEN]) -> bool {
        cookie::cookie_valid([self.current.as_ref(), self.previous.as_ref()], &host(src), msg)
    }

    fn seal(&mut self, src: Endpoint, msg: &[u8; RP_INIT_HELLO_LEN], out: &mut [u8; RP_COOKIE_REPLY_LEN]) -> bool {
        let Some(current) = self.current.as_ref() else {
            return false;
        };
        let (Some(sidi), Some(mac)) = (
            msg.get(rosenpass_wire::HEADER_LEN..).and_then(|m| m.first_chunk::<SID_LEN>()),
            msg.get(mac_offset(RP_INIT_HELLO_LEN)..).and_then(|m| m.first_chunk::<MAC_LEN>()),
        ) else {
            return false;
        };
        // A nonce is never derived twice under one secret; at the
        // (unreachable) end of the counter, replies stop until the next
        // rotation.
        let Some(next) = self.counter.checked_add(1) else {
            return false;
        };
        let nonce = cookie::reply_nonce(current, self.counter);
        self.counter = next;
        let value = cookie::cookie_value(current, &host(src));
        cookie::seal_cookie_reply(&self.key, *sidi, &nonce, &value, mac, out).is_ok()
    }

    /// The current secret becomes the previous one (the old previous is
    /// zeroized on drop), then a fresh one is drawn. A failed draw clears
    /// both: no stale secret is ever used.
    fn rotate(&mut self) -> bool {
        let mut fresh = Secret::zero();
        if !(self.fill)(fresh.expose_mut()) {
            self.clear();
            return false;
        }
        self.previous = self.current.replace(fresh);
        self.counter = 0;
        true
    }

    fn clear(&mut self) {
        self.current = None;
        self.previous = None;
    }
}
