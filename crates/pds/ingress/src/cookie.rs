//! The PD's `CookieCrypto` (plan C1, C3 [M7]): owns the cookie secret, which
//! never leaves this struct, and plugs wg-core's cookie primitives into the
//! Gate. Kept free of seL4 so it can be built on the host.

use ingress_core::{CookieCrypto, Endpoint};
use wg_core::cookie::{self, CookieSecret};
use wg_core::crypto::{CryptoError, Key32};
use wg_core::wire::{COOKIE_REPLY_LEN, INITIATION_LEN, MessageInitiation};

pub struct CookieAdapter {
    secret: CookieSecret,
    /// HASH("cookie--" ‖ S_pub): public, like the mac1 key.
    key: Key32,
    /// Replies sealed under the current secret; the reply nonce's input.
    counter: u64,
    /// Fills the secret in place; zeroes it and returns false on failure.
    fill: fn(&mut [u8]) -> bool,
}

impl CookieAdapter {
    /// Holds no valid secret until the first successful `rotate`.
    pub fn new(gw_public: &[u8; 32], fill: fn(&mut [u8]) -> bool) -> Result<Self, CryptoError> {
        Ok(Self { secret: CookieSecret::new(), key: cookie::cookie_key(gw_public)?, counter: 0, fill })
    }
}

impl CookieCrypto for CookieAdapter {
    fn rotate(&mut self) -> bool {
        let fill = self.fill;
        let ok = self.secret.fill(|b| fill(b));
        if ok {
            self.counter = 0;
        }
        ok
    }

    fn clear(&mut self) {
        self.secret.clear();
    }

    fn mac2_valid(&self, src: Endpoint, msg: &[u8; INITIATION_LEN]) -> bool {
        cookie::make_cookie(&self.secret, src.ip, src.port).is_some_and(|c| cookie::mac2_valid(&c, msg))
    }

    fn seal_reply(&mut self, src: Endpoint, msg: &[u8; INITIATION_LEN], out: &mut [u8; COOKIE_REPLY_LEN]) -> bool {
        let Ok(init) = MessageInitiation::parse(msg) else {
            return false;
        };
        let Some(nonce) = cookie::reply_nonce(&self.secret, self.counter) else {
            return false;
        };
        // A nonce is never derived twice under one secret; at the (unreachable)
        // end of the counter, replies stop until the next rotation.
        let Some(next) = self.counter.checked_add(1) else {
            return false;
        };
        self.counter = next;
        let Some(c) = cookie::make_cookie(&self.secret, src.ip, src.port) else {
            return false;
        };
        match cookie::seal_cookie_reply(&self.key, init.sender, &nonce, &c, &init.mac1) {
            Ok(reply) => {
                *out = reply;
                true
            }
            Err(_) => false,
        }
    }
}
