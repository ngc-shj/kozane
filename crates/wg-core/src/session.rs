//! Transport data keys for one handshake (whitepaper section 5.4.6) with
//! the REJECT_AFTER_TIME / REJECT_AFTER_MESSAGES limits. Slot rules
//! (next/current/previous) belong to the `data` PD.

use wg_wire::replay::ReplayWindow;

use crate::crypto::{self, CryptoError, Key32};
use crate::noise::SessionKeys;
use crate::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME_NS};

pub const REPLAY_BITS: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// REJECT_AFTER_TIME has passed; the keys have been zeroized.
    Expired,
    /// Counter at or beyond REJECT_AFTER_MESSAGES.
    CounterLimit,
    /// Tag mismatch.
    Auth,
    /// Authentic, but the counter was already seen or is too old.
    Replay,
    /// Buffer too small or ciphertext shorter than a tag.
    Buffer,
}

/// Dropping a `Session` zeroizes both keys.
pub struct Session {
    recv_key: Key32,
    send_key: Key32,
    /// Our index: the receiver index on packets sent to us.
    pub recv_index: u32,
    /// Their index: the receiver index we put on packets we send.
    pub send_index: u32,
    pub created_ns: u64,
    send_counter: u64,
    replay: ReplayWindow<REPLAY_BITS>,
    /// Highest counter `open` has accepted (drives roaming in `data`).
    highest_received: Option<u64>,
}

impl Session {
    pub fn new(keys: SessionKeys, recv_index: u32, send_index: u32, created_ns: u64) -> Self {
        let SessionKeys { send, recv } = keys;
        Self {
            recv_key: recv,
            send_key: send,
            recv_index,
            send_index,
            created_ns,
            send_counter: 0,
            replay: ReplayWindow::new(),
            highest_received: None,
        }
    }

    /// True once REJECT_AFTER_TIME has elapsed since `created_ns`.
    pub fn expired(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.created_ns) >= REJECT_AFTER_TIME_NS
    }

    /// Highest counter accepted by `open` so far; `None` before the first.
    pub fn highest_received(&self) -> Option<u64> {
        self.highest_received
    }

    fn check_live(&mut self, now_ns: u64) -> Result<(), SessionError> {
        if self.expired(now_ns) {
            self.recv_key = Key32::zero();
            self.send_key = Key32::zero();
            return Err(SessionError::Expired);
        }
        Ok(())
    }

    /// Decrypts a transport payload (ciphertext || tag) into `out` and
    /// returns the plaintext length. The replay window is updated only
    /// after the tag verifies; on `Replay` the plaintext is wiped.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut [u8],
        now_ns: u64,
    ) -> Result<usize, SessionError> {
        self.check_live(now_ns)?;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(SessionError::CounterLimit);
        }
        let n = crypto::aead_open(&self.recv_key, counter, ciphertext, &[], out).map_err(|e| match e {
            CryptoError::Auth => SessionError::Auth,
            _ => SessionError::Buffer,
        })?;
        if !self.replay.check_and_update(counter) {
            if let Some(p) = out.get_mut(..n) {
                p.fill(0);
            }
            return Err(SessionError::Replay);
        }
        self.highest_received = self.highest_received.max(Some(counter));
        Ok(n)
    }

    /// Encrypts `plaintext` into `out` (ciphertext || tag) under the next
    /// send counter; returns `(counter, length)`.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8], now_ns: u64) -> Result<(u64, usize), SessionError> {
        self.check_live(now_ns)?;
        let counter = self.send_counter;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(SessionError::CounterLimit);
        }
        let n = crypto::aead_seal(&self.send_key, counter, plaintext, &[], out)
            .map_err(|_| SessionError::Buffer)?;
        self.send_counter = counter.checked_add(1).ok_or(SessionError::CounterLimit)?;
        Ok((counter, n))
    }

    #[cfg(test)]
    pub(crate) fn set_send_counter(&mut self, c: u64) {
        self.send_counter = c;
    }
}
