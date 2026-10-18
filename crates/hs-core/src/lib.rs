//! `hs` logic (plan C11): consumes handshake initiations relayed by
//! `ingress`, asks `key` for the two static-secret operations over PPC,
//! and produces the session install for `data` and the response for
//! `ingress` — in that order, so `data` knows the session before the
//! initiator can use it. Host-testable: the PPC, the clock and the
//! hardware entropy sources are traits.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod index;

use key_core::{LABEL_BOOT_SEED, LABEL_PSK_MIX, LABEL_STATIC_DH, MAX_WORDS, OK, pack32, unpack32};
use wg_core::crypto::{self, Key32};
use wg_core::noise::{Entropy, EntropyError, KeyError, PeerId, PeerTable, Reject, Responder, StaticKey};

/// One synchronous call into `key`: (label, request words) → (reply
/// label, reply word count). The PD implements it with a PPC; tests with
/// `key_core::Oracle` directly.
pub trait KeyCall {
    fn call(&mut self, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize);
}

/// `key` as wg-core's `StaticKey`. Every reply buffer is zeroed after use
/// (plan, secrets residue); refusals carry no data.
pub struct KeyClient<C: KeyCall> {
    pub call: C,
    /// Last refusal label from `key`, for auditing (e.g. rate limited).
    pub last_error: u64,
}

impl<C: KeyCall> KeyClient<C> {
    pub fn new(call: C) -> Self {
        Self { call, last_error: OK }
    }

    fn request(&mut self, label: u64, req: &[u64], want: usize, reply: &mut [u64; MAX_WORDS]) -> Result<(), KeyError> {
        let (status, n) = self.call.call(label, req, reply);
        if status != OK || n != want {
            reply.fill(0);
            self.last_error = status;
            return Err(KeyError);
        }
        Ok(())
    }

    /// The per-boot seed (fetched once at init).
    pub fn boot_seed(&mut self) -> Result<Key32, KeyError> {
        let mut reply = [0u64; MAX_WORDS];
        self.request(LABEL_BOOT_SEED, &[], key_core::BOOT_SEED_REPLY_WORDS, &mut reply)?;
        let seed = unpack32(reply.get(..4).unwrap_or(&[])).ok_or(KeyError);
        reply.fill(0);
        seed.map(Key32::from_bytes)
    }
}

fn take32(reply: &[u64], at: usize) -> Result<Key32, KeyError> {
    let words = reply.get(at..at.checked_add(4).ok_or(KeyError)?).ok_or(KeyError)?;
    unpack32(words).map(Key32::from_bytes).ok_or(KeyError)
}

impl<C: KeyCall> StaticKey for KeyClient<C> {
    fn dh(&mut self, peer_point: &[u8; 32]) -> Result<Key32, KeyError> {
        let mut reply = [0u64; MAX_WORDS];
        self.request(LABEL_STATIC_DH, &pack32(peer_point), key_core::STATIC_DH_REPLY_WORDS, &mut reply)?;
        let out = take32(&reply, 0);
        reply.fill(0);
        out
    }

    fn psk_mix(&mut self, peer: PeerId, chaining: &Key32) -> Result<(Key32, Key32, Key32), KeyError> {
        let mut req = [0u64; key_core::PSK_MIX_REQ_WORDS];
        let (head, c) = req.split_at_mut(1);
        if let Some(p) = head.first_mut() {
            *p = u64::from(peer.0);
        }
        c.copy_from_slice(&pack32(chaining.as_bytes()));
        let mut reply = [0u64; MAX_WORDS];
        let r = self.request(LABEL_PSK_MIX, &req, key_core::PSK_MIX_REPLY_WORDS, &mut reply);
        req.fill(0);
        r?;
        let out = (|| Ok((take32(&reply, 0)?, take32(&reply, 4)?, take32(&reply, 8)?)))();
        reply.fill(0);
        out
    }
}

/// Hardware inputs for ephemeral keys: a timestamp counter and RNDR.
pub trait Hardware {
    fn counter(&mut self) -> u64;
    /// One RNDR sample, or None if the source failed (fail closed).
    fn random(&mut self) -> Option<u64>;
}

/// Ephemeral-key entropy (plan, L9): each draw is
/// BLAKE2s(boot_seed ‖ draw counter ‖ CNTPCT ‖ RNDR), so it stays
/// unpredictable if either the boot seed or RNDR is sound, and never
/// repeats within a boot.
pub struct HedgedEntropy<H: Hardware> {
    seed: Key32,
    draws: u64,
    hw: H,
}

impl<H: Hardware> HedgedEntropy<H> {
    pub fn new(seed: Key32, hw: H) -> Self {
        Self { seed, draws: 0, hw }
    }
}

impl<H: Hardware> Entropy for HedgedEntropy<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in out.chunks_mut(32) {
            let rndr = self.hw.random().ok_or(EntropyError)?;
            self.draws = self.draws.checked_add(1).ok_or(EntropyError)?;
            let mut block = crypto::hash(&[
                self.seed.as_bytes(),
                &self.draws.to_le_bytes(),
                &self.hw.counter().to_le_bytes(),
                &rndr.to_le_bytes(),
            ])
            .map_err(|_| EntropyError)?;
            chunk.copy_from_slice(block.get(..chunk.len()).ok_or(EntropyError)?);
            block.fill(0);
        }
        Ok(())
    }
}

/// Configured peers by static public key (configuration order = PeerId).
pub struct Peers<'a>(pub &'a [[u8; 32]]);

impl PeerTable for Peers<'_> {
    fn lookup(&self, static_pub: &[u8; 32]) -> Option<PeerId> {
        let i = self.0.iter().position(|p| crypto::ct_eq(p, static_pub))?;
        u16::try_from(i).ok().map(PeerId)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `install` holds `msgs::Install` bytes for `data` and `response`
    /// `msgs::Response` bytes for `ingress`; send them in that order.
    Accepted { peer: PeerId, install_len: usize, response_len: usize },
    Rejected(Reject),
    /// The initiation message from `ingress` was malformed.
    BadInput,
    /// Output buffers too small (a build error, not attacker-reachable).
    NoBuffer,
}

pub struct Handshaker<const MAX_PEERS: usize> {
    responder: Responder<MAX_PEERS>,
    indices: index::Indices,
}

impl<const MAX_PEERS: usize> Handshaker<MAX_PEERS> {
    pub fn new(gateway_public: &[u8; 32], boot_seed: &Key32) -> Result<Self, crypto::CryptoError> {
        Ok(Self { responder: Responder::new(gateway_public)?, indices: index::Indices::new(boot_seed)? })
    }

    /// Handles one `msgs::Initiation`. Writes the install and response into
    /// the caller's buffers; the install buffer holds transport keys and
    /// must be zeroed by the caller after it has been copied to `data`.
    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        input: &[u8],
        now_ns: u64,
        key: &mut impl StaticKey,
        entropy: &mut impl Entropy,
        peers: &impl PeerTable,
        install: &mut [u8],
        response: &mut [u8],
    ) -> Outcome {
        let Ok(init) = msgs::Initiation::decode(input) else {
            return Outcome::BadInput;
        };
        let Some(local_index) = self.indices.next_index() else {
            return Outcome::Rejected(Reject::Entropy);
        };
        let accepted = match self.responder.consume_initiation(init.msg, now_ns, local_index, key, entropy, peers) {
            Ok(a) => a,
            Err(r) => return Outcome::Rejected(r),
        };
        let install_len = msgs::Install {
            peer: accepted.peer.0,
            local_index: accepted.responder_index,
            remote_index: accepted.initiator_index,
            created_ns: now_ns,
            send: accepted.keys.send.as_bytes(),
            recv: accepted.keys.recv.as_bytes(),
        }
        .encode(install);
        let response_len = msgs::Response { dst: init.src, msg: &accepted.response }.encode(response);
        match (install_len, response_len) {
            (Some(install_len), Some(response_len)) => {
                Outcome::Accepted { peer: accepted.peer, install_len, response_len }
            }
            _ => {
                install.fill(0);
                Outcome::NoBuffer
            }
        }
    }
}

#[cfg(test)]
mod tests;
