//! `hs` logic (plan C11): consumes handshake initiations relayed by
//! `ingress`, asks `key` for the two static-secret operations over PPC,
//! and produces the session install for `data` and the response for
//! `ingress` — in that order, so `data` knows the session before the
//! initiator can use it. Each initiation needs a fresh PSK for its peer
//! from the `PskTable`, which `pq` fills with Rosenpass OSKs (M3 plan L8).
//! Host-testable: the PPC, the clock and the hardware entropy sources are
//! traits.

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

use key_core::{LABEL_BOOT_SEED, LABEL_STATIC_DH, MAX_WORDS, OK, pack32, unpack32};
use wg_core::REJECT_AFTER_TIME_NS;
use wg_core::crypto::{self, Key32};
use wg_core::noise::{
    Entropy, EntropyError, KeyError, PeerId, PeerTable, PskRefusal, PskSource, Reject, Responder, StaticKey,
};

/// Most `key` calls one initiation can cost, over every exit of `handle`:
/// `es` and `ss`. Every exit that reaches `ss` costs exactly this, PSK
/// refusals included (M3 plan C5).
pub const KEY_CALLS_PER_HANDSHAKE: u64 = 2;

// The key budget invariant (M2.5 plan C5), checked when `hs-core` is
// built, so an image whose constants could exhaust `key` does not compile. `hs` spends key calls when it
// drains `ih`, so a burst is everything `ingress` can forward plus all that
// can wait in `ih` (NET_BUFFERS) and the one `hs` has already dequeued.
const IH_BACKLOG: u64 = layout::NET_BUFFERS as u64 + 1;
const _: () = assert!(
    (ingress_core::FORWARD_BURST + IH_BACKLOG) * KEY_CALLS_PER_HANDSHAKE
        <= key_core::KEY_BURST - key_core::KEY_BOOT_CALLS,
    "C5: forwarded burst plus ih backlog can exhaust key's bucket"
);
const _: () = assert!(
    KEY_CALLS_PER_HANDSHAKE * key_core::KEY_INTERVAL_NS <= ingress_core::FORWARD_INTERVAL_NS,
    "C5: hs can spend key calls faster than key refills"
);
const _: () = assert!(ingress_core::NET_BUFFERS == layout::NET_BUFFERS, "ingress-core NET_BUFFERS differs from layout");

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
}

/// A peer's PSK as `PskTable::fresh` found it: installed less than
/// REJECT_AFTER_TIME ago and not expired. Only `fresh` makes one, so the
/// responder cannot be handed a static, zero or stale PSK (M3 plan L8).
/// Zeroized on drop.
pub struct FreshPsk(Key32);

impl AsRef<Key32> for FreshPsk {
    fn as_ref(&self) -> &Key32 {
        &self.0
    }
}

/// One peer's PSK slot. `Expired` keeps no key at all, so no path can turn
/// an expired PSK into a zero one (M3 plan, `hs` [R4-S-P1]).
enum Entry {
    Absent,
    /// A Rosenpass OSK installed at `installed_at` (hs's clock).
    Live { osk: Key32, installed_at: u64 },
    /// A `Live` entry that the tick found REJECT_AFTER_TIME old; its OSK
    /// was zeroized. `installed_at` is kept for inspection only: no
    /// decision reads it, so it can never make the entry fresh again.
    #[allow(dead_code)] // kept for inspection only, see above
    Expired { installed_at: u64 },
}

/// A `PskInstall` that `hs` refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    Malformed,
    /// The peer index is at or beyond the table's capacity.
    PeerOutOfRange,
}

/// `peer → Entry` for every configured peer (M3 plan, `hs`).
pub struct PskTable<const MAX_PEERS: usize> {
    entries: [Entry; MAX_PEERS],
}

impl<const MAX_PEERS: usize> Default for PskTable<MAX_PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_PEERS: usize> PskTable<MAX_PEERS> {
    pub const fn new() -> Self {
        Self { entries: [const { Entry::Absent }; MAX_PEERS] }
    }

    /// Installs `osk` as `peer`'s PSK, fresh from `now_ns`. Supersedes (and
    /// zeroizes) a `Live` OSK and revives an `Expired` entry.
    pub fn install(&mut self, peer: u16, osk: &[u8; 32], now_ns: u64) -> Result<(), InstallError> {
        let entry = self.entries.get_mut(usize::from(peer)).ok_or(InstallError::PeerOutOfRange)?;
        // Assigning drops the old entry in place; `Key32` zeroizes on drop.
        *entry = Entry::Live { osk: Key32::copy_from(osk), installed_at: now_ns };
        Ok(())
    }

    /// Decodes a `msgs::PskInstall` from `pq` and installs it. Returns the
    /// peer it was for.
    pub fn install_message(&mut self, input: &[u8], now_ns: u64) -> Result<PeerId, InstallError> {
        let msg = msgs::PskInstall::decode(input).map_err(|_| InstallError::Malformed)?;
        self.install(msg.peer, msg.osk, now_ns)?;
        Ok(PeerId(msg.peer))
    }

    /// `peer`'s PSK if it is `Live` and younger than REJECT_AFTER_TIME at
    /// `now_ns`; otherwise why not.
    pub fn fresh(&self, peer: PeerId, now_ns: u64) -> Result<FreshPsk, PskRefusal> {
        match self.entries.get(usize::from(peer.0)) {
            Some(Entry::Live { osk, installed_at }) if now_ns.saturating_sub(*installed_at) < REJECT_AFTER_TIME_NS => {
                Ok(FreshPsk(Key32::copy_from(osk.as_bytes())))
            }
            Some(Entry::Live { .. } | Entry::Expired { .. }) => Err(PskRefusal::Stale),
            Some(Entry::Absent) | None => Err(PskRefusal::Missing),
        }
    }

    /// The expiry tick (law L12): every `Live` entry at or past
    /// REJECT_AFTER_TIME becomes `Expired`, zeroizing its OSK.
    pub fn tick(&mut self, now_ns: u64) {
        for entry in &mut self.entries {
            if let Entry::Live { installed_at, .. } = *entry
                && now_ns.saturating_sub(installed_at) >= REJECT_AFTER_TIME_NS
            {
                *entry = Entry::Expired { installed_at };
            }
        }
    }
}

impl<const MAX_PEERS: usize> PskSource for PskTable<MAX_PEERS> {
    type Psk = FreshPsk;
    fn fresh(&self, peer: PeerId, now_ns: u64) -> Result<FreshPsk, PskRefusal> {
        PskTable::fresh(self, peer, now_ns)
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
        psks: &PskTable<MAX_PEERS>,
        install: &mut [u8],
        response: &mut [u8],
    ) -> Outcome {
        let Ok(init) = msgs::Initiation::decode(input) else {
            return Outcome::BadInput;
        };
        let indices = &mut self.indices;
        let accepted = match self.responder.consume_initiation(init.msg, now_ns, || indices.next_index(), key, entropy, peers, psks) {
            Ok(a) => a,
            Err(r) => return Outcome::Rejected(r),
        };
        let install_len = msgs::Install {
            peer: accepted.peer.0,
            local_index: accepted.responder_index,
            remote_index: accepted.initiator_index,
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

/// The audit event for a rejected handshake. `key_error` is
/// `KeyClient::last_error`, which tells key-budget exhaustion apart from
/// other refusals (C10: exhaustion is audited).
pub fn reject_event(r: Reject, key_error: u64) -> audit_event::Event {
    use audit_event::Event;
    match r {
        Reject::UnknownPeer => Event::HandshakeUnknownPeer,
        Reject::Decrypt => Event::HandshakeDecrypt,
        Reject::Replay => Event::HandshakeReplay,
        Reject::Flood => Event::HandshakeFlood,
        Reject::Psk(PskRefusal::Missing) => Event::HandshakePskMissing,
        Reject::Psk(PskRefusal::Stale) => Event::HandshakePskStale,
        Reject::Key(_) if key_error == key_core::ERR_RATE_LIMITED => Event::HandshakeKeyRateLimited,
        Reject::Key(_) => Event::HandshakeKeyRefused,
        Reject::Malformed(_)
        | Reject::BadMac1
        | Reject::ZeroDh
        | Reject::PeerOutOfRange
        | Reject::Entropy
        | Reject::IndexExhausted
        | Reject::Crypto(_) => Event::HandshakeOther,
    }
}

#[cfg(test)]
mod tests;
