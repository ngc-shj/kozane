//! Responder side of Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s as used by
//! WireGuard (whitepaper sections 5.4.2 - 5.4.5).
//!
//! The gateway's static private key never enters this module:
//! `StaticKey::dh` computes `DH(S_priv, point)`. The IKpsk2 PSK `Q` comes
//! only from a `PskSource`, which hands out a PSK it vouches is fresh or
//! refuses (M3 plan L8); there is no static or default PSK, and the
//! responder mixes `Q` itself. This module ignores mac2 on
//! input: `ingress` verifies it under load, through `crate::cookie`, before
//! an initiation reaches `hs`. Responses carry mac2 = 0, since the gateway
//! never needs a cookie from its peers (SC19).

use wg_wire::{
    INITIATION_MAC1_OFFSET, MessageInitiation, MessageResponse, RESPONSE_LEN, RESPONSE_MAC1_OFFSET,
    WireError,
};

use crate::crypto::{self, CryptoError, Key32};

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Accept at most one initiation per peer per 1/50 s.
pub const INITIATION_MIN_INTERVAL_NS: u64 = 1_000_000_000 / 50;

pub const TAI64N_LEN: usize = 12;

/// Index of a configured peer; the responder keeps per-peer state at this index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

/// Holder of the gateway's static private key.
pub trait StaticKey {
    /// `DH(S_priv, peer_point)`.
    fn dh(&mut self, peer_point: &[u8; 32]) -> Result<Key32, KeyError>;
}

/// Why a `PskSource` gave no PSK for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskRefusal {
    /// No PSK was ever installed for the peer.
    Missing,
    /// The peer's PSK is REJECT_AFTER_TIME old or older, or has expired.
    Stale,
}

/// The per-peer PSKs (M3 plan L8). `fresh` is asked once per initiation,
/// after the sender has authenticated and passed the replay and flood
/// checks and before they are committed, so a refusal commits nothing.
/// `Psk` is the source's own proof of freshness; the responder only reads
/// its bytes, as the IKpsk2 `Q`.
pub trait PskSource {
    type Psk: AsRef<Key32>;
    fn fresh(&self, peer: PeerId, now_ns: u64) -> Result<Self::Psk, PskRefusal>;
}

pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;
}

pub trait PeerTable {
    fn lookup(&self, static_pub: &[u8; 32]) -> Option<PeerId>;
}

/// Responder transport keys: `(recv, send) = KDF2(C, empty)`, i.e. the
/// initiator's `(T_send, T_recv)` swapped.
pub struct SessionKeys {
    pub send: Key32,
    pub recv: Key32,
}

pub struct Accepted {
    /// Handshake response with mac1 keyed to the initiator's static key, mac2 zero.
    pub response: [u8; RESPONSE_LEN],
    pub keys: SessionKeys,
    pub peer: PeerId,
    /// The initiator's sender index: the receiver index of our transport packets.
    pub initiator_index: u32,
    /// Our sender index, as passed to `consume_initiation`.
    pub responder_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Malformed(WireError),
    BadMac1,
    /// A DH result was all zero (low-order point).
    ZeroDh,
    Key(KeyError),
    /// The encrypted static key or timestamp failed to authenticate.
    Decrypt,
    UnknownPeer,
    /// `PeerTable` returned an id at or beyond the responder's capacity.
    PeerOutOfRange,
    /// TAI64N not greater than the last accepted one for this peer.
    Replay,
    /// Less than `INITIATION_MIN_INTERVAL_NS` since this peer's last accepted initiation.
    Flood,
    /// The `PskSource` holds no fresh PSK for this peer.
    Psk(PskRefusal),
    Entropy,
    /// No receiver index left to issue (after 2^32 accepted handshakes).
    IndexExhausted,
    Crypto(CryptoError),
}

impl From<CryptoError> for Reject {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::ZeroDh => Reject::ZeroDh,
            CryptoError::Auth => Reject::Decrypt,
            e => Reject::Crypto(e),
        }
    }
}

#[derive(Clone, Copy)]
struct PeerState {
    last_timestamp: [u8; TAI64N_LEN],
    last_accept_ns: Option<u64>,
}

pub struct Responder<const MAX_PEERS: usize> {
    /// HASH(CONSTRUCTION): the initial chaining key (public).
    ck0: [u8; 32],
    /// HASH(HASH(ck0 || IDENTIFIER) || S_pub).
    h0: [u8; 32],
    /// HASH(LABEL_MAC1 || S_pub).
    mac1_key: [u8; 32],
    peers: [PeerState; MAX_PEERS],
}

fn key_dh(key: &mut impl StaticKey, point: &[u8; 32]) -> Result<Key32, Reject> {
    let out = key.dh(point).map_err(Reject::Key)?;
    if out.is_zero() {
        return Err(Reject::ZeroDh);
    }
    Ok(out)
}

impl<const MAX_PEERS: usize> Responder<MAX_PEERS> {
    pub fn new(gateway_public: &[u8; 32]) -> Result<Self, CryptoError> {
        let ck0 = crypto::hash(&[CONSTRUCTION])?;
        let h = crypto::hash(&[&ck0, IDENTIFIER])?;
        Ok(Self {
            ck0,
            h0: crypto::hash(&[&h, gateway_public])?,
            mac1_key: crypto::hash(&[LABEL_MAC1, gateway_public])?,
            peers: [PeerState { last_timestamp: [0; TAI64N_LEN], last_accept_ns: None }; MAX_PEERS],
        })
    }

    /// Verifies and consumes a handshake initiation and builds the response.
    ///
    /// mac1 is checked before any DH; an unknown static key is rejected
    /// after the first DH (`es`) and before the second (`ss`). `local_index`
    /// is asked for our receiver index only once the initiation has
    /// authenticated and passed the replay, flood and PSK checks, so
    /// rejected initiations cannot use up the index space.
    ///
    /// Order (M3 plan, `hs`): `es`, static decrypt and peer lookup, `ss`,
    /// timestamp decrypt, replay and flood, `psks.fresh`, commit. The
    /// timestamp key comes from `ss`, so the PSK check is the earliest point
    /// at which the sender is authenticated; a refusal there commits no
    /// replay or flood state.
    #[allow(clippy::too_many_arguments)] // each seam is a distinct trust boundary; see the PD wiring
    pub fn consume_initiation(
        &mut self,
        msg: &[u8; wg_wire::INITIATION_LEN],
        now_ns: u64,
        local_index: impl FnOnce() -> Option<u32>,
        key: &mut impl StaticKey,
        entropy: &mut impl Entropy,
        peers: &impl PeerTable,
        psks: &impl PskSource,
    ) -> Result<Accepted, Reject> {
        let init = MessageInitiation::parse(msg).map_err(Reject::Malformed)?;
        let covered = msg.get(..INITIATION_MAC1_OFFSET).ok_or(Reject::Malformed(WireError::TooShort))?;
        let mac1 = crypto::mac(&self.mac1_key, &[covered])?;
        if !crypto::ct_eq(&mac1, &init.mac1) {
            return Err(Reject::BadMac1);
        }

        // e
        let c = Key32::from_bytes(self.ck0);
        let c = crypto::kdf1(&c, &init.ephemeral)?;
        let h = crypto::hash(&[&self.h0, &init.ephemeral])?;
        // es
        let es = key_dh(key, &init.ephemeral)?;
        let (c, k) = crypto::kdf2(&c, es.as_bytes())?;
        // s
        let mut static_pub = [0u8; 32];
        crypto::aead_open(&k, 0, &init.enc_static, &h, &mut static_pub)?;
        let h = crypto::hash(&[&h, &init.enc_static])?;
        let peer = peers.lookup(&static_pub).ok_or(Reject::UnknownPeer)?;
        let slot = usize::from(peer.0);
        if slot >= MAX_PEERS {
            return Err(Reject::PeerOutOfRange);
        }
        // ss
        let ss = key_dh(key, &static_pub)?;
        let (c, k) = crypto::kdf2(&c, ss.as_bytes())?;
        // {t}
        let mut timestamp = [0u8; TAI64N_LEN];
        crypto::aead_open(&k, 0, &init.enc_timestamp, &h, &mut timestamp)?;
        let h = crypto::hash(&[&h, &init.enc_timestamp])?;

        let state = self.peers.get_mut(slot).ok_or(Reject::PeerOutOfRange)?;
        // Big-endian seconds then nanoseconds: byte order is numeric order.
        if timestamp <= state.last_timestamp {
            return Err(Reject::Replay);
        }
        if let Some(last) = state.last_accept_ns
            && now_ns.saturating_sub(last) < INITIATION_MIN_INTERVAL_NS
        {
            return Err(Reject::Flood);
        }
        let psk = psks.fresh(peer, now_ns).map_err(Reject::Psk)?;
        // The initiation is authentic: commit before building the response,
        // so a later failure cannot let the same initiation be replayed.
        state.last_timestamp = timestamp;
        state.last_accept_ns = Some(now_ns);
        let local_index = local_index().ok_or(Reject::IndexExhausted)?;

        // e (ours)
        let mut e_priv = Key32::zero();
        entropy.fill(e_priv.as_mut_bytes()).map_err(|_| Reject::Entropy)?;
        crypto::clamp(&mut e_priv);
        let e_pub = crypto::public_key(&e_priv);
        let c = crypto::kdf1(&c, &e_pub)?;
        let h = crypto::hash(&[&h, &e_pub])?;
        // ee, se
        let ee = crypto::dh(&e_priv, &init.ephemeral)?;
        let c = crypto::kdf1(&c, ee.as_bytes())?;
        let se = crypto::dh(&e_priv, &static_pub)?;
        let c = crypto::kdf1(&c, se.as_bytes())?;
        // psk
        let (c, tau, kappa) = crypto::kdf3(&c, psk.as_ref().as_bytes())?;
        drop(psk);
        let h = crypto::hash(&[&h, tau.as_bytes()])?;
        let mut enc_nothing = [0u8; crypto::TAG_LEN];
        crypto::aead_seal(&kappa, 0, &[], &h, &mut enc_nothing)?;

        let mut resp = MessageResponse {
            sender: local_index,
            receiver: init.sender,
            ephemeral: e_pub,
            enc_nothing,
            mac1: [0; 16],
            mac2: [0; 16],
        };
        let mut response = [0u8; RESPONSE_LEN];
        resp.emit(&mut response).map_err(Reject::Malformed)?;
        let peer_mac1_key = crypto::hash(&[LABEL_MAC1, &static_pub])?;
        let covered = response
            .get(..RESPONSE_MAC1_OFFSET)
            .ok_or(Reject::Malformed(WireError::BufferTooSmall))?;
        resp.mac1 = crypto::mac(&peer_mac1_key, &[covered])?;
        resp.emit(&mut response).map_err(Reject::Malformed)?;

        let (recv, send) = crypto::kdf2(&c, &[])?;
        Ok(Accepted {
            response,
            keys: SessionKeys { send, recv },
            peer,
            initiator_index: init.sender,
            responder_index: local_index,
        })
    }
}
