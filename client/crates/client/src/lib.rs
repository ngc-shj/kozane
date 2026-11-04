//! The Kozane client's core (M9 plan C8): drives `rosenpass-core`'s
//! initiator against one gateway and tells its shell what to do.
//!
//! Sans-IO (D5): the core owns no socket, timer or file. The shell passes
//! every datagram from `rp_endpoint` and the time, from a clock that counts
//! suspend (`CLOCK_BOOTTIME` on Linux), and carries out the [`Actions`] it
//! gets back. Randomness is the OS's, through `getrandom`; a failed draw is
//! an error, never a fallback, and the shell cannot supply another source.
//!
//! I8.1, the client mirror of L8: [`Client::new`] returns `Scrub` before any
//! `Send`, and a `Scrub` follows whenever no RespHello has authenticated for
//! `wg_core::REJECT_AFTER_TIME_NS`. A due `Scrub` is always alone in its
//! `Actions`: no fallible step (an RNG draw, a datagram) can hold it back.
//! I8.2: the gateway's keys come only from [`Config`]. I8.3: no action
//! carries `rp.sk`; it stays in [`Keys`].

#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod actions;
mod keys;

use std::net::SocketAddr;

use rosenpass_core::initiator_state::Phase;
use rosenpass_core::{
    Decaps, DecapsError, Initiator, InitiatorKeys, Kyber512, McEliece460896, Rng, RngError, SHK_LEN, Seams,
};
use rosenpass_wire::{MSG_COOKIE_REPLY, MSG_EMPTY_DATA, MSG_RESP_HELLO, SCT_LEN};
use wg_core::REJECT_AFTER_TIME_NS;
use zeroize::Zeroize;

pub use actions::{Action, Actions, Datagram, MAX_ACTIONS, MAX_DATAGRAM, PSK_LEN};
pub use keys::{Keys, RP_SK_LEN, lock_memory};
pub use rosenpass_core::{SPK_LEN, Secret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The OS RNG failed (D5). Nothing was sent or changed; the shell stops.
    Rng,
    /// The datagram was refused, or the handshake could not go on; the
    /// client's state is unchanged.
    Protocol(rosenpass_core::Error),
    /// `now` went backwards, or a deadline does not fit in a u64.
    Clock,
    /// A key or setting has the wrong length.
    InvalidKey,
    /// The secret key's memory could not be locked or kept out of dumps.
    Memory,
    /// More than `MAX_ACTIONS` in one call: a build error, refused rather
    /// than dropped.
    Full,
}

impl From<rosenpass_core::Error> for Error {
    fn from(e: rosenpass_core::Error) -> Self {
        match e {
            rosenpass_core::Error::Rng => Error::Rng,
            e => Error::Protocol(e),
        }
    }
}

/// What the client trusts about its gateway (I8.2), and where it sends.
pub struct Config {
    /// The gateway's Rosenpass address; every `Send` goes there.
    pub rp_endpoint: SocketAddr,
    /// The gateway's pinned McEliece public key (`SPK_LEN` bytes).
    pub gw_rp_pub: Box<[u8; SPK_LEN]>,
    /// The gateway's WireGuard key, for the shell's peer; the core does not
    /// use it.
    pub gw_wg_pub: [u8; 32],
}

impl Config {
    /// Copies `gw_rp_pub`, which must be `SPK_LEN` bytes, to the heap.
    pub fn new(rp_endpoint: SocketAddr, gw_rp_pub: &[u8], gw_wg_pub: [u8; 32]) -> Result<Self, Error> {
        Ok(Self { rp_endpoint, gw_rp_pub: keys::boxed_public(gw_rp_pub)?, gw_wg_pub })
    }
}

/// The OS RNG: getrandom(2), BCryptGenRandom or SecRandomCopyBytes.
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(out).map_err(|_| RngError)
    }
}

/// Decapsulation under `rp.sk` with the real Classic McEliece 460896.
struct RpDecaps<'a>(&'a Secret<{ mce460896::SK_LEN }>);

impl Decaps for RpDecaps<'_> {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut shk = Secret::<SHK_LEN>::zero();
        mce460896::decaps(self.0.expose(), sct, shk.expose_mut());
        Ok(shk)
    }
}

const _: () = assert!(SCT_LEN == mce460896::CT_LEN && SHK_LEN == mce460896::SS_LEN);

/// Bytes of stack [`scrub_stack`] zeroes below its caller: every frame an
/// initiator call just left (M9 plan C7, I7.2; deviation D-16). Moved-from
/// `Secret`s and libcrux's BLAKE2b, ChaCha20 and SHAKE256 state stay there
/// otherwise. Measured by tools/rp-residue on the client's release profile,
/// deepest non-paint byte below the caller: an accepted `handle_resp_hello`
/// with the real KEMs 103 064 bytes (McEliece decapsulation's own 96 KiB
/// scrub included), `start` 53 576; with the stand-in KEMs every one of the
/// 22 residue cases stays within 13 352. 128 KiB keeps about 27 % (28 008
/// bytes) over the deepest; the harness fails a call deeper than this. The
/// caller's thread needs this much stack free below its frame.
pub const SCRUB_DEPTH: usize = 128 * 1024;

/// Zeroes, with volatile writes, [`SCRUB_DEPTH`] bytes of stack below the
/// caller's frame, where the initiator call it follows ran: tls-core's
/// `scrub_session_stack` (M6 plan C7), sized for the initiator. Called
/// after every `Initiator` call, on success and on error, before the result
/// is acted on; tools/rp-residue calls it the same way.
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u64; SCRUB_DEPTH / 8];
    area.zeroize();
    std::hint::black_box(&area);
}

/// One Rosenpass initiator for one gateway.
pub struct Client<R: Rng = OsRng> {
    ini: Initiator,
    keys: Box<Keys>,
    gw_rp_pub: Box<[u8; SPK_LEN]>,
    rp_endpoint: SocketAddr,
    gw_wg_pub: [u8; 32],
    rng: R,
    /// When the PSK the last authenticated RespHello installed must be
    /// scrubbed (I8.1). None while no such PSK is live: at start and after
    /// a `Scrub`, the peer carries a random PSK, so no WireGuard keypair can
    /// exist to bound.
    scrub_at: Option<u64>,
    /// The latest `now` seen; time never goes back.
    last_now: u64,
}

impl Client {
    /// The client, and its first action: `Scrub`, so no WireGuard keypair
    /// exists before the first exchange (I8.1). The first `Send` comes from
    /// `on_timer`, which `next_deadline` asks for at once.
    pub fn new(config: Config, keys: Box<Keys>) -> Result<(Self, Actions), Error> {
        Self::with_rng(config, keys, OsRng)
    }
}

impl<R: Rng> Client<R> {
    /// The constructor behind `new`; another `Rng` is a test seam only.
    pub(crate) fn with_rng(config: Config, keys: Box<Keys>, rng: R) -> Result<(Self, Actions), Error> {
        let ini = Initiator::new(&InitiatorKeys { spki: keys.public(), spkr: &config.gw_rp_pub })?;
        let client = Self {
            ini,
            keys,
            gw_rp_pub: config.gw_rp_pub,
            rp_endpoint: config.rp_endpoint,
            gw_wg_pub: config.gw_wg_pub,
            rng,
            scrub_at: None,
            last_now: 0,
        };
        let mut out = Actions::new();
        out.push(Action::Scrub)?;
        Ok((client, out))
    }

    pub fn rp_endpoint(&self) -> SocketAddr {
        self.rp_endpoint
    }

    pub fn gw_wg_pub(&self) -> &[u8; 32] {
        &self.gw_wg_pub
    }

    /// When the shell must call `on_timer` next, at the latest: the
    /// handshake's retransmission or death, the rekey, or the scrub. `now`
    /// itself while no handshake has started.
    pub fn next_deadline(&self) -> Option<u64> {
        let st = self.ini.state();
        let handshake = match st.phase() {
            Phase::Idle => Some(self.last_now),
            Phase::Established => st.rekey_at(),
            Phase::SentInitHello | Phase::SentInitConf => st.deadline(),
        };
        [handshake, self.scrub_at].into_iter().flatten().min()
    }

    /// A datagram from `rp_endpoint`: a RespHello, an EmptyData or a
    /// CookieReply. A refused one is `Error::Protocol` and changes nothing.
    /// When a scrub is due, the datagram is dropped unread and only `Scrub`
    /// returns; the initiator's retransmission recovers the exchange.
    pub fn on_datagram(&mut self, now: u64, msg: &[u8]) -> Result<Actions, Error> {
        self.advance(now)?;
        if let Some(scrub) = self.scrub(now)? {
            return Ok(scrub);
        }
        let mut out = Actions::new();
        let ini = &mut self.ini;
        let keys = InitiatorKeys { spki: self.keys.public(), spkr: &self.gw_rp_pub };
        match rosenpass_wire::peek_type(msg) {
            Ok(MSG_RESP_HELLO) => {
                let scrub_at = now.checked_add(REJECT_AFTER_TIME_NS).ok_or(Error::Clock)?;
                let mut decaps = RpDecaps(self.keys.secret());
                let seams =
                    &mut Seams { decaps: &mut decaps, kyber: &mut Kyber512, mceliece: &mut McEliece460896, rng: &mut self.rng };
                let r = ini.handle_resp_hello(&keys, msg, now, seams);
                scrub_stack();
                let (ic, osk) = r?;
                // The PSK first, so the gateway's WireGuard handshake, which
                // the InitConf lets it start, meets it in place.
                out.push(Action::InstallPsk(osk))?;
                out.push(Action::Send(Datagram::new(&ic)?))?;
                self.scrub_at = Some(scrub_at);
            }
            Ok(MSG_EMPTY_DATA) => {
                let r = ini.handle_empty_data(msg, now);
                scrub_stack();
                r?
            }
            Ok(MSG_COOKIE_REPLY) => {
                let r = ini.handle_cookie_reply(msg, now);
                scrub_stack();
                r?;
                let again = ini.tick(now);
                scrub_stack();
                if let Some(r) = again {
                    out.push(Action::Send(Datagram::new(r.as_bytes())?))?;
                }
            }
            _ => return Err(Error::Protocol(rosenpass_core::Error::Malformed)),
        }
        Ok(out)
    }

    /// The deadline passed (or the shell polls): the scrub, a
    /// retransmission, or a new handshake (the first, after one died, or the
    /// rekey at the initiator's `rekey_at`).
    pub fn on_timer(&mut self, now: u64) -> Result<Actions, Error> {
        self.advance(now)?;
        if let Some(scrub) = self.scrub(now)? {
            return Ok(scrub);
        }
        let mut out = Actions::new();
        let ini = &mut self.ini;
        let again = ini.tick(now);
        scrub_stack();
        if let Some(r) = again {
            out.push(Action::Send(Datagram::new(r.as_bytes())?))?;
            return Ok(out);
        }
        let st = ini.state();
        let start = match st.phase() {
            Phase::Idle => true,
            Phase::Established => st.rekey_at().is_some_and(|t| now >= t),
            Phase::SentInitHello | Phase::SentInitConf => false,
        };
        if start {
            let keys = InitiatorKeys { spki: self.keys.public(), spkr: &self.gw_rp_pub };
            let mut decaps = RpDecaps(self.keys.secret());
            let seams =
                &mut Seams { decaps: &mut decaps, kyber: &mut Kyber512, mceliece: &mut McEliece460896, rng: &mut self.rng };
            let r = ini.start(&keys, now, seams);
            scrub_stack();
            let ih = r?;
            out.push(Action::Send(Datagram::new(&ih)?))?;
        }
        Ok(out)
    }

    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Clock);
        }
        self.last_now = now;
        Ok(())
    }

    /// `Scrub`, alone, once the live PSK reached `REJECT_AFTER_TIME_NS`.
    fn scrub(&mut self, now: u64) -> Result<Option<Actions>, Error> {
        if !self.scrub_at.is_some_and(|t| now >= t) {
            return Ok(None);
        }
        let mut out = Actions::new();
        out.push(Action::Scrub)?;
        self.scrub_at = None;
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests;
