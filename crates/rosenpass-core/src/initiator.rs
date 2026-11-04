//! The V02 initiator (M9 plan C7; upstream `handle_initiation`,
//! `handle_resp_hello`, `handle_resp_conf` and `handle_cookie_reply`):
//! IHI1–IHI8, RHI3–RHI7 and ICI3–ICI7 over the responder's chain, crypto and
//! wire code, with `initiator_state` as its state core.
//!
//! The OSK leaves only from `handle_resp_hello`, once the RespHello
//! authenticated, as upstream's initiator enters its session there (I7.1).
//! EmptyData only stops retransmission. Every handler computes into locals
//! and commits the state core and the handshake secrets last, so an error
//! leaves both unchanged (I7.3); every transient secret is a `Secret`, wiped
//! when it drops, on errors too (I7.2).

use rosenpass_wire::{
    self as wire, EMPTY_DATA_CTR_LEN, INIT_CONF_LEN, INIT_HELLO_LEN, MAC_LEN, PIDI_CT_LEN, SCT_LEN, SID_LEN, TAG_LEN,
};

use crate::Secret;
use crate::chain::Chain;
use crate::cookie::{self, COOKIE_REPLY_LEN, COOKIE_VALUE_LEN};
use crate::crypto::{self, Domains, KEY_LEN, NONCE_LEN};
use crate::initiator_state::{InitiatorState, JITTER_LEN, StateError, Tick};
use crate::kem::{Decaps, ESK_LEN, Encaps, Ephemeral, Rng, SPK_LEN};
use crate::responder::{Error, Seams, envelope_mac, mac_field, mac_key, mac_ok, peer_id};

/// The output shared key, released by `handle_resp_hello`.
pub type Osk = Secret<KEY_LEN>;

impl From<StateError> for Error {
    fn from(e: StateError) -> Self {
        match e {
            StateError::UnexpectedMessage | StateError::UnknownSession | StateError::Expired => Error::UnknownPeer,
            StateError::Overflow => Error::Internal,
        }
    }
}

/// A message to send again: the stored InitHello or InitConf, its cookie
/// field sealed afresh.
pub struct Retransmit {
    buf: [u8; INIT_HELLO_LEN],
    len: usize,
}

impl Retransmit {
    fn new(msg: &[u8]) -> Result<Self, Error> {
        let mut buf = [0u8; INIT_HELLO_LEN];
        buf.get_mut(..msg.len()).ok_or(Error::Internal)?.copy_from_slice(msg);
        Ok(Self { buf, len: msg.len() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.buf.get_mut(..self.len).unwrap_or(&mut [])
    }

    fn mac(&self) -> Result<[u8; MAC_LEN], Error> {
        let msg = self.as_bytes();
        msg.get(wire::mac_offset(msg.len())..).and_then(|m| m.first_chunk::<MAC_LEN>()).copied().ok_or(Error::Internal)
    }
}

/// The secrets of the handshake in flight; dropping it wipes them.
struct Handshake {
    /// The chain after IHI8; wiped once the RespHello authenticated.
    ck: Secret<KEY_LEN>,
    eski: Secret<ESK_LEN>,
    epki: [u8; wire::EPK_LEN],
    /// tkr, which seals the EmptyData; set at ICI7.
    txkt: Secret<KEY_LEN>,
    /// Sealed into every message's cookie field (upstream `cookie_value`):
    /// random until a CookieReply replaces it.
    cookie: Secret<COOKIE_VALUE_LEN>,
    sent: Retransmit,
}

/// The two McEliece public keys, passed to each call that reads them (as
/// `Seams` is), so the initiator holds no borrow: `spki` is ours (its
/// secret is the `Decaps` seam), `spkr` the responder's.
#[derive(Clone, Copy)]
pub struct InitiatorKeys<'a> {
    pub spki: &'a [u8; SPK_LEN],
    pub spkr: &'a [u8; SPK_LEN],
}

/// The initiator for one responder. It keeps only values derived from the
/// keys; each call that reads the keys themselves takes them again and
/// checks them against `new`'s.
pub struct Initiator {
    d: Domains,
    /// The chaining key after IHI1, KH(ckinit, spkr): public and constant.
    ck_init: [u8; KEY_LEN],
    /// Our peer id, KH(peerid, spki), sealed into IHI6.
    pidi: [u8; KEY_LEN],
    /// KH(mac, spki): incoming RespHello and EmptyData are sealed under it.
    own_mac_key: [u8; KEY_LEN],
    /// KH(mac, spkr): seals what we send.
    peer_mac_key: [u8; KEY_LEN],
    /// The responder's public cookie key, which opens its CookieReply.
    cookie_key: [u8; KEY_LEN],
    state: InitiatorState,
    /// Some exactly while the state core is in SentInitHello or SentInitConf.
    hs: Option<Handshake>,
}

/// Writes the envelope mac under `mac_key`, then the cookie field.
fn seal(mac_key: &[u8; KEY_LEN], cookie: &Secret<COOKIE_VALUE_LEN>, msg: &mut [u8]) -> Result<(), Error> {
    let mac = envelope_mac(mac_key, msg)?;
    *mac_field(msg).ok_or(Error::Internal)? = mac;
    seal_cookie(cookie, msg)
}

/// Upstream `Envelope::seal_cookie`: the cookie over every byte before it.
fn seal_cookie(cookie: &Secret<COOKIE_VALUE_LEN>, msg: &mut [u8]) -> Result<(), Error> {
    let (before, field) = msg.split_at_mut_checked(wire::cookie_offset(msg.len())).ok_or(Error::Internal)?;
    let field: &mut [u8; wire::COOKIE_LEN] = field.try_into().map_err(|_| Error::Internal)?;
    *field = cookie::cookie_field(cookie, before);
    Ok(())
}

fn draw_jitter<R: Rng>(rng: &mut R) -> Result<[u8; JITTER_LEN], Error> {
    let mut jitter = [0u8; JITTER_LEN];
    rng.fill(&mut jitter).map_err(|_| Error::Rng)?;
    Ok(jitter)
}

impl Initiator {
    pub fn new(keys: &InitiatorKeys<'_>) -> Result<Self, Error> {
        let d = Domains::v02()?;
        Ok(Self {
            ck_init: crypto::kh_public(&d.ckinit, keys.spkr)?,
            pidi: peer_id(&d, keys.spki)?,
            own_mac_key: mac_key(&d, keys.spki)?,
            peer_mac_key: mac_key(&d, keys.spkr)?,
            cookie_key: cookie::cookie_key(keys.spkr),
            d,
            state: InitiatorState::new(),
            hs: None,
        })
    }

    /// Refuses `spki` other than `new`'s, by its peer id.
    fn check_spki(&self, spki: &[u8; SPK_LEN]) -> Result<(), Error> {
        if crypto::ct_eq(&peer_id(&self.d, spki)?, &self.pidi) { Ok(()) } else { Err(Error::Internal) }
    }

    /// Refuses `spkr` other than `new`'s, by KH(ckinit, spkr).
    fn check_spkr(&self, spkr: &[u8; SPK_LEN]) -> Result<(), Error> {
        if crypto::ct_eq(&crypto::kh_public(&self.d.ckinit, spkr)?, &self.ck_init) { Ok(()) } else { Err(Error::Internal) }
    }

    /// The state core, for callers' deadlines and for tests.
    pub fn state(&self) -> &InitiatorState {
        &self.state
    }

    /// IHI1–IHI8: a new handshake, replacing any in flight. Returns the
    /// InitHello to send. Keys other than `new`'s are `Error::Internal`.
    pub fn start<D, K, M, R>(
        &mut self,
        keys: &InitiatorKeys<'_>,
        now: u64,
        s: &mut Seams<'_, D, K, M, R>,
    ) -> Result<[u8; INIT_HELLO_LEN], Error>
    where
        D: Decaps,
        K: Ephemeral,
        M: Encaps<SPK_LEN, SCT_LEN>,
        R: Rng,
    {
        self.check_spki(keys.spki)?;
        self.check_spkr(keys.spkr)?;
        // Upstream draws the cookie value first, with the handshake
        // (`InitiatorHandshake::zero_with_timestamp`).
        let mut cookie = Secret::<COOKIE_VALUE_LEN>::zero();
        s.rng.fill(cookie.expose_mut()).map_err(|_| Error::Rng)?;
        // IHI1
        let mut c = Chain::from_ck(Secret::from_bytes(self.ck_init), &self.d);
        // IHI2
        let mut sidi = [0u8; SID_LEN];
        s.rng.fill(&mut sidi).map_err(|_| Error::Rng)?;
        // IHI3
        let (epki, eski) = s.kyber.keygen(s.rng).map_err(|_| Error::Rng)?;
        // IHI4
        c.mix(&sidi)?.mix(&epki)?;
        // IHI5
        let (sctr, shk) = s.mceliece.encaps(keys.spkr, s.rng)?;
        c.mix_kem(keys.spkr, &shk, &sctr)?;
        drop(shk);
        // IHI6
        let mut pidi_ct = [0u8; PIDI_CT_LEN];
        c.encrypt_and_mix(&self.pidi, &mut pidi_ct)?;
        // IHI7: no PSK (SC25), so upstream's all-zero default.
        c.mix(keys.spki)?.mix(&[0; KEY_LEN])?;
        // IHI8
        let mut auth = [0u8; TAG_LEN];
        c.auth(&mut auth)?;
        let ck = Secret::copy_from(c.ck().expose());
        drop(c);

        let next = self.state.start(now, sidi, draw_jitter(s.rng)?)?;
        let ih = wire::InitHello { sidi, epki, sctr, pidi_ct, auth, mac: [0; MAC_LEN], cookie: [0; wire::COOKIE_LEN] };
        let mut out = [0u8; INIT_HELLO_LEN];
        ih.emit(&mut out).map_err(|_| Error::Internal)?;
        seal(&self.peer_mac_key, &cookie, &mut out)?;
        let sent = Retransmit::new(&out)?;

        self.hs = Some(Handshake { ck, eski, epki, txkt: Secret::zero(), cookie, sent });
        self.state = next;
        Ok(out)
    }

    /// RHI2–RHI7, ICI3, ICI4 and ICI7: authenticates the RespHello and
    /// returns the InitConf to send with the OSK. An `spki` other than
    /// `new`'s is `Error::Internal`; `spkr` is not read.
    pub fn handle_resp_hello<D, K, M, R>(
        &mut self,
        keys: &InitiatorKeys<'_>,
        msg: &[u8],
        now: u64,
        s: &mut Seams<'_, D, K, M, R>,
    ) -> Result<([u8; INIT_CONF_LEN], Osk), Error>
    where
        D: Decaps,
        K: Ephemeral,
        M: Encaps<SPK_LEN, SCT_LEN>,
        R: Rng,
    {
        let rh = wire::RespHello::parse(msg).map_err(|_| Error::Malformed)?;
        if !mac_ok(&self.own_mac_key, msg)? {
            return Err(Error::BadMac);
        }
        // RHI2: before any decapsulation, a RespHello for no handshake of
        // ours costs nothing.
        let next = self.state.resp_hello(now, rh.sidi, draw_jitter(s.rng)?)?;
        let hs = self.hs.as_ref().ok_or(Error::Internal)?;
        // After the mac and RHI2, so an unauthenticated datagram costs no
        // hash over the key.
        self.check_spki(keys.spki)?;

        let mut c = Chain::from_ck(Secret::copy_from(hs.ck.expose()), &self.d);
        // RHI3
        c.mix(&rh.sidr)?.mix(&rh.sidi)?;
        // RHI4
        let shk = s.kyber.decaps(&hs.eski, &rh.ecti);
        c.mix_kem(&hs.epki, &shk, &rh.ecti)?;
        drop(shk);
        // RHI5
        let shk = s.decaps.decaps(&rh.scti).map_err(Error::Decaps)?;
        c.mix_kem(keys.spki, &shk, &rh.scti)?;
        drop(shk);
        // RHI6
        c.mix(&rh.biscuit_ct)?;
        // RHI7
        c.check_auth(&rh.auth)?;
        // ICI3
        c.mix(&rh.sidi)?.mix(&rh.sidr)?;
        // ICI4
        let mut auth = [0u8; TAG_LEN];
        c.auth(&mut auth)?;
        // ICI7: the OSK, and tkr = KH(ck, res_enc) to check the EmptyData.
        let osk = c.derive(&self.d.osk)?;
        let txkt = c.derive(&self.d.res_enc)?;
        drop(c);

        let ic = wire::InitConf {
            sidi: rh.sidi,
            sidr: rh.sidr,
            biscuit_ct: rh.biscuit_ct,
            auth,
            mac: [0; MAC_LEN],
            cookie: [0; wire::COOKIE_LEN],
        };
        let mut out = [0u8; INIT_CONF_LEN];
        ic.emit(&mut out).map_err(|_| Error::Internal)?;
        seal(&self.peer_mac_key, &hs.cookie, &mut out)?;
        let sent = Retransmit::new(&out)?;

        let hs = self.hs.as_mut().ok_or(Error::Internal)?;
        hs.ck.wipe();
        hs.eski.wipe();
        hs.txkt = txkt;
        hs.sent = sent;
        self.state = next;
        Ok((out, osk))
    }

    /// Upstream `handle_resp_conf`: the EmptyData's auth under tkr. Stops
    /// retransmission and wipes the handshake; exports nothing.
    pub fn handle_empty_data(&mut self, msg: &[u8], now: u64) -> Result<(), Error> {
        let ed = wire::EmptyData::parse(msg).map_err(|_| Error::Malformed)?;
        if !mac_ok(&self.own_mac_key, msg)? {
            return Err(Error::BadMac);
        }
        let next = self.state.empty_data(now, ed.sid)?;
        let hs = self.hs.as_ref().ok_or(Error::Internal)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.get_mut(..EMPTY_DATA_CTR_LEN).ok_or(Error::Internal)?.copy_from_slice(&ed.ctr);
        crypto::aead_open(&hs.txkt, &nonce, &ed.auth, &mut [])?;

        self.hs = None;
        self.state = next;
        Ok(())
    }

    /// Upstream `handle_cookie_reply`: opens the cookie value with the mac of
    /// the message last sent and retransmits it at once (`tick` returns it).
    pub fn handle_cookie_reply(&mut self, msg: &[u8], now: u64) -> Result<(), Error> {
        let sid = cookie::reply_sid(msg).ok_or(Error::Malformed)?;
        let reply: &[u8; COOKIE_REPLY_LEN] = msg.try_into().map_err(|_| Error::Malformed)?;
        let next = self.state.cookie_reply(now, sid)?;
        let hs = self.hs.as_ref().ok_or(Error::Internal)?;
        let value = cookie::open_cookie_reply(&self.cookie_key, reply, &hs.sent.mac()?)?;

        let hs = self.hs.as_mut().ok_or(Error::Internal)?;
        hs.cookie = value;
        self.state = next;
        Ok(())
    }

    /// Retransmits the stored message when due, and drops a handshake past
    /// its lifetime (the caller starts a new one).
    pub fn tick(&mut self, now: u64) -> Option<Retransmit> {
        let (next, t) = self.state.tick(now).ok()?;
        match t {
            Tick::Nothing => {
                self.state = next;
                None
            }
            Tick::Expired => {
                self.hs = None;
                self.state = next;
                None
            }
            Tick::Retransmit => {
                let hs = self.hs.as_ref()?;
                let mut msg = Retransmit::new(hs.sent.as_bytes()).ok()?;
                seal_cookie(&hs.cookie, msg.as_mut_bytes()).ok()?;
                self.state = next;
                Some(msg)
            }
        }
    }
}
