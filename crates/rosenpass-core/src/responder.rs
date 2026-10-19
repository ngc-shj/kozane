//! The V02 responder state machine (upstream `handle_init_hello` and
//! `handle_init_conf`, IHR1–RHR7 and ICR1–ICR7), with biscuit keys, the
//! replay rule and the known-InitConf cache.
//!
//! OSK export order (M3 plan F8, S15): `handle_init_conf` only prepares. It
//! returns a `PendingExport` whose `PskInstall` the PD sends first; only when
//! that send succeeded does `commit_conf` record `biscuit_used`, cache the
//! EmptyData and hand it out. Dropping or aborting the pending export leaves
//! no trace, so the client's retransmission is processed again.

use rosenpass_wire::{
    self as wire, BISCUIT_CT_LEN, BISCUIT_PT_LEN, ECT_LEN, EMPTY_DATA_LEN, EPK_LEN, MAC_LEN, RESP_HELLO_LEN, SCT_LEN,
    SID_LEN, TAG_LEN,
};

use crate::Secret;
use crate::chain::Chain;
use crate::crypto::{self, CryptoError, Domains, KEY_LEN, NONCE_LEN, XNONCE_LEN};
use crate::kem::{Decaps, DecapsError, Encaps, EncapsError, Rng, SPK_LEN};

const NS_PER_S: u64 = 1_000_000_000;
/// A biscuit key seals for one epoch and opens for two (upstream
/// `BISCUIT_EPOCH`), so a rotation keeps the previous key one more epoch.
pub const BISCUIT_EPOCH_NS: u64 = 300 * NS_PER_S;
const BISCUIT_KEY_LIFETIME_NS: u64 = 2 * BISCUIT_EPOCH_NS;
/// How long an EmptyData stays cached for retransmitted InitConfs
/// (upstream `REKEY_AFTER_TIME_RESPONDER`).
pub const KNOWN_RESPONSE_TTL_NS: u64 = 120 * NS_PER_S;

const BISCUIT_NO_LEN: usize = 12;
/// Biscuit numbers are 96-bit little-endian counters.
const BISCUIT_NO_LIMIT: u128 = 1 << (8 * BISCUIT_NO_LEN);
const KNOWN_HASH_LEN: usize = 16;

/// Why a message was refused. Every refusal leaves the responder's state
/// unchanged, except that a refused InitHello may have consumed a biscuit
/// number or (on RNG failure during a due rotation) dropped the biscuit keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong length, type or reserved bytes.
    Malformed,
    BadMac,
    Decaps(DecapsError),
    /// The RNG failed; the handshake is aborted (`RpRngFailed`).
    Rng,
    Encaps(EncapsError),
    /// The decrypted initiator id, or the biscuit's, names no configured peer.
    UnknownPeer,
    /// An AEAD did not open: the peer id, an `auth` field or the biscuit.
    Auth,
    /// No live biscuit key: none rotated in yet, a failed rotation, or the
    /// biscuit's key is past its second epoch.
    NoBiscuitKey,
    /// `biscuit_no` is not greater than the peer's `biscuit_used`
    /// (`RpBiscuitReplay`).
    BiscuitReplay,
    /// Two configured peers share a key.
    DuplicatePeer,
    /// A buffer size or counter limit (a build error, not attacker-reachable).
    Internal,
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Auth => Error::Auth,
            CryptoError::Hash | CryptoError::Buffer => Error::Internal,
        }
    }
}

impl From<EncapsError> for Error {
    fn from(e: EncapsError) -> Self {
        match e {
            EncapsError::Rng => Error::Rng,
            EncapsError::PublicKey => Error::Encaps(e),
        }
    }
}

/// The crypto seams one InitHello needs: `pqkey`'s decapsulation, both
/// encapsulations and the hedged RNG.
pub struct Seams<'a, D, K, M, R> {
    pub decaps: &'a mut D,
    pub kyber: &'a mut K,
    pub mceliece: &'a mut M,
    pub rng: &'a mut R,
}

/// What `pq` sends `hs` before anything else is committed.
pub struct PskInstall<'a> {
    pub peer: usize,
    pub osk: &'a Secret<KEY_LEN>,
}

/// A fresh, authenticated InitConf whose OSK is not yet installed. Not
/// `Clone`: it is consumed by exactly one of `commit_conf` or `abort_conf`;
/// dropping it is the same as aborting.
pub struct PendingExport {
    peer: usize,
    osk: Secret<KEY_LEN>,
    biscuit_no: u128,
    request: [u8; KNOWN_HASH_LEN],
    response: [u8; EMPTY_DATA_LEN],
}

impl PendingExport {
    pub fn peer(&self) -> usize {
        self.peer
    }

    pub fn psk_install(&self) -> PskInstall<'_> {
        PskInstall { peer: self.peer, osk: &self.osk }
    }
}

/// The outcome of an accepted InitConf.
pub enum Conf {
    /// An exact retransmission of an InitConf whose OSK was already
    /// installed: resend the cached EmptyData, export nothing.
    Retransmission { peer: usize, response: [u8; EMPTY_DATA_LEN] },
    /// Send `PskInstall` first, then `commit_conf` or `abort_conf`.
    Fresh(PendingExport),
}

struct Known {
    request: [u8; KNOWN_HASH_LEN],
    response: [u8; EMPTY_DATA_LEN],
    at: u64,
}

struct Peer<'k> {
    spkt: &'k [u8; SPK_LEN],
    pid: [u8; KEY_LEN],
    /// KH(mac, spkt): seals what we send to this peer.
    mac_key: [u8; KEY_LEN],
    biscuit_used: u128,
    known: Option<Known>,
}

struct BiscuitKey {
    key: Secret<KEY_LEN>,
    created_at: u64,
}

impl BiscuitKey {
    fn age(&self, now: u64) -> Option<u64> {
        now.checked_sub(self.created_at)
    }

    fn seals(&self, now: u64) -> bool {
        self.age(now).is_some_and(|a| a < BISCUIT_EPOCH_NS)
    }

    fn opens(&self, now: u64) -> bool {
        self.age(now).is_some_and(|a| a < BISCUIT_KEY_LIFETIME_NS)
    }
}

/// Upstream's peer id: KH(peerid, spk).
pub fn peer_id(d: &Domains, spk: &[u8; SPK_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    crypto::kh_public(&d.peerid, spk)
}

/// KH(mac, spk): the envelope mac key for messages sent to the owner of
/// `spk`. `ingress` checks InitHello and InitConf under `mac_key(spkm)`.
pub fn mac_key(d: &Domains, spk: &[u8; SPK_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    crypto::kh_public(&d.mac, spk)
}

/// The envelope mac: the first 16 bytes of KH(mac_key, everything before
/// the mac field). Note KH is the "incorrect HMAC", not plain keyed BLAKE2b.
pub fn envelope_mac(mac_key: &[u8; KEY_LEN], msg: &[u8]) -> Result<[u8; MAC_LEN], CryptoError> {
    let covered = msg.get(..wire::mac_offset(msg.len())).ok_or(CryptoError::Buffer)?;
    let full = crypto::kh_public(mac_key, covered)?;
    let (mac, _) = full.split_first_chunk::<MAC_LEN>().ok_or(CryptoError::Buffer)?;
    Ok(*mac)
}

fn mac_field(msg: &mut [u8]) -> Option<&mut [u8; MAC_LEN]> {
    let off = wire::mac_offset(msg.len());
    msg.get_mut(off..)?.first_chunk_mut::<MAC_LEN>()
}

fn mac_ok(mac_key: &[u8; KEY_LEN], msg: &[u8]) -> Result<bool, Error> {
    let want = envelope_mac(mac_key, msg)?;
    let got = msg.get(wire::mac_offset(msg.len())..).and_then(|m| m.first_chunk::<MAC_LEN>()).ok_or(Error::Internal)?;
    Ok(crypto::ct_eq(&want, got))
}

#[cfg(test)]
fn trace(label: &'static str, v: &[u8]) {
    crate::tests::trace(label, v);
}

#[cfg(not(test))]
fn trace(_: &'static str, _: &[u8]) {}

/// The responder for up to `P` peers. Public keys are borrowed (the PD
/// embeds them in its ELF), never copied.
pub struct Responder<'k, const P: usize> {
    d: Domains,
    spkm: &'k [u8; SPK_LEN],
    /// The chaining key after IHR1, KH(ckinit, spkm): public and constant.
    ck_init: [u8; KEY_LEN],
    /// KH(mac, spkm): incoming InitHello and InitConf are sealed under it.
    mac_key: [u8; KEY_LEN],
    /// KH(biscuit_ad, spkm), the constant prefix of every biscuit's ad.
    biscuit_ad_m: [u8; KEY_LEN],
    peers: [Peer<'k>; P],
    biscuit_keys: [Option<BiscuitKey>; 2],
    /// The slot of the newest key; it doubles as the nonce's top bit.
    active: usize,
    biscuit_ctr: u128,
    /// Keys the known-InitConf hash (upstream `KnownResponseHasher`).
    known_key: Secret<KEY_LEN>,
}

impl<'k, const P: usize> Responder<'k, P> {
    /// Hashes every public key once. Biscuit keys start empty: call `tick`
    /// (or let the first InitHello rotate one in).
    pub fn new<R: Rng>(spkm: &'k [u8; SPK_LEN], spkts: [&'k [u8; SPK_LEN]; P], rng: &mut R) -> Result<Self, Error> {
        let d = Domains::v02()?;
        let mut peers =
            spkts.map(|spkt| Peer { spkt, pid: [0; KEY_LEN], mac_key: [0; KEY_LEN], biscuit_used: 0, known: None });
        for p in peers.iter_mut() {
            p.pid = peer_id(&d, p.spkt)?;
            p.mac_key = mac_key(&d, p.spkt)?;
        }
        for (i, a) in peers.iter().enumerate() {
            if peers.iter().take(i).any(|b| b.pid == a.pid) {
                return Err(Error::DuplicatePeer);
            }
        }
        let mut known_key = Secret::zero();
        rng.fill(known_key.expose_mut()).map_err(|_| Error::Rng)?;
        Ok(Self {
            ck_init: crypto::kh_public(&d.ckinit, spkm)?,
            mac_key: mac_key(&d, spkm)?,
            biscuit_ad_m: crypto::kh_public(&d.biscuit_ad, spkm)?,
            d,
            spkm,
            peers,
            biscuit_keys: [None, None],
            active: 0,
            // Upstream starts at 1 (LSB first); fresh keys per boot make an
            // older boot's biscuits unopenable, so restarting is safe.
            biscuit_ctr: 1,
            known_key,
        })
    }

    pub fn domains(&self) -> &Domains {
        &self.d
    }

    /// KH(mac, spkm), for `ingress`'s mac check.
    pub fn own_mac_key(&self) -> &[u8; KEY_LEN] {
        &self.mac_key
    }

    pub fn peer_id(&self, peer: usize) -> Option<&[u8; KEY_LEN]> {
        self.peers.get(peer).map(|p| &p.pid)
    }

    /// Rotates the biscuit key when the newest one no longer seals. A failed
    /// draw drops every key, so InitHello and InitConf are refused until a
    /// later rotation succeeds; a zeroed or stale key is never used.
    pub fn tick<R: Rng>(&mut self, now: u64, rng: &mut R) -> Result<(), Error> {
        self.sealing_slot(now, rng).map(|_| ())
    }

    fn sealing_slot<R: Rng>(&mut self, now: u64, rng: &mut R) -> Result<usize, Error> {
        if self.biscuit_keys.get(self.active).and_then(Option::as_ref).is_some_and(|k| k.seals(now)) {
            return Ok(self.active);
        }
        let next = self.active ^ 1;
        let mut key = Secret::zero();
        if rng.fill(key.expose_mut()).is_err() {
            self.biscuit_keys = [None, None];
            return Err(Error::Rng);
        }
        *self.biscuit_keys.get_mut(next).ok_or(Error::Internal)? = Some(BiscuitKey { key, created_at: now });
        self.active = next;
        Ok(next)
    }

    fn find_peer(&self, pid: &[u8; KEY_LEN]) -> Option<usize> {
        // No early exit, so the time does not depend on which peer matched.
        let mut found = None;
        for (i, p) in self.peers.iter().enumerate() {
            if crypto::ct_eq(&p.pid, pid) {
                found = Some(i);
            }
        }
        found
    }

    /// IHR1–IHR8 and RHR1–RHR7: authenticates an InitHello and writes the
    /// RespHello to `out`. Returns the peer it came from.
    pub fn handle_init_hello<D, K, M, R>(
        &mut self,
        msg: &[u8],
        now: u64,
        s: &mut Seams<'_, D, K, M, R>,
        out: &mut [u8; RESP_HELLO_LEN],
    ) -> Result<usize, Error>
    where
        D: Decaps,
        K: Encaps<EPK_LEN, ECT_LEN>,
        M: Encaps<SPK_LEN, SCT_LEN>,
        R: Rng,
    {
        let ih = wire::InitHello::parse(msg).map_err(|_| Error::Malformed)?;
        if !mac_ok(&self.mac_key, msg)? {
            return Err(Error::BadMac);
        }
        // Before the decapsulation, so a responder without a biscuit key
        // spends nothing on a handshake it cannot finish.
        let slot = self.sealing_slot(now, s.rng)?;

        // IHR1
        let mut c = Chain::from_ck(Secret::from_bytes(self.ck_init), &self.d);
        // IHR4
        c.mix(&ih.sidi)?.mix(&ih.epki)?;
        trace("ck.ihr4", c.ck().expose());
        // IHR5
        let shk = s.decaps.decaps(&ih.sctr).map_err(Error::Decaps)?;
        c.mix_kem(self.spkm, &shk, &ih.sctr)?;
        drop(shk);
        trace("ck.ihr5", c.ck().expose());
        // IHR6
        let mut pidi = [0u8; KEY_LEN];
        c.decrypt_and_mix(&ih.pidi_ct, &mut pidi)?;
        let peer = self.find_peer(&pidi).ok_or(Error::UnknownPeer)?;
        trace("ck.ihr6", c.ck().expose());
        let p = self.peers.get(peer).ok_or(Error::Internal)?;
        let (spkt, pidt, peer_mac_key) = (p.spkt, p.pid, p.mac_key);
        // IHR7: no PSK (SC25), so upstream's all-zero default.
        c.mix(spkt)?.mix(&[0; KEY_LEN])?;
        trace("ck.ihr7", c.ck().expose());
        // IHR8
        c.check_auth(&ih.auth)?;
        trace("ck.ihr8", c.ck().expose());

        // RHR1
        let mut sidr = [0u8; SID_LEN];
        s.rng.fill(&mut sidr).map_err(|_| Error::Rng)?;
        // RHR3
        c.mix(&sidr)?.mix(&ih.sidi)?;
        trace("ck.rhr3", c.ck().expose());
        // RHR4
        let (ecti, shk) = s.kyber.encaps(&ih.epki, s.rng)?;
        c.mix_kem(&ih.epki, &shk, &ecti)?;
        drop(shk);
        trace("ck.rhr4", c.ck().expose());
        // RHR5
        let (scti, shk) = s.mceliece.encaps(spkt, s.rng)?;
        c.mix_kem(spkt, &shk, &scti)?;
        drop(shk);
        trace("ck.rhr5", c.ck().expose());
        // RHR6
        let key = self.biscuit_keys.get(slot).and_then(Option::as_ref).ok_or(Error::NoBiscuitKey)?;
        let no = self.biscuit_ctr;
        if no >= BISCUIT_NO_LIMIT {
            return Err(Error::Internal);
        }
        self.biscuit_ctr = no.checked_add(1).ok_or(Error::Internal)?;
        let biscuit_ct = seal_biscuit(&self.biscuit_ad_m, key, slot, &pidt, no, c.ck(), &ih.sidi, &sidr, s.rng)?;
        c.mix(&biscuit_ct)?;
        trace("ck.rhr6", c.ck().expose());
        // RHR7
        let mut auth = [0u8; TAG_LEN];
        c.auth(&mut auth)?;
        trace("ck.rhr7", c.ck().expose());
        drop(c);

        let rh = wire::RespHello {
            sidr,
            sidi: ih.sidi,
            ecti,
            scti,
            auth,
            biscuit_ct,
            mac: [0; MAC_LEN],
            cookie: [0; wire::COOKIE_LEN],
        };
        rh.emit(out).map_err(|_| Error::Internal)?;
        let mac = envelope_mac(&peer_mac_key, out)?;
        *mac_field(out).ok_or(Error::Internal)? = mac;
        Ok(peer)
    }

    fn known_hash(&self, msg: &[u8]) -> Result<[u8; KNOWN_HASH_LEN], Error> {
        // Everything but the cookie, like upstream's `KnownResponseHasher`
        // (which uses keyed SHAKE256; the hash never leaves this PD).
        let covered = msg.get(..wire::cookie_offset(msg.len())).ok_or(Error::Internal)?;
        let mut full = [0u8; KEY_LEN];
        crypto::blake2b(self.known_key.expose(), &[covered], &mut full)?;
        let (h, _) = full.split_first_chunk::<KNOWN_HASH_LEN>().ok_or(Error::Internal)?;
        Ok(*h)
    }

    /// The cache lookup, then ICR1–ICR5 and the OSK and EmptyData of ICR7.
    /// Nothing is committed here (see the module docs).
    pub fn handle_init_conf(&mut self, msg: &[u8], now: u64) -> Result<Conf, Error> {
        let ic = wire::InitConf::parse(msg).map_err(|_| Error::Malformed)?;
        if !mac_ok(&self.mac_key, msg)? {
            return Err(Error::BadMac);
        }
        // Before handle_init_conf proper (M3 plan F17): an exact
        // retransmission is answered from the cache and never re-exported.
        let request = self.known_hash(msg)?;
        for (i, p) in self.peers.iter_mut().enumerate() {
            if p.known.as_ref().is_some_and(|k| now.saturating_sub(k.at) >= KNOWN_RESPONSE_TTL_NS) {
                p.known = None;
            }
            if let Some(k) = p.known.as_ref().filter(|k| crypto::ct_eq(&k.request, &request)) {
                return Ok(Conf::Retransmission { peer: i, response: k.response });
            }
        }

        // ICR1: the nonce's top bit names the key.
        let slot = usize::from(ic.biscuit_ct.first().copied().unwrap_or(0) >> 7);
        let key =
            self.biscuit_keys.get(slot).and_then(Option::as_ref).filter(|k| k.opens(now)).ok_or(Error::NoBiscuitKey)?;
        let ad = crypto::kh_public(&crypto::kh_public(&self.biscuit_ad_m, &ic.sidi)?, &ic.sidr)?;
        let mut pt = Secret::<BISCUIT_PT_LEN>::zero();
        crypto::xaead_open(&key.key, &ad, &ic.biscuit_ct, pt.expose_mut())?;
        let (pid, rest) = pt.expose().split_first_chunk::<KEY_LEN>().ok_or(Error::Internal)?;
        let (no, ck) = rest.split_first_chunk::<BISCUIT_NO_LEN>().ok_or(Error::Internal)?;
        let ck = ck.first_chunk::<KEY_LEN>().ok_or(Error::Internal)?;
        let peer = self.find_peer(pid).ok_or(Error::UnknownPeer)?;
        let mut no16 = [0u8; 16];
        no16.get_mut(..BISCUIT_NO_LEN).ok_or(Error::Internal)?.copy_from_slice(no);
        let biscuit_no = u128::from_le_bytes(no16);
        let mut c = Chain::from_ck(Secret::from_bytes(*ck), &self.d);
        drop(pt);
        c.mix(&ic.biscuit_ct)?;
        trace("ck.icr1", c.ck().expose());
        // ICR2
        c.auth(&mut [0u8; TAG_LEN])?;
        trace("ck.icr2", c.ck().expose());
        // ICR3
        c.mix(&ic.sidi)?.mix(&ic.sidr)?;
        trace("ck.icr3", c.ck().expose());
        // ICR4
        c.check_auth(&ic.auth)?;
        trace("ck.icr4", c.ck().expose());
        // ICR5: equal means a retransmission, which the cache answered if
        // its OSK was installed.
        let p = self.peers.get(peer).ok_or(Error::Internal)?;
        if biscuit_no <= p.biscuit_used {
            return Err(Error::BiscuitReplay);
        }

        // ICR7: the responder's transmit key is tkr = KH(ck, res_enc).
        let osk = c.derive(&self.d.osk)?;
        let txk = c.derive(&self.d.res_enc)?;
        drop(c);
        let ctr = 0u64.to_le_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        nonce.get_mut(..ctr.len()).ok_or(Error::Internal)?.copy_from_slice(&ctr);
        let mut auth = [0u8; TAG_LEN];
        crypto::aead_seal(&txk, &nonce, &[], &mut auth)?;
        drop(txk);
        let ed = wire::EmptyData { sid: ic.sidi, ctr, auth, mac: [0; MAC_LEN], cookie: [0; wire::COOKIE_LEN] };
        let mut response = [0u8; EMPTY_DATA_LEN];
        ed.emit(&mut response).map_err(|_| Error::Internal)?;
        let mac = envelope_mac(&p.mac_key, &response)?;
        *mac_field(&mut response).ok_or(Error::Internal)? = mac;
        Ok(Conf::Fresh(PendingExport { peer, osk, biscuit_no, request, response }))
    }

    /// ICR6 and the cache insert, once `PskInstall` was sent. Returns the
    /// EmptyData to send; the OSK is zeroized when `pending` drops here.
    pub fn commit_conf(&mut self, pending: PendingExport, now: u64) -> Result<[u8; EMPTY_DATA_LEN], Error> {
        let p = self.peers.get_mut(pending.peer).ok_or(Error::Internal)?;
        // Re-checked: a commit must never move biscuit_used backwards.
        if pending.biscuit_no <= p.biscuit_used {
            return Err(Error::BiscuitReplay);
        }
        p.biscuit_used = pending.biscuit_no;
        p.known = Some(Known { request: pending.request, response: pending.response, at: now });
        Ok(pending.response)
    }

    /// The `PskInstall` send failed: forget the export entirely.
    pub fn abort_conf(&mut self, pending: PendingExport) {
        drop(pending);
    }
}

/// RHR6: `pidi ‖ biscuit_no ‖ ck` sealed under the biscuit key with ad
/// KH(KH(KH(biscuit_ad, spkm), sidi), sidr); the nonce's top bit is the slot.
#[allow(clippy::too_many_arguments)] // mirrors upstream's RHR6 inputs one to one
fn seal_biscuit<R: Rng>(
    ad_m: &[u8; KEY_LEN],
    key: &BiscuitKey,
    slot: usize,
    pidt: &[u8; KEY_LEN],
    no: u128,
    ck: &Secret<KEY_LEN>,
    sidi: &[u8; SID_LEN],
    sidr: &[u8; SID_LEN],
    rng: &mut R,
) -> Result<[u8; BISCUIT_CT_LEN], Error> {
    let mut pt = Secret::<BISCUIT_PT_LEN>::zero();
    let (pid_f, rest) = pt.expose_mut().split_first_chunk_mut::<KEY_LEN>().ok_or(Error::Internal)?;
    *pid_f = *pidt;
    let (no_f, ck_f) = rest.split_first_chunk_mut::<BISCUIT_NO_LEN>().ok_or(Error::Internal)?;
    no_f.copy_from_slice(no.to_le_bytes().get(..BISCUIT_NO_LEN).ok_or(Error::Internal)?);
    ck_f.copy_from_slice(ck.expose());
    trace("biscuit.pt", pt.expose());
    let ad = crypto::kh_public(&crypto::kh_public(ad_m, sidi)?, sidr)?;
    trace("biscuit.ad", &ad);
    let mut n = [0u8; XNONCE_LEN];
    rng.fill(&mut n).map_err(|_| Error::Rng)?;
    if let Some(b) = n.first_mut() {
        *b = (*b & 0x7f) | (u8::from(slot == 1) << 7);
    }
    let mut out = [0u8; BISCUIT_CT_LEN];
    crypto::xaead_seal(&key.key, &n, &ad, pt.expose(), &mut out)?;
    Ok(out)
}
