//! Rosenpass PD (M3 plan C3): the V02 responder. InitHello and InitConf
//! arrive from `ingress`; RespHello and EmptyData go back to it, and each
//! fresh OSK goes to `hs` as a `PskInstall` over a scrubbing link. The
//! McEliece secret stays in `pqkey` (PPC); the public keys are embedded in
//! this ELF from the compiled configuration (law L6). Tainted (law L1).

#![no_std]
#![no_main]

use audit_event::{CostHighWater, Event};
use layout::pq as ch;
use msgs::{Endpoint, RpDatagram};
use pdkit::{Audit, Buf, Rx, Tx};
use pqkey_core::{LABEL_PQ_BOOT_SEED, LABEL_PQ_DECAPS, MAX_WORDS, OK, PQ_DECAPS_REQ_WORDS};
use ring::pass::{any_full, drain, run_passes};
use rosenpass_core::{
    Conf, Decaps, DecapsError, Error, KEY_LEN, Kyber512, McEliece460896, Responder, Rng, RngError, SHK_LEN,
    SPK_LEN, Secret, Seams, crypto,
};
use rosenpass_wire::{INIT_CONF_LEN, INIT_HELLO_LEN, RESP_HELLO_LEN, SCT_LEN};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, MessageInfo, debug_println, memory_region_symbol, protection_domain,
    with_msg_regs, with_msg_regs_mut,
};

const PQKEY: Channel = Channel::new(ch::CH_PQKEY);
const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const HS: Channel = Channel::new(ch::CH_HS);
const TIMER: Channel = Channel::new(ch::CH_TIMER);

const PEERS: usize = config::PEERS.len();
// The configuration was validated against this bound at build time; the
// assertion keeps the responder's table from silently diverging from it.
const _: () = assert!(PEERS <= config::MAX_PEERS);

/// Our McEliece public key and each peer's, in `config::PEERS` order (about
/// 4.5 MiB). Only this crate expands the macros, so only `pq` carries them.
static SPKM: &[u8; SPK_LEN] = config::gateway_rp_public!();
static SPKTS: [&[u8; SPK_LEN]; PEERS] = config::peer_rp_publics!();

/// Messages taken from `ingress` per pass. Each InitHello costs a
/// decapsulation and two encapsulations, so passes stay short and every
/// pass ends by notifying the peers it answered.
const PASS_MSGS: usize = 4;

/// One PPC to `pqkey`: `req` (whole words) out, exactly `reply.len()` bytes
/// back. Returns `pqkey`'s reply label; anything but a full `OK` reply
/// leaves `reply` zero. Message registers are zeroed afterwards.
fn pqkey_call(label: u64, req: &[u8], reply: &mut [u8]) -> u64 {
    let (words, rest) = req.as_chunks::<8>();
    if !rest.is_empty() || words.len() > MAX_WORDS {
        return pqkey_core::ERR_BAD_REQUEST;
    }
    with_msg_regs_mut(|mrs| {
        for (dst, w) in mrs.iter_mut().zip(words) {
            *dst = u64::from_le_bytes(*w);
        }
    });
    let info = PQKEY.pp_call(MessageInfo::new(label, words.len()));
    let (out, out_rest) = reply.as_chunks_mut::<8>();
    let ok = info.label() == OK && info.count() == out.len() && out_rest.is_empty();
    if ok {
        with_msg_regs(|mrs| {
            for (dst, src) in out.iter_mut().zip(mrs) {
                *dst = src.to_le_bytes();
            }
        });
    }
    with_msg_regs_mut(|mrs| mrs.iter_mut().take(MAX_WORDS).for_each(|w| *w = 0));
    if ok {
        return OK;
    }
    reply.fill(0);
    if info.label() == OK { pqkey_core::ERR_BAD_REQUEST } else { info.label() }
}

/// `pqkey`'s `PQ_DECAPS`: the ciphertext in 24 words, the last 4 bytes zero.
struct PqKey;

impl Decaps for PqKey {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut req = [0u8; PQ_DECAPS_REQ_WORDS * 8];
        req.get_mut(..SCT_LEN).ok_or(DecapsError::Refused)?.copy_from_slice(sct);
        let mut shk = Secret::<SHK_LEN>::zero();
        match pqkey_call(LABEL_PQ_DECAPS, &req, shk.expose_mut()) {
            OK => Ok(shk),
            pqkey_core::ERR_RATE_LIMITED => Err(DecapsError::RateLimited),
            _ => Err(DecapsError::Refused),
        }
    }
}

/// The hedged source (hs-core's `HedgedEntropy` pattern): each 32-byte
/// block is BLAKE2b keyed with the boot seed over a draw counter, CNTPCT
/// and RNDR, so it stays unpredictable if either the seed or RNDR is
/// sound, and never repeats within a boot. A failed RNDR read fails the
/// draw.
struct Hedged {
    seed: Secret<KEY_LEN>,
    draws: u64,
}

impl Rng for Hedged {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        for chunk in out.chunks_mut(KEY_LEN) {
            let rndr = cpu::rndr().ok_or(RngError)?;
            self.draws = self.draws.checked_add(1).ok_or(RngError)?;
            let mut block = Secret::<KEY_LEN>::zero();
            crypto::blake2b(
                self.seed.expose(),
                &[&self.draws.to_le_bytes(), &cpu::cntpct().to_le_bytes(), &rndr.to_le_bytes()],
                block.expose_mut(),
            )
            .map_err(|_| RngError)?;
            chunk.copy_from_slice(block.expose().get(..chunk.len()).ok_or(RngError)?);
        }
        Ok(())
    }
}

/// The audit event for a refused message.
fn reject_event(e: Error) -> Event {
    match e {
        Error::Rng => Event::RpRngFailed,
        Error::Decaps(DecapsError::RateLimited) => Event::RpDecapsRateLimited,
        Error::BiscuitReplay => Event::RpBiscuitReplay,
        Error::Malformed
        | Error::BadMac
        | Error::Decaps(DecapsError::Refused)
        | Error::Encaps(_)
        | Error::UnknownPeer
        | Error::Auth
        | Error::NoBiscuitKey
        | Error::DuplicatePeer
        | Error::Internal => Event::HandshakeOther,
    }
}

fn send_rp(tx: &mut Tx, scratch: &mut Buf, audit: &mut Audit, m: RpDatagram<'_>) -> bool {
    let mut enc = [0u8; layout::NET_BUF_SIZE];
    match m.encode(&mut enc) {
        Some(len) => pdkit::send(tx, scratch, enc.get(..len).unwrap_or(&[]), audit),
        None => false,
    }
}

/// Sends `PskInstall` to `hs`, encoded straight into the scrubbing link's
/// staging buffer, which is zeroed before returning.
fn send_psk(tx: &mut Tx, scratch: &mut Buf, audit: &mut Audit, peer: usize, osk: &Secret<KEY_LEN>) -> bool {
    let Ok(peer) = u16::try_from(peer) else { return false };
    if let Err(e) = tx.reclaim() {
        audit.link_error(e);
    }
    let r = tx.send_with(scratch, |s| msgs::PskInstall { peer, osk: osk.expose() }.encode(s));
    scratch.fill(0);
    match r {
        Ok(sent) => sent,
        Err(e) => {
            audit.link_error(e);
            false
        }
    }
}

struct Pq {
    from_ingress: Rx,
    to_ingress: Tx,
    to_hs: Tx,
    audit: Audit,
    responder: Responder<'static, PEERS>,
    rng: Hedged,
    cost: CostHighWater,
    freq: u64,
    input: Buf,
    resp_hello: [u8; RESP_HELLO_LEN],
    scratch: Buf,
}

fn halt(msg: &str) -> ! {
    debug_println!("pq: {msg}");
    panic!("pq: halted");
}

#[protection_domain]
fn init() -> Pq {
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout` (checked by tools/laws and layout tests).
    let (from_ingress, to_ingress, to_hs, audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(ipq_used: *mut u8),
                memory_region_symbol!(ipq_free: *mut u8),
                memory_region_symbol!(ipq_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(pqi_used: *mut u8),
                memory_region_symbol!(pqi_free: *mut u8),
                memory_region_symbol!(pqi_data: *mut u8),
            ),
            pdkit::tx_scrubbing(
                memory_region_symbol!(pqh_used: *mut u8),
                memory_region_symbol!(pqh_free: *mut u8),
                memory_region_symbol!(pqh_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_pq: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    let freq = cpu::checked_frequency(cpu::cntfrq())
        .unwrap_or_else(|| halt("CNTFRQ is 0; refusing to run without a clock"));
    // The embedded keys must be the configured ones (M3 plan S8).
    if secret_blob::blake2s(&[SPKM]) != config::GATEWAY_RP_HASH {
        halt("gateway McEliece public key does not match its rp_hash");
    }
    for (i, (spkt, peer)) in SPKTS.iter().zip(config::PEERS).enumerate() {
        if secret_blob::blake2s(&[*spkt]) != peer.rp_hash {
            debug_println!("pq: peer {i} McEliece public key does not match its rp_hash");
            panic!("pq: halted");
        }
    }
    // Once per boot. If `pqkey` halted at boot this blocks, which still
    // fails closed: no PSK ever reaches `hs`, so WireGuard is refused.
    let mut seed = Secret::<KEY_LEN>::zero();
    if pqkey_call(LABEL_PQ_BOOT_SEED, &[], seed.expose_mut()) != OK {
        halt("no boot seed from pqkey");
    }
    let mut rng = Hedged { seed, draws: 0 };
    let mut responder = match Responder::new(SPKM, SPKTS, &mut rng) {
        Ok(r) => r,
        Err(Error::Rng) => halt("RNDR unavailable"),
        Err(_) => halt("init failed"),
    };
    let mut audit = audit;
    // The first biscuit key; a failure is retried on every timer tick.
    if let Err(e) = responder.tick(cpu::now_ns(), &mut rng) {
        audit.record(reject_event(e));
    }
    debug_println!("pq: ready");
    Pq {
        from_ingress,
        to_ingress,
        to_hs,
        audit,
        responder,
        rng,
        cost: CostHighWater::new(),
        freq,
        input: [0; layout::NET_BUF_SIZE],
        resp_hello: [0; RESP_HELLO_LEN],
        scratch: [0; layout::NET_BUF_SIZE],
    }
}

#[derive(Default)]
struct Wake {
    ingress: bool,
    hs: bool,
}

impl Pq {
    /// Takes and handles one datagram from `ingress`; `false` when the
    /// input is empty.
    fn one(&mut self, wake: &mut Wake) -> bool {
        let Some(n) = pdkit::recv(&mut self.from_ingress, &mut self.input, &mut self.audit) else { return false };
        // The buffer went back to `ingress`, which reclaims on notification.
        wake.ingress = true;
        let mut msg = [0u8; layout::NET_BUF_SIZE];
        let decoded = RpDatagram::decode(self.input.get(..n).unwrap_or(&[])).ok().and_then(|d| {
            let dst = msg.get_mut(..d.msg.len())?;
            dst.copy_from_slice(d.msg);
            Some((d.peer, d.msg.len()))
        });
        self.input.fill(0);
        match decoded {
            Some((src, INIT_HELLO_LEN)) => self.init_hello(src, msg.get(..INIT_HELLO_LEN).unwrap_or(&[]), wake),
            Some((src, INIT_CONF_LEN)) => self.init_conf(src, msg.get(..INIT_CONF_LEN).unwrap_or(&[]), wake),
            // `ingress` forwards InitHello and InitConf only.
            Some(_) => self.audit.record(Event::RpTypeDropped),
            None => self.audit.record(Event::BadDescriptor),
        }
        msg.fill(0);
        true
    }

    /// IHR/RHR, then the RespHello to `ingress`. The wall-clock cost of the
    /// whole path, preemption included, feeds `RpCostHighWater` (VE10).
    fn init_hello(&mut self, src: Endpoint, msg: &[u8], wake: &mut Wake) {
        let start = cpu::cntpct();
        let Self { responder, rng, resp_hello, to_ingress, scratch, audit, cost, freq, .. } = self;
        let mut seams = Seams { decaps: &mut PqKey, kyber: &mut Kyber512, mceliece: &mut McEliece460896, rng };
        match responder.handle_init_hello(msg, cpu::now_ns(), &mut seams, resp_hello) {
            Ok(_) => {
                wake.ingress |= send_rp(to_ingress, scratch, audit, RpDatagram { peer: src, msg: resp_hello.as_slice() });
                audit.record(Event::RpInitHello);
                let us = cpu::ticks_to_ns(cpu::cntpct().saturating_sub(start), *freq) / 1000;
                if let Some(ev) = cost.observe(u32::try_from(us).unwrap_or(u32::MAX)) {
                    audit.record(ev);
                }
            }
            Err(e) => audit.record(reject_event(e)),
        }
        resp_hello.fill(0);
        scratch.fill(0);
    }

    /// ICR, then the OSK export order (M3 plan F8, S15): `PskInstall` to
    /// `hs` first; only once it was sent is the InitConf committed and the
    /// EmptyData sent. A failed send leaves no trace, so the client's
    /// retransmission is processed again.
    fn init_conf(&mut self, src: Endpoint, msg: &[u8], wake: &mut Wake) {
        let Self { responder, to_ingress, to_hs, scratch, audit, .. } = self;
        let now = cpu::now_ns();
        let response = match responder.handle_init_conf(msg, now) {
            Ok(Conf::Retransmission { response, .. }) => response,
            Ok(Conf::Fresh(pending)) => {
                let install = pending.psk_install();
                if !send_psk(to_hs, scratch, audit, install.peer, install.osk) {
                    responder.abort_conf(pending);
                    audit.record(Event::RpPskInstallFailed);
                    return;
                }
                wake.hs = true;
                match responder.commit_conf(pending, now) {
                    Ok(response) => {
                        audit.record(Event::RpPskExported);
                        response
                    }
                    Err(e) => {
                        audit.record(reject_event(e));
                        return;
                    }
                }
            }
            Err(e) => {
                audit.record(reject_event(e));
                return;
            }
        };
        wake.ingress |= send_rp(to_ingress, scratch, audit, RpDatagram { peer: src, msg: &response });
        scratch.fill(0);
    }
}

impl Wake {
    fn notify(&self) {
        if self.ingress {
            INGRESS.notify();
        }
        if self.hs {
            HS.notify();
        }
    }
}

/// One handler run: the wake-ups gathered since the last `end_pass`.
struct Pass<'a> {
    pq: &'a mut Pq,
    wake: Wake,
}

impl ring::pass::Pass for Pass<'_> {
    fn serve(&mut self) -> bool {
        // `hs` notifies once it has copied a PskInstall out: take the
        // buffer back now, which zeroes it (law L12).
        if let Err(e) = self.pq.to_hs.reclaim() {
            self.pq.audit.link_error(e);
        }
        let n = drain(PASS_MSGS, || self.pq.one(&mut self.wake));
        any_full(&[n], PASS_MSGS)
    }

    fn end_pass(&mut self) {
        core::mem::take(&mut self.wake).notify();
        self.pq.audit.flush();
    }
}

impl Handler for Pq {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(TIMER) {
            // Rotates the biscuit key once it no longer seals; a failed draw
            // leaves none, so InitHello and InitConf are refused until a
            // later tick succeeds.
            if let Err(e) = self.responder.tick(cpu::now_ns(), &mut self.rng) {
                self.audit.record(reject_event(e));
            }
        }
        run_passes(&mut Pass { pq: self, wake: Wake::default() });
        Ok(())
    }
}
