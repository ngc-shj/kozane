//! Rosenpass PD (M3 plan C3): the V02 responder. InitHello and InitConf
//! arrive from `ingress`; RespHello and EmptyData go back to it, and each
//! fresh OSK goes to `hs` as a `PskInstall` over a scrubbing link. The
//! McEliece secret stays in `pqkey` (PPC); the public keys are embedded in
//! this ELF from the compiled configuration (law L6). Tainted (law L1).

#![no_std]
#![no_main]

use audit_event::{CostHighWater, Event};
use layout::pq as ch;
use msgs::{RP_NO_PEER, RpDatagram, RpReply};
use pdkit::{Audit, Buf, Rx, Take, Tx};
use pqkey_core::{LABEL_PQ_BOOT_SEED, LABEL_PQ_DECAPS, MAX_WORDS, OK, PQ_DECAPS_REQ_WORDS};
use ring::link::Taken;
use ring::pass::{any_full, drain, run_passes};
use rosenpass_core::{
    Conf, Decaps, DecapsError, Error, HedgeHw, Hedged, KEY_LEN, Kyber512, McEliece460896, Responder, SHK_LEN,
    SPK_LEN, Secret, Seams,
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
// A configured peer's index travels in `RpReply` as one byte, apart from
// `RP_NO_PEER`.
const _: () = assert!(config::MAX_PEERS < RP_NO_PEER as usize);

/// Our McEliece public key and each peer's, in `config::PEERS` order (about
/// 4.5 MiB). Only `pq` expands both macros; `ingress` expands
/// `gateway_rp_public!` alone, to derive its mac key.
static SPKM: &[u8; SPK_LEN] = config::gateway_rp_public!();
static SPKTS: [&[u8; SPK_LEN]; PEERS] = config::peer_rp_publics!();

/// Messages taken from `ingress` per pass. One: an InitHello costs seconds
/// of wall time at pq's budget (MCE-COST: 8.5 s median, 16.1 s max), and
/// each pass ends by notifying its peers and flushing the audit records, so
/// every answer, `PskInstall` and record leaves after its own message.
const PASS_MSGS: usize = 1;

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

/// `Hedged`'s hardware: RNDR and CNTPCT.
struct Cpu;

impl HedgeHw for Cpu {
    fn rndr(&mut self) -> Option<u64> {
        cpu::rndr()
    }

    fn counter(&mut self) -> u64 {
        cpu::cntpct()
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

/// Sends the one completion record of the input being handled.
fn send_record(tx: &mut Tx, scratch: &mut Buf, audit: &mut Audit, r: RpReply<'_>) -> bool {
    let mut enc = [0u8; layout::NET_BUF_SIZE];
    let sent = match r.encode(&mut enc) {
        Some(len) => pdkit::send(tx, scratch, enc.get(..len).unwrap_or(&[]), audit),
        None => false,
    };
    enc.fill(0);
    sent
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
    rng: Hedged<Cpu>,
    cost: CostHighWater,
    freq: u64,
    input: Buf,
    resp_hello: [u8; RESP_HELLO_LEN],
    scratch: Buf,
    /// A completion record could not be sent, so the input is still held
    /// and the Rosenpass path is stopped for good (M3b plan C3).
    stuck: bool,
    stack: cpu::StackProbe,
}

/// `stack_size` of `pq` in system/secureos.system (the integration suite
/// checks that this constant matches it).
const STACK_SIZE: usize = 0x20_000;


fn halt(msg: &str) -> ! {
    debug_println!("pq: {msg}");
    panic!("pq: halted");
}

#[protection_domain]
fn init() -> Pq {
    // SAFETY: first thing in init, with STACK_SIZE this PD's stack_size.
    let stack = unsafe { cpu::StackProbe::paint(STACK_SIZE) };
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
    let mut rng = Hedged::new(seed, Cpu);
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
        stuck: false,
        stack,
    }
}

#[derive(Default)]
struct Wake {
    ingress: bool,
    hs: bool,
}

impl Pq {
    /// Takes one datagram from `ingress`, handles it, sends exactly one
    /// completion record and only then returns the input's buffer (M3b
    /// plan C3, the order contract). `false` when the input is empty.
    ///
    /// `ingress` pairs each record with its record of the forward. The
    /// completion ring's Release (the record) is program-ordered before the
    /// input ring's Release (the return), and `ingress` reads the return
    /// with an Acquire before draining records, so every return it counts
    /// has its record visible. Taking the next input before the return is
    /// refused by the held receive.
    fn one(&mut self, wake: &mut Wake) -> bool {
        if self.stuck {
            return false;
        }
        let n = match pdkit::take(&mut self.from_ingress, &mut self.input, &mut self.audit) {
            Take::Empty => return false,
            Take::Skipped => return true,
            Take::Got(Taken::Payload(n)) => Some(n),
            Take::Got(Taken::Unreadable) => None,
        };
        let mut msg = [0u8; layout::NET_BUF_SIZE];
        let decoded = n.and_then(|n| RpDatagram::decode(self.input.get(..n).unwrap_or(&[])).ok()).and_then(|d| {
            let dst = msg.get_mut(..d.msg.len())?;
            dst.copy_from_slice(d.msg);
            Some(d.msg.len())
        });
        self.input.fill(0);
        let mut reply = [0u8; RESP_HELLO_LEN];
        let record = match decoded {
            Some(INIT_HELLO_LEN) => self.init_hello(msg.get(..INIT_HELLO_LEN).unwrap_or(&[]), &mut reply),
            Some(INIT_CONF_LEN) => self.init_conf(msg.get(..INIT_CONF_LEN).unwrap_or(&[]), &mut reply, wake),
            // `ingress` forwards InitHello and InitConf only.
            Some(_) => {
                self.audit.record(Event::RpTypeDropped);
                None
            }
            None => {
                self.audit.record(Event::BadDescriptor);
                None
            }
        };
        msg.fill(0);
        let r = match record {
            Some((index, len)) => RpReply::Reply { index, msg: reply.get(..len).unwrap_or(&[]) },
            None => RpReply::NoReply,
        };
        let Self { to_ingress, scratch, audit, from_ingress, .. } = self;
        let sent = send_record(to_ingress, scratch, audit, r);
        reply.fill(0);
        scratch.fill(0);
        if !sent {
            // The link has room for a record per input in flight, so only a
            // broken link gets here. Returning the input without its record
            // would put `ingress` out of step; keep it and stop.
            self.stuck = true;
            self.audit.record(Event::RpPqRecordStuck);
            return false;
        }
        wake.ingress = true;
        pdkit::release(from_ingress, audit);
        true
    }

    /// IHR/RHR into `reply`. The wall-clock cost of the whole path,
    /// preemption included, feeds `RpCostHighWater` (VE10). Returns the
    /// record's index and length, or `None` for `NoReply`.
    fn init_hello(&mut self, msg: &[u8], reply: &mut [u8; RESP_HELLO_LEN]) -> Option<(u8, usize)> {
        let start = cpu::cntpct();
        let Self { responder, rng, resp_hello, audit, cost, freq, .. } = self;
        let mut seams = Seams { decaps: &mut PqKey, kyber: &mut Kyber512, mceliece: &mut McEliece460896, rng };
        let out = match responder.handle_init_hello(msg, cpu::now_ns(), &mut seams, resp_hello) {
            Ok(_) => {
                reply.copy_from_slice(resp_hello);
                audit.record(Event::RpInitHello);
                let us = cpu::ticks_to_ns(cpu::cntpct().saturating_sub(start), *freq) / 1000;
                cost.observe_with(u32::try_from(us).unwrap_or(u32::MAX), |ev| audit.record_delivered(ev));
                Some((RP_NO_PEER, RESP_HELLO_LEN))
            }
            Err(e) => {
                audit.record(reject_event(e));
                None
            }
        };
        resp_hello.fill(0);
        out
    }

    /// ICR, then the OSK export order (M3 plan F8, S15): `PskInstall` to
    /// `hs` first; only once it was sent is the InitConf committed and the
    /// EmptyData produced. A failed send leaves no trace, so the client's
    /// retransmission is processed again. Returns the record's index (the
    /// configured peer) and length, or `None` for `NoReply`.
    fn init_conf(&mut self, msg: &[u8], reply: &mut [u8; RESP_HELLO_LEN], wake: &mut Wake) -> Option<(u8, usize)> {
        let Self { responder, to_hs, scratch, audit, .. } = self;
        let now = cpu::now_ns();
        let (peer, response) = match responder.handle_init_conf(msg, now) {
            Ok(Conf::Retransmission { peer, response }) => (peer, response),
            Ok(Conf::Fresh(pending)) => {
                let install = pending.psk_install();
                let sent = send_psk(to_hs, scratch, audit, install.peer, install.osk);
                scratch.fill(0);
                if !sent {
                    responder.abort_conf(pending);
                    audit.record(Event::RpPskInstallFailed);
                    return None;
                }
                wake.hs = true;
                let peer = pending.peer();
                match responder.commit_conf(pending, now) {
                    Ok(response) => {
                        audit.record(Event::RpPskExported);
                        (peer, response)
                    }
                    Err(e) => {
                        audit.record(reject_event(e));
                        return None;
                    }
                }
            }
            Err(e) => {
                audit.record(reject_event(e));
                return None;
            }
        };
        // `PEERS <= MAX_PEERS` (asserted above), so the index fits a byte
        // and never collides with `RP_NO_PEER`.
        let index = u8::try_from(peer).ok().filter(|i| *i != RP_NO_PEER)?;
        let dst = reply.get_mut(..response.len())?;
        dst.copy_from_slice(&response);
        Some((index, response.len()))
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
        // Once a second: the scan costs pq budget it needs under load. The
        // mark goes out as an audit record, not a console line, which would
        // interleave with `audit`'s own lines and break the ones awaited.
        if channels.contains(TIMER)
            && let Some((hw, _)) = self.stack.deeper()
        {
            self.audit.record(Event::StackHighWater { bytes: u32::try_from(hw).unwrap_or(u32::MAX) });
            self.audit.flush();
        }
        Ok(())
    }
}
