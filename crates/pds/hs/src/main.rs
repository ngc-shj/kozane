//! Handshake PD (plan C11): initiations from `ingress` → session install
//! to `data`, then the response to `ingress`. Static secrets stay in `key`
//! (PPC); this PD holds only ephemeral state. Tainted (law L1).

#![no_std]
#![no_main]

use audit_event::Event;
use hs_core::{Handshaker, HedgedEntropy, KeyCall, KeyClient, Outcome, Peers};
use key_core::MAX_WORDS;
use layout::hs as ch;
use pdkit::{Audit, Buf, Rx, Tx};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, MessageInfo, debug_println, memory_region_symbol, protection_domain,
    with_msg_regs, with_msg_regs_mut,
};

const KEY: Channel = Channel::new(ch::CH_KEY);
const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const DATA: Channel = Channel::new(ch::CH_DATA);
const MAX_PEERS: usize = config::MAX_PEERS;
// The configuration was validated against this bound at build time; the
// assertion keeps the PD's tables from silently diverging from it.
const _: () = assert!(config::PEERS.len() <= MAX_PEERS);

/// `key` over PPC. Request and reply registers are zeroed after each call.
struct Ppc;

impl KeyCall for Ppc {
    fn call(&mut self, label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
        if req.len() > MAX_WORDS {
            return (key_core::ERR_BAD_REQUEST, 0);
        }
        with_msg_regs_mut(|mrs| {
            for (dst, src) in mrs.iter_mut().zip(req) {
                *dst = *src;
            }
        });
        let info = KEY.pp_call(MessageInfo::new(label, req.len()));
        let n = info.count().min(reply.len()).min(MAX_WORDS);
        with_msg_regs(|mrs| {
            for (dst, src) in reply.iter_mut().zip(mrs.iter().take(n)) {
                *dst = *src;
            }
        });
        with_msg_regs_mut(|mrs| mrs.iter_mut().take(MAX_WORDS).for_each(|w| *w = 0));
        (info.label(), n)
    }
}

struct Hw;

impl hs_core::Hardware for Hw {
    fn counter(&mut self) -> u64 {
        cpu::cntpct()
    }
    fn random(&mut self) -> Option<u64> {
        cpu::rndr()
    }
}

struct Hs {
    from_ingress: Rx,
    to_ingress: Tx,
    to_data: Tx,
    audit: Audit,
    key: KeyClient<Ppc>,
    entropy: HedgedEntropy<Hw>,
    handshaker: Handshaker<MAX_PEERS>,
    peers: [[u8; 32]; MAX_PEERS],
    peer_count: usize,
    input: Buf,
    install: Buf,
    response: Buf,
    scratch: Buf,
}

fn halt(msg: &str) -> ! {
    debug_println!("hs: {msg}");
    panic!("hs: halted");
}

#[protection_domain]
fn init() -> Hs {
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout` (checked by tools/laws and layout tests).
    let (from_ingress, to_ingress, to_data, audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(ih_used: *mut u8),
                memory_region_symbol!(ih_free: *mut u8),
                memory_region_symbol!(ih_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(hi_used: *mut u8),
                memory_region_symbol!(hi_free: *mut u8),
                memory_region_symbol!(hi_data: *mut u8),
            ),
            pdkit::tx_scrubbing(
                memory_region_symbol!(hd_used: *mut u8),
                memory_region_symbol!(hd_free: *mut u8),
                memory_region_symbol!(hd_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_hs: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    if cpu::checked_frequency(cpu::cntfrq()).is_none() {
        halt("CNTFRQ is 0; refusing to run without a clock");
    }
    let mut key = KeyClient::new(Ppc);
    let seed = key.boot_seed().unwrap_or_else(|_| halt("no boot seed from key"));
    let handshaker = Handshaker::new(&config::GATEWAY_PUBLIC, &seed).unwrap_or_else(|_| halt("init failed"));
    let mut peers = [[0u8; 32]; MAX_PEERS];
    for (dst, p) in peers.iter_mut().zip(config::PEERS) {
        *dst = p.public;
    }
    debug_println!("hs: ready");
    Hs {
        from_ingress,
        to_ingress,
        to_data,
        audit,
        key,
        entropy: HedgedEntropy::new(seed, Hw),
        handshaker,
        peers,
        peer_count: config::PEERS.len(),
        input: [0; layout::NET_BUF_SIZE],
        install: [0; layout::NET_BUF_SIZE],
        response: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
    }
}

impl Hs {
    /// Returns (sent to data, sent to ingress, consumed input).
    fn poll(&mut self) -> (bool, bool, bool) {
        let (mut to_data, mut to_ingress, mut consumed) = (false, false, false);
        while let Some(n) = pdkit::recv(&mut self.from_ingress, &mut self.input, &mut self.audit) {
            consumed = true;
            let peers = Peers(self.peers.get(..self.peer_count).unwrap_or(&[]));
            let out = self.handshaker.handle(
                self.input.get(..n).unwrap_or(&[]),
                cpu::now_ns(),
                &mut self.key,
                &mut self.entropy,
                &peers,
                &mut self.install,
                &mut self.response,
            );
            match out {
                Outcome::Accepted { install_len, response_len, .. } => {
                    // Install first: `data` must know the session before
                    // the initiator can use it (plan, Ordering).
                    let installed = pdkit::send(
                        &mut self.to_data,
                        &mut self.scratch,
                        self.install.get(..install_len).unwrap_or(&[]),
                        &mut self.audit,
                    );
                    self.install.fill(0);
                    self.scratch.fill(0);
                    if installed {
                        to_data = true;
                        DATA.notify();
                        if pdkit::send(
                            &mut self.to_ingress,
                            &mut self.scratch,
                            self.response.get(..response_len).unwrap_or(&[]),
                            &mut self.audit,
                        ) {
                            to_ingress = true;
                            self.audit.record(Event::HandshakeOk);
                        }
                    }
                }
                Outcome::Rejected(r) => self.audit.record(hs_core::reject_event(r, self.key.last_error)),
                Outcome::BadInput | Outcome::NoBuffer => self.audit.record(Event::HandshakeOther),
            }
        }
        (to_data, to_ingress, consumed)
    }
}

impl Handler for Hs {
    type Error = Infallible;

    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        // Scrub returned install buffers now, not at the next handshake:
        // `data` notifies as soon as it has copied an install out, so the
        // transport keys leave the shared `hd` region within one wakeup
        // (law L12). The 1 Hz timer tick retries if that notify was missed.
        if let Err(e) = self.to_data.reclaim() {
            self.audit.link_error(e);
        }
        let (_, to_ingress, consumed) = self.poll();
        if to_ingress || consumed {
            INGRESS.notify();
        }
        self.audit.flush();
        Ok(())
    }
}
