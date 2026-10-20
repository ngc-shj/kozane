//! `ingress` v2 (plan C14): the outside NIC's only consumer. Answers ARP,
//! hands vetted initiations to `hs`, transport messages to `data` and
//! vetted Rosenpass InitHello/InitConf to `pq` (M3 plan C4), and frames
//! their replies to the peers' endpoints, which it alone tracks.
//! Under load it answers initiations without a valid mac2 with cookie
//! replies (plan M2.5 C4), so it holds the cookie secret (in `cookie`); a
//! compromise yields only that, which weakens DoS protection and nothing
//! else. It holds no static or session key (law L1).

#![no_std]
#![no_main]

mod cookie;
mod rp_cookie;
mod rp_mac;

use audit_event::Event;
use cookie::CookieAdapter;
use ingress_core::{
    Buckets, Config, Endpoint, Gate, Mac1, Outcome, PassIo, PqSync, RP_COOKIE_REPLY_LEN, RP_RECORD_MAX, RpGate, RpKind,
    RpMac, RpOutcome, SyncOutcome, TxTier, emit_udp, respond, rp_classify, rp_tx_allowed, run_passes,
};
use layout::ingress as ch;
use msgs::ToIngress;
use pdkit::{Audit, Buf, Rx, Tx};
use ring::pass::drain;
use rp_cookie::RpCookieAdapter;
use rp_mac::RpMacKey;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain};
use wg_core::crypto;
use wg_core::noise::LABEL_MAC1;
use wg_core::wire::{COOKIE_REPLY_LEN, INITIATION_LEN, INITIATION_MAC1_OFFSET};

const ETH_OUT: Channel = Channel::new(ch::CH_ETH_OUT);
const HS: Channel = Channel::new(ch::CH_HS);
const DATA: Channel = Channel::new(ch::CH_DATA);
const PQ: Channel = Channel::new(ch::CH_PQ);
const MAX_PEERS: usize = config::MAX_PEERS;
// The configuration was validated against this bound at build time; the
// assertion keeps the PD's tables from silently diverging from it.
const _: () = assert!(config::PEERS.len() <= MAX_PEERS);
const BUCKETS: usize = 64;
// The Gate's backlog and TX-reserve thresholds are fractions of the ring
// size it was written against.
const _: () = assert!(ingress_core::NET_BUFFERS == layout::NET_BUFFERS, "ingress-core NET_BUFFERS differs from layout");
// The demux needs two distinct ports (config validates the same).
const _: () = assert!(config::RP_PORT != 0 && config::RP_PORT != config::LISTEN_PORT, "RP_PORT must be nonzero and distinct");
// ingress-core's Rosenpass type filter is written against rosenpass-wire's
// values, which it does not depend on.
const _: () = assert!(ingress_core::RP_MSG_INIT_HELLO == rosenpass_wire::MSG_INIT_HELLO);
const _: () = assert!(ingress_core::RP_INIT_HELLO_LEN == rosenpass_wire::INIT_HELLO_LEN);
const _: () = assert!(ingress_core::RP_MSG_INIT_CONF == rosenpass_wire::MSG_INIT_CONF);
const _: () = assert!(ingress_core::RP_INIT_CONF_LEN == rosenpass_wire::INIT_CONF_LEN);
// msgs' accepted Rosenpass lengths are rosenpass-wire's, which it does not
// depend on.
const _: () = assert!(
    msgs::RP_LENS[0] == rosenpass_wire::INIT_HELLO_LEN
        && msgs::RP_LENS[1] == rosenpass_wire::RESP_HELLO_LEN
        && msgs::RP_LENS[2] == rosenpass_wire::INIT_CONF_LEN
        && msgs::RP_LENS[3] == rosenpass_wire::EMPTY_DATA_LEN,
    "msgs::RP_LENS differs from rosenpass-wire"
);
// An encoded `RpDatagram` (endpoint + the longest message) fits a buffer.
const _: () = assert!(6 + rosenpass_wire::RESP_HELLO_LEN <= layout::NET_BUF_SIZE);
// The completion records `sync_pq` pairs: ingress-core's and msgs' reply
// lengths are rosenpass-wire's, a record fits a buffer, and the `pq` link
// has a buffer for every record ever owed (M3b plan C3).
const _: () = assert!(ingress_core::RP_RESP_HELLO_LEN == rosenpass_wire::RESP_HELLO_LEN);
const _: () = assert!(ingress_core::RP_EMPTY_DATA_LEN == rosenpass_wire::EMPTY_DATA_LEN);
const _: () = assert!(
    msgs::RP_REPLY_LENS[0] == rosenpass_wire::RESP_HELLO_LEN && msgs::RP_REPLY_LENS[1] == rosenpass_wire::EMPTY_DATA_LEN
);
const _: () = assert!(ingress_core::RP_RECORD_MAX <= layout::NET_BUF_SIZE);
const _: () = assert!(layout::NET_BUFFERS >= ingress_core::RP_IN_FLIGHT);
// The cookie gate's layout and peer count are rosenpass-wire's, rosenpass-
// core's and config's, which ingress-core does not depend on (M3b plan C2).
const _: () = assert!(ingress_core::RP_MAX_PEERS == config::MAX_PEERS);
const _: () = assert!(ingress_core::RP_SID_AT == rosenpass_wire::HEADER_LEN);
const _: () = assert!(ingress_core::RP_COOKIE_AT == rosenpass_wire::cookie_offset(rosenpass_wire::INIT_HELLO_LEN));
const _: () = assert!(ingress_core::RP_COOKIE_REPLY_LEN == rosenpass_core::cookie::COOKIE_REPLY_LEN);

const CONFIG: Config = Config {
    mac: config::OUTSIDE_MAC,
    ipv4: config::OUTSIDE_IP,
    router_mac: config::OUTSIDE_ROUTER_MAC,
    port: config::LISTEN_PORT,
    rp_port: config::RP_PORT,
};

/// mac1 = MAC(HASH(LABEL_MAC1 ‖ S_pub), msg[..116]).
struct GatewayMac1 {
    key: [u8; 32],
}

impl Mac1 for GatewayMac1 {
    fn verify(&self, msg: &[u8; INITIATION_LEN]) -> bool {
        let (covered, rest) = msg.split_at(INITIATION_MAC1_OFFSET);
        match (crypto::mac(&self.key, &[covered]), rest.get(..16)) {
            (Ok(m), Some(got)) => crypto::ct_eq(&m, got),
            _ => false,
        }
    }
}

impl RpMac for RpMacKey {
    fn verify(&self, msg: &[u8]) -> bool {
        RpMacKey::verify(self, msg)
    }
}

struct Ingress {
    from_driver: Rx,
    to_driver: Tx,
    to_hs: Tx,
    from_hs: Rx,
    to_data: Tx,
    from_data: Rx,
    to_pq: Tx,
    from_pq: Rx,
    audit: Audit,
    mac1: GatewayMac1,
    buckets: Buckets<BUCKETS>,
    gate: Gate,
    rp_mac: RpMacKey,
    rp: RpGate<BUCKETS>,
    cookies: CookieAdapter,
    rp_cookie: RpCookieAdapter,
    /// Rosenpass CookieReplies, apart from every other buffer.
    rp_cookie_out: [u8; RP_COOKIE_REPLY_LEN],
    endpoints: [Option<Endpoint>; MAX_PEERS],
    frame: Buf,
    reply: Buf,
    msg: Buf,
    scratch: Buf,
    /// Cookie replies, apart from `reply` and `frame` so neither aliases it.
    cookie: [u8; COOKIE_REPLY_LEN],
}

fn halt(msg: &str) -> ! {
    debug_println!("ingress: {msg}");
    panic!("ingress: halted");
}

#[protection_domain]
fn init() -> Ingress {
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout`; receive data regions are read-only here.
    let (from_driver, to_driver, to_hs, from_hs, to_data, from_data, to_pq, from_pq, audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(net_rx_used: *mut u8),
                memory_region_symbol!(net_rx_free: *mut u8),
                memory_region_symbol!(net_rx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(net_tx_used: *mut u8),
                memory_region_symbol!(net_tx_free: *mut u8),
                memory_region_symbol!(net_tx_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(ih_used: *mut u8),
                memory_region_symbol!(ih_free: *mut u8),
                memory_region_symbol!(ih_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(hi_used: *mut u8),
                memory_region_symbol!(hi_free: *mut u8),
                memory_region_symbol!(hi_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(id_used: *mut u8),
                memory_region_symbol!(id_free: *mut u8),
                memory_region_symbol!(id_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(di_used: *mut u8),
                memory_region_symbol!(di_free: *mut u8),
                memory_region_symbol!(di_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(ipq_used: *mut u8),
                memory_region_symbol!(ipq_free: *mut u8),
                memory_region_symbol!(ipq_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(pqi_used: *mut u8),
                memory_region_symbol!(pqi_free: *mut u8),
                memory_region_symbol!(pqi_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_ingress: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    if cpu::checked_frequency(cpu::cntfrq()).is_none() {
        // Without a clock the cookie secret would never age out (L12).
        halt("CNTFRQ is 0; refusing to run without a clock");
    }
    let key = crypto::hash(&[LABEL_MAC1, &config::GATEWAY_PUBLIC]).unwrap_or_else(|_| panic!("ingress: mac1 key"));
    let mut cookies =
        CookieAdapter::new(&config::GATEWAY_PUBLIC, cpu::fill_random).unwrap_or_else(|_| halt("cookie key derivation failed"));
    // Only the 32-byte mac and cookie keys are kept; `spkm` itself is read
    // here once.
    let spkm = config::gateway_rp_public!();
    let rp_mac = RpMacKey::new(spkm).unwrap_or_else(|_| halt("Rosenpass mac key derivation failed"));
    let mut rp_cookie = RpCookieAdapter::new(spkm, cpu::fill_random);
    let mut gate = Gate::default();
    if !gate.tick_if_due(&mut cookies, cpu::now_ns(), 0).rotated {
        halt("RNDR unavailable; no cookie secret");
    }
    let mut rp = RpGate::default();
    if !rp.tick_if_due(&mut rp_cookie, cpu::now_ns()).rotated {
        halt("RNDR unavailable; no Rosenpass cookie secret");
    }
    debug_println!("ingress: ready");
    Ingress {
        from_driver,
        to_driver,
        to_hs,
        from_hs,
        to_data,
        from_data,
        to_pq,
        from_pq,
        audit,
        mac1: GatewayMac1 { key },
        buckets: Buckets::default(),
        gate,
        rp_mac,
        rp,
        cookies,
        rp_cookie,
        rp_cookie_out: [0; RP_COOKIE_REPLY_LEN],
        endpoints: [None; MAX_PEERS],
        frame: [0; layout::NET_BUF_SIZE],
        reply: [0; layout::NET_BUF_SIZE],
        msg: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
        cookie: [0; COOKIE_REPLY_LEN],
    }
}

/// Which peers to notify after a pass.
#[derive(Default)]
struct Wake {
    driver: bool,
    hs: bool,
    data: bool,
    pq: bool,
}

impl Wake {
    fn notify(&self) {
        if self.driver {
            ETH_OUT.notify();
        }
        if self.hs {
            HS.notify();
        }
        if self.data {
            DATA.notify();
        }
        if self.pq {
            PQ.notify();
        }
    }
}

/// Audits the Gate's load and expiry edges (never coalesced); due after
/// every `respond` and every `tick_if_due`.
fn record_edges(gate: &mut Gate, audit: &mut Audit) {
    if gate.take_load_entered() {
        audit.record(Event::WgUnderLoad);
    }
    if gate.take_expired() {
        audit.record(Event::CookieSecretExpired);
    }
}

/// The Rosenpass gate's edges (never coalesced), as `record_edges`.
fn record_rp_edges<const N: usize>(rp: &mut RpGate<N>, audit: &mut Audit) {
    if rp.take_load_entered() {
        audit.record(Event::RpUnderLoad);
    }
    if rp.take_expired() {
        audit.record(Event::RpCookieSecretExpired);
    }
}

impl Ingress {
    /// `to_hs` buffers `hs` has not returned and free `to_driver` buffers,
    /// each read after a reclaim. A link error counts as under load and as
    /// no TX reserve, which fails safe.
    fn levels(&mut self) -> (usize, usize) {
        let backlog = match self.to_hs.in_flight() {
            Ok(n) => n,
            Err(e) => {
                self.audit.link_error(e);
                usize::MAX
            }
        };
        let tx_free = match self.to_driver.free() {
            Ok(n) => n,
            Err(e) => {
                self.audit.link_error(e);
                0
            }
        };
        (backlog, tx_free)
    }

    fn tick(&mut self) {
        let (backlog, _) = self.levels();
        let report = self.gate.tick_if_due(&mut self.cookies, cpu::now_ns(), backlog);
        // WgUnderLoad before this tick's WgLoadCleared, so the two alternate.
        record_edges(&mut self.gate, &mut self.audit);
        if report.secret_unavailable {
            self.audit.record(Event::CookieSecretUnavailable);
        }
        if report.left_load {
            self.audit.record(Event::WgLoadCleared);
        }
        let rp = self.rp.tick_if_due(&mut self.rp_cookie, cpu::now_ns());
        // RpUnderLoad before this tick's RpLoadCleared, so the two alternate.
        record_rp_edges(&mut self.rp, &mut self.audit);
        if rp.secret_unavailable {
            self.audit.record(Event::RpCookieSecretUnavailable);
        }
        if rp.left_load {
            self.audit.record(Event::RpLoadCleared);
        }
    }

    /// Whether the datagram, from our port `sport`, was handed to `eth_out`.
    fn send_to_peer(&mut self, sport: u16, dst: Endpoint, payload: &[u8], wake: &mut Wake) -> bool {
        match emit_udp(&CONFIG, sport, dst, payload, &mut self.reply) {
            Ok(n) => {
                let frame = self.reply.get(..n).unwrap_or(&[]);
                let sent = pdkit::send(&mut self.to_driver, &mut self.scratch, frame, &mut self.audit);
                wake.driver |= sent;
                sent
            }
            Err(_) => {
                self.audit.record(Event::TxNoBuffer);
                false
            }
        }
    }

    fn drain_outside(&mut self, wake: &mut Wake, max: usize) -> usize {
        drain(max, || self.outside_one(wake))
    }

    /// Takes and handles one message; `false` when the input is empty.
    fn outside_one(&mut self, wake: &mut Wake) -> bool {
        let Some(n) = pdkit::recv(&mut self.from_driver, &mut self.frame, &mut self.audit) else { return false };
        wake.driver = true;
        // Retire what `pq` has finished before any Rosenpass admission
        // decides on room (a sync is a reclaim and, usually, an empty read).
        self.sync_pq(wake);
        let (backlog, tx_free) = self.levels();
        let frame = self.frame.get(..n).unwrap_or(&[]);
        let mut msg_len = None;
        let mut rp_forward = None;
        let now = cpu::now_ns();
        let outcome = respond(
            &CONFIG,
            &mut self.gate,
            &mut self.cookies,
            &self.mac1,
            &mut self.buckets,
            now,
            backlog,
            tx_free,
            frame,
            &mut self.reply,
            &mut self.cookie,
        );
        record_edges(&mut self.gate, &mut self.audit);
        let target = match outcome {
            Outcome::ArpReplied(len) => {
                let reply = self.reply.get(..len).unwrap_or(&[]);
                if pdkit::send(&mut self.to_driver, &mut self.scratch, reply, &mut self.audit) {
                    self.audit.record(Event::ArpReplied);
                }
                return true;
            }
            Outcome::ArpSuppressed => {
                self.audit.record(Event::ArpSuppressed);
                None
            }
            Outcome::Initiation { src, msg, mac2_checked } => {
                if mac2_checked {
                    self.audit.record(Event::WgMac2Accepted);
                }
                msg_len = msgs::Initiation { src: ep(src), msg }.encode(&mut self.msg);
                Some(Target::Hs)
            }
            Outcome::Transport { src, msg } => {
                msg_len = msgs::Transport { src: ep(src), msg }.encode(&mut self.msg);
                Some(Target::Data)
            }
            Outcome::Rosenpass { src, payload } => {
                let o = rp_classify(
                    &mut self.rp,
                    &self.rp_mac,
                    &mut self.rp_cookie,
                    now,
                    tx_free,
                    src,
                    payload,
                    &mut self.rp_cookie_out,
                );
                record_rp_edges(&mut self.rp, &mut self.audit);
                let msg = match o {
                    RpOutcome::ForwardHello { src, msg, cookied } => {
                        if cookied {
                            self.audit.record(Event::RpCookieAccepted);
                        }
                        rp_forward = Some((RpKind::Hello, src));
                        msgs::RpDatagram { peer: ep(src), msg }.encode(&mut self.msg)
                    }
                    RpOutcome::ForwardConf { src, msg } => {
                        rp_forward = Some((RpKind::Conf, src));
                        msgs::RpDatagram { peer: ep(src), msg }.encode(&mut self.msg)
                    }
                    RpOutcome::BadMac => {
                        self.audit.record(Event::RpBadMac);
                        return true;
                    }
                    // A full share of the link is a rate limit as seen from
                    // outside; there is no separate audit code for it.
                    RpOutcome::RateLimited | RpOutcome::RingReserved => {
                        self.audit.record(Event::RpRateLimited);
                        return true;
                    }
                    RpOutcome::TypeDropped => {
                        self.audit.record(Event::RpTypeDropped);
                        return true;
                    }
                    // Audited once, when the sync stopped.
                    RpOutcome::PqDown => return true,
                    RpOutcome::CookieReply { dst } => {
                        // Public bytes: the cookie value inside is sealed.
                        let reply = self.rp_cookie_out;
                        if self.send_to_peer(CONFIG.rp_port, dst, &reply, wake) {
                            self.audit.record(Event::RpCookieReplySent);
                        }
                        return true;
                    }
                    // The secret's own edges are audited by the tick and by
                    // `record_rp_edges`; a refused reply is counted here.
                    RpOutcome::CookieSuppressed | RpOutcome::NoCookieSecret | RpOutcome::CookieSecretExpired => {
                        self.audit.record(Event::RpCookieSuppressed);
                        return true;
                    }
                };
                msg_len = msg;
                Some(Target::Pq)
            }
            Outcome::CookieReply { dst, len } => {
                // Public bytes: the cookie inside is sealed.
                let cookie = self.cookie;
                if self.send_to_peer(CONFIG.port, dst, cookie.get(..len).unwrap_or(&[]), wake) {
                    self.audit.record(Event::WgCookieSent);
                }
                None
            }
            Outcome::CookieSuppressed => {
                self.audit.record(Event::WgCookieSuppressed);
                None
            }
            Outcome::NoCookieSecret | Outcome::CookieSecretExpired => {
                self.audit.record(Event::WgCookieDropped);
                None
            }
            Outcome::Dropped(reason) => {
                self.audit.record(Event::FrameDropped { reason: reason as u16 });
                None
            }
            Outcome::NotForUs => {
                self.audit.record(Event::NotForUs);
                None
            }
            Outcome::NoService => {
                self.audit.record(Event::NoService);
                None
            }
            Outcome::Spoofed => {
                self.audit.record(Event::Spoofed);
                None
            }
            Outcome::BadMessage => {
                self.audit.record(Event::WgBadMessage);
                None
            }
            Outcome::BadMac1 => {
                self.audit.record(Event::WgBadMac1);
                None
            }
            Outcome::RateLimited => {
                self.audit.record(Event::WgRateLimited);
                None
            }
        };
        let (Some(target), Some(len)) = (target, msg_len) else { return true };
        let msg = self.msg.get(..len).unwrap_or(&[]);
        match target {
            Target::Hs => wake.hs |= pdkit::send(&mut self.to_hs, &mut self.scratch, msg, &mut self.audit),
            Target::Data => wake.data |= pdkit::send(&mut self.to_data, &mut self.scratch, msg, &mut self.audit),
            Target::Pq => {
                let sent = pdkit::send(&mut self.to_pq, &mut self.scratch, msg, &mut self.audit);
                // Only a forward on the link awaits a record (I9a).
                if let (true, Some((kind, src))) = (sent, rp_forward) {
                    self.rp.sent(kind, src);
                }
                wake.pq |= sent;
            }
        }
        true
    }

    /// One sync with `pq` through ingress-core's `sync_pq`, which owns the
    /// order (snapshot, drain, pair, retire) and every destination; this
    /// side only moves bytes. Returns the replies relayed.
    fn sync_pq(&mut self, wake: &mut Wake) -> usize {
        let mut rp = core::mem::take(&mut self.rp);
        let outcome = ingress_core::sync_pq(&mut rp, &mut PqLink { ingress: self, wake }, config::PEERS.len(), cpu::now_ns());
        self.rp = rp;
        match outcome {
            SyncOutcome::Synced { relayed } => relayed,
            SyncOutcome::DiedNow => {
                self.audit.record(Event::RpPqSyncDead);
                0
            }
            SyncOutcome::Dead => 0,
        }
    }

    fn drain_hs(&mut self, wake: &mut Wake, max: usize) -> usize {
        drain(max, || self.hs_one(wake))
    }

    /// Takes and handles one message; `false` when the input is empty.
    fn hs_one(&mut self, wake: &mut Wake) -> bool {
        let Some(n) = pdkit::recv(&mut self.from_hs, &mut self.msg, &mut self.audit) else { return false };
        wake.hs = true;
        let Ok(r) = msgs::Response::decode(self.msg.get(..n).unwrap_or(&[])) else {
            self.audit.record(Event::BadDescriptor);
            return true;
        };
        let (dst, payload) = (Endpoint { ip: r.dst.ip, port: r.dst.port }, *r.msg);
        self.send_to_peer(CONFIG.port, dst, &payload, wake);
        true
    }

    fn drain_data(&mut self, wake: &mut Wake, max: usize) -> usize {
        drain(max, || self.data_one(wake))
    }

    /// Takes and handles one message; `false` when the input is empty.
    fn data_one(&mut self, wake: &mut Wake) -> bool {
        let Some(n) = pdkit::recv(&mut self.from_data, &mut self.msg, &mut self.audit) else { return false };
        wake.data = true;
        let len = n.min(self.msg.len());
        let mut payload = [0u8; layout::NET_BUF_SIZE];
        let (dst, plen) = match ToIngress::decode(self.msg.get(..len).unwrap_or(&[])) {
            Ok(ToIngress::Outbound { peer, msg }) => {
                let Some(dst) = self.endpoints.get(usize::from(peer)).copied().flatten() else {
                    self.audit.record(Event::NoSession);
                    return true;
                };
                let Some(p) = payload.get_mut(..msg.len()) else { return true };
                p.copy_from_slice(msg);
                (dst, msg.len())
            }
            Ok(ToIngress::EndpointUpdate { peer, endpoint }) => {
                if usize::from(peer) < config::PEERS.len()
                    && let Some(slot) = self.endpoints.get_mut(usize::from(peer))
                {
                    *slot = Some(Endpoint { ip: endpoint.ip, port: endpoint.port });
                }
                return true;
            }
            Err(_) => {
                self.audit.record(Event::BadDescriptor);
                return true;
            }
        };
        self.send_to_peer(CONFIG.port, dst, payload.get(..plen).unwrap_or(&[]), wake);
        true
    }
}

/// Where a vetted outside message goes.
enum Target {
    Hs,
    Data,
    Pq,
}

/// One handler run: the wake-ups gathered since the last `end_pass`.
struct Pass<'a> {
    ingress: &'a mut Ingress,
    wake: Wake,
}

impl PassIo for Pass<'_> {
    fn serve_hs(&mut self, max: usize) -> usize {
        self.ingress.drain_hs(&mut self.wake, max)
    }

    fn serve_pq(&mut self, max: usize) -> usize {
        // One sync empties an honest `pq`'s records (RP_IN_FLIGHT < max).
        self.ingress.sync_pq(&mut self.wake).min(max.saturating_sub(1))
    }

    fn serve_data(&mut self, max: usize) -> usize {
        self.ingress.drain_data(&mut self.wake, max)
    }

    fn tick(&mut self) {
        self.ingress.tick();
    }

    fn serve_outside(&mut self, max: usize) -> usize {
        self.ingress.drain_outside(&mut self.wake, max)
    }

    fn end_pass(&mut self) {
        core::mem::take(&mut self.wake).notify();
        self.ingress.audit.flush();
    }
}

/// The PD's side of `sync_pq`. `transmit` gets a destination and bytes
/// only, never the record or its index, so it cannot pick another
/// destination (M3b plan, T19).
struct PqLink<'a> {
    ingress: &'a mut Ingress,
    wake: &'a mut Wake,
}

impl PqSync for PqLink<'_> {
    fn outstanding(&mut self) -> Option<usize> {
        match self.ingress.to_pq.in_flight() {
            Ok(n) => Some(n),
            Err(e) => {
                self.ingress.audit.link_error(e);
                None
            }
        }
    }

    /// Reads the link directly rather than through `pdkit::recv`, which
    /// skips bad descriptors: a skipped record would put the pairing out of
    /// step, so it must reach `sync_pq` as unreadable.
    fn next_record(&mut self, out: &mut [u8; RP_RECORD_MAX]) -> Option<Option<usize>> {
        let r = self.ingress.from_pq.recv_into(&mut self.ingress.msg);
        let read = match r {
            Ok(None) => return None,
            Ok(Some(n)) => self.ingress.msg.get(..n).and_then(|b| {
                out.get_mut(..b.len())?.copy_from_slice(b);
                Some(b.len())
            }),
            Err(e) => {
                self.ingress.audit.link_error(e);
                None
            }
        };
        // The buffer went back to `pq`, which reclaims on notification.
        self.wake.pq = true;
        Some(read)
    }

    /// RespHello and EmptyData each answer a mac-valid InitHello or
    /// InitConf, which proves nothing about its source; so, like cookie
    /// replies, they stay out of the TX reserve.
    fn transmit(&mut self, dst: Endpoint, reply: &[u8]) -> bool {
        let tx_free = match self.ingress.to_driver.free() {
            Ok(n) => n,
            Err(e) => {
                self.ingress.audit.link_error(e);
                0
            }
        };
        if !rp_tx_allowed(TxTier::Answer, tx_free) {
            self.ingress.audit.record(Event::TxNoBuffer);
            return false;
        }
        self.ingress.send_to_peer(CONFIG.rp_port, dst, reply, self.wake)
    }
}

fn ep(e: Endpoint) -> msgs::Endpoint {
    msgs::Endpoint { ip: e.ip, port: e.port }
}

impl Handler for Ingress {
    type Error = Infallible;

    /// The bounded handler loop lives in `ingress_core::run_passes`, where it
    /// is unit-tested; the timer's notification is just another run of it.
    fn notified(&mut self, _channels: ChannelSet) -> Result<(), Self::Error> {
        run_passes(&mut Pass { ingress: self, wake: Wake::default() });
        Ok(())
    }
}
