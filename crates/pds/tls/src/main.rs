//! `tls` (M6 plan C1, C3, C7, C8, C10): the HTTPS reverse proxy. TCP runs
//! in smoltcp on two interfaces, each polling only its own sockets: the
//! outside one on the IP packets `ingress` vetted (`itl`), every segment
//! going back out through `ingress`'s `tls_egress` (`tli`), with eight
//! listeners on the HTTPS port; the inside one on the backend's segments
//! `inner` delivers (`ntl`), every segment leaving through `inner`'s check
//! towards the backend (`tln`), with one backend socket per listener. Each
//! listener's connection has a slot of `tls_core::conn`, which holds the
//! TLS 1.3 session and the proxy flow and decides every timeout, close and
//! wipe; this PD carries its events between the slot and the two sockets.
//! The server's CertificateVerify is signed by `tlskey` (`TlsSign` over
//! PPC, M6 plan C12); the randomness is hedged over `tlskey`'s boot seed,
//! RNDR and CNTPCT. Tainted (law L1).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use audit_event::{CostHighWater, Event};
use tlskey_core::{LABEL_BOOT_SEED, LABEL_TLS_SIGN, MAX_WORDS, OK};
use layout::tls as ch;
use pdkit::{Audit, Buf, Rx, Tx};
use ring::pass::{any_full, run_passes};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs,
    with_msg_regs_mut,
};
use smoltcp::iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};
use tls_core::conn::{
    Action, BACKEND_CHUNK, BackendEnd, Closed, Endpoint, MAX_CLIENT_OUT, Next, Outcome, Slot, Stage, Table, Timeout,
    backend_end,
};
use tls_core::halt;
use tls_core::handshake::{Ctx, Signer};
use tls_core::rng::{HedgeHw, Hedged, Rng, SEED_LEN};
use tls_core::{Refusal, Secret};
use tls_wire::{HASH_LEN, MAX_CIPHERTEXT, RECORD_HEADER_LEN};
use zeroize::Zeroize;

const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const INNER: Channel = Channel::new(ch::CH_INNER);
const TIMER: Channel = Channel::new(ch::CH_TIMER);
const TLSKEY: Channel = Channel::new(ch::CH_TLSKEY);

/// Connections at once (plan C10), one listener, one slot and one backend
/// socket each.
const MAX_CONNS: usize = tls_core::conn::MAX_CONNS;
// One backend source port per connection at least (config validates
// `TLS_PORTS` against the same bound, plan C3).
const _: () = assert!(config::TLS_PORTS.1 as usize >= MAX_CONNS);
/// One whole record off the socket: header and the largest protected body.
const RECORD_BUF: usize = RECORD_HEADER_LEN + MAX_CIPHERTEXT;
/// A socket's receive buffer holds a whole record of the largest size, so
/// a record is taken only once complete and the window never stalls on a
/// partial one (plan C10's 16 KiB raised to fit; M6 deviation log).
const RX_BUF: usize = 17 * 1024;
const _: () = assert!(RX_BUF >= RECORD_BUF);
const TX_BUF: usize = 8 * 1024;
/// The backend socket's buffers (plan C10, F18): the response arrives in
/// chunks of at most `BACKEND_CHUNK`, the request leaves as fast as the
/// backend takes it.
const BACKEND_RX_BUF: usize = 8 * 1024;
const BACKEND_TX_BUF: usize = 16 * 1024;
const _: () = assert!(BACKEND_CHUNK <= BACKEND_RX_BUF);
/// The records one call writes: at most the server's flight (ServerHello,
/// then EncryptedExtensions, Certificate, CertificateVerify and Finished,
/// one record each), which must also fit the empty send buffer; after the
/// handshake, at most `MAX_CLIENT_OUT`, written only while the send buffer
/// has that much room.
const OUT_BUF: usize = 8 * 1024;
const FLIGHT_MAX: usize = config::TLS_CERT.len() + 2048;
const _: () = assert!(FLIGHT_MAX <= OUT_BUF && FLIGHT_MAX <= TX_BUF);
const _: () = assert!(MAX_CLIENT_OUT <= OUT_BUF && MAX_CLIENT_OUT <= TX_BUF);
/// The largest IP packet either link carries: Ethernet's.
const MTU: usize = 1500;
const _: () = assert!(MTU <= layout::NET_BUF_SIZE);
/// A listener's timeout: a handshake that never completes frees its slot
/// (smoltcp has no SYN cookies, RM6-7). smoltcp's timeout is per socket,
/// so it is raised to the idle timeout once the connection is established.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(tls_core::conn::IDLE_TIMEOUT_NS / 1_000_000_000);
/// Packets taken from each of `itl` and `ntl` per pass.
const PASS_PACKETS: usize = layout::NET_BUFFERS;
/// The static per-connection state (plan C10, F18) is bounded.
const TLS_STATE_MAX: usize = 1 << 20;
const _: () = assert!(core::mem::size_of::<Storage>() <= TLS_STATE_MAX);

// `audit` names the `tls` kinds from audit-event's tables, which cannot see
// the enums they mirror; checked here, where both are visible.
const _: () = assert!(names_match());

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn decimal(s: &str) -> u16 {
    let s = s.as_bytes();
    let (mut v, mut i) = (0u16, 0);
    while i < s.len() {
        v = v * 10 + (s[i] - b'0') as u16;
        i += 1;
    }
    v
}

const fn names_match() -> bool {
    use audit_event::{HTTP_REFUSED_NAMES, TLS_CLOSED_NAMES, TLS_REFUSED_NAMES, TLS_TIMEOUT_NAMES};
    use http_wire::Status;
    let refused = Refusal::ALL;
    let closed = Closed::ALL;
    let timeouts = Timeout::ALL;
    let statuses = Status::ALL;
    if refused.len() != TLS_REFUSED_NAMES.len()
        || closed.len() != TLS_CLOSED_NAMES.len()
        || timeouts.len() != TLS_TIMEOUT_NAMES.len()
        || statuses.len() != HTTP_REFUSED_NAMES.len()
    {
        return false;
    }
    let mut i = 0;
    while i < refused.len() {
        if refused[i].code() as usize != i || !str_eq(refused[i].name(), TLS_REFUSED_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    i = 0;
    while i < closed.len() {
        if closed[i].code() as usize != i || !str_eq(closed[i].name(), TLS_CLOSED_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    i = 0;
    while i < timeouts.len() {
        if timeouts[i].stage() as usize != i || !str_eq(timeouts[i].name(), TLS_TIMEOUT_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    i = 0;
    while i < statuses.len() {
        if statuses[i].index() as usize != i || statuses[i].code() != decimal(HTTP_REFUSED_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Everything too large for the stack, where the handler state lives: the
/// sockets of both interfaces and their buffers, the connection slots, and
/// the record buffers a pass works in.
struct Storage {
    sockets: [SocketStorage<'static>; MAX_CONNS],
    rx: [[u8; RX_BUF]; MAX_CONNS],
    tx: [[u8; TX_BUF]; MAX_CONNS],
    backend_sockets: [SocketStorage<'static>; MAX_CONNS],
    backend_rx: [[u8; BACKEND_RX_BUF]; MAX_CONNS],
    backend_tx: [[u8; BACKEND_TX_BUF]; MAX_CONNS],
    /// One record taken off a socket: ciphertext, or a plaintext handshake
    /// or alert record.
    record: [u8; RECORD_BUF],
    /// The records one call writes (ciphertext, or plaintext ServerHello
    /// and alerts), copied into the socket at once.
    out: [u8; OUT_BUF],
    /// Built slot by slot at init: `Table::new` is not const and too large
    /// for the stack.
    table: MaybeUninit<Table>,
}

struct Static(UnsafeCell<Storage>);

// SAFETY: a PD runs one thread; `init` hands each part out once, and the
// socket buffers are reached again only through `socket_buffers` and
// `backend_buffers`.
unsafe impl Sync for Static {}

static STORAGE: Static = Static(UnsafeCell::new(Storage {
    sockets: [SocketStorage::EMPTY; MAX_CONNS],
    rx: [[0; RX_BUF]; MAX_CONNS],
    tx: [[0; TX_BUF]; MAX_CONNS],
    backend_sockets: [SocketStorage::EMPTY; MAX_CONNS],
    backend_rx: [[0; BACKEND_RX_BUF]; MAX_CONNS],
    backend_tx: [[0; BACKEND_TX_BUF]; MAX_CONNS],
    record: [0; RECORD_BUF],
    out: [0; OUT_BUF],
    table: MaybeUninit::uninit(),
}));

/// Entry `i` of a per-listener buffer array in the static, through a raw
/// place, so no reference to another listener's entry (held by its
/// socket) is made.
///
/// # Safety
/// `base` points into `STORAGE`; no other reference to entry `i` is live.
unsafe fn entry<const N: usize>(base: *mut [[u8; N]; MAX_CONNS], i: usize) -> Option<&'static mut [u8; N]> {
    if i >= MAX_CONNS {
        return None;
    }
    // SAFETY: `i` is in bounds of the array `base` points to; exclusivity
    // is the caller's.
    unsafe { Some(&mut *base.cast::<[u8; N]>().add(i)) }
}

/// Listener `i`'s socket buffers, through the static.
///
/// # Safety
/// No other reference to them may be live: listener `i`'s socket was never
/// made or has been removed from its set and dropped.
unsafe fn socket_buffers(i: usize) -> Option<(&'static mut [u8; RX_BUF], &'static mut [u8; TX_BUF])> {
    let s = STORAGE.0.get();
    // SAFETY: the caller's; raw places into the static.
    unsafe { Some((entry(addr_of_mut!((*s).rx), i)?, entry(addr_of_mut!((*s).tx), i)?)) }
}

/// Listener `i`'s backend socket buffers, through the static.
///
/// # Safety
/// As `socket_buffers`, for listener `i`'s backend socket.
unsafe fn backend_buffers(i: usize) -> Option<(&'static mut [u8; BACKEND_RX_BUF], &'static mut [u8; BACKEND_TX_BUF])> {
    let s = STORAGE.0.get();
    // SAFETY: the caller's; raw places into the static.
    unsafe { Some((entry(addr_of_mut!((*s).backend_rx), i)?, entry(addr_of_mut!((*s).backend_tx), i)?)) }
}

/// An address and port: a client, or the backend and our source port.
type Peer = ([u8; 4], u16);

/// The RSTs this pass's transmits wrote into a link's ring, by peer: how an
/// aborted socket's RST is observed (M6 plan C8, F-R6-2).
#[derive(Default)]
struct RstLog {
    peers: [Peer; 2 * MAX_CONNS],
    len: usize,
}

impl RstLog {
    /// A full log drops the entry: its slot waits further passes, at most
    /// `MAX_RST_PASSES` in all.
    fn push(&mut self, peer: Peer) {
        if let Some(e) = self.peers.get_mut(self.len) {
            *e = peer;
            self.len += 1;
        }
    }

    fn contains(&self, peer: Peer) -> bool {
        self.peers.get(..self.len).unwrap_or(&[]).contains(&peer)
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// The client of a RST from the HTTPS port in `packet`, an IP packet
/// smoltcp built, read with `wire`'s checked parsers.
fn client_rst(packet: &[u8]) -> Option<Peer> {
    let ip = wire::parse_ipv4_packet(packet).ok()?;
    let tcp = wire::parse_tcp(&ip).ok()?;
    (tcp.flags & wire::TCP_RST != 0 && tcp.src_port == config::HTTPS_PORT).then_some((ip.dst, tcp.dst_port))
}

/// The backend and our source port of a RST to the backend in `packet`.
fn backend_rst(packet: &[u8]) -> Option<Peer> {
    let ip = wire::parse_ipv4_packet(packet).ok()?;
    let tcp = wire::parse_tcp(&ip).ok()?;
    let (backend, port) = config::BACKEND;
    (tcp.flags & wire::TCP_RST != 0 && ip.dst == backend && tcp.dst_port == port).then_some((ip.dst, tcp.src_port))
}

/// One ring pair, one IP packet per buffer: `itl`/`tli` outside,
/// `ntl`/`tln` inside.
struct Link {
    rx: Rx,
    tx: Tx,
    packet: Buf,
    staging: Buf,
    scratch: Buf,
    /// A segment went to the peer PD since it was last notified.
    sent: bool,
    rsts: RstLog,
    /// Which transmitted RSTs `rsts` records, and under what peer.
    rst_peer: fn(&[u8]) -> Option<Peer>,
}

impl Link {
    fn new(rx: Rx, tx: Tx, rst_peer: fn(&[u8]) -> Option<Peer>) -> Self {
        Self {
            rx,
            tx,
            packet: [0; layout::NET_BUF_SIZE],
            staging: [0; layout::NET_BUF_SIZE],
            scratch: [0; layout::NET_BUF_SIZE],
            sent: false,
            rsts: RstLog::default(),
            rst_peer,
        }
    }
}

/// A link as smoltcp's device for one poll, with the PD's audit.
struct Dev<'a> {
    link: &'a mut Link,
    audit: &'a mut Audit,
}

struct RxToken<'a> {
    packet: &'a [u8],
}

struct TxToken<'a> {
    tx: &'a mut Tx,
    staging: &'a mut Buf,
    scratch: &'a mut Buf,
    audit: &'a mut Audit,
    sent: &'a mut bool,
    rsts: &'a mut RstLog,
    rst_peer: fn(&[u8]) -> Option<Peer>,
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.packet)
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        // The capabilities keep `len` within MTU, below a buffer.
        let packet = self.staging.get_mut(..len.min(MTU)).unwrap_or_default();
        let r = f(packet);
        let sent = pdkit::send(self.tx, self.scratch, packet, self.audit);
        // Only a RST that reached the ring counts as dispatched.
        if sent && let Some(peer) = (self.rst_peer)(packet) {
            self.rsts.push(peer);
        }
        *self.sent |= sent;
        r
    }
}

impl Dev<'_> {
    fn tx_token(&mut self) -> TxToken<'_> {
        let Link { tx, staging, scratch, sent, rsts, rst_peer, .. } = &mut *self.link;
        TxToken { tx, staging, scratch, audit: self.audit, sent, rsts, rst_peer: *rst_peer }
    }
}

impl Device for Dev<'_> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _: Instant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        let Link { rx, tx, packet, staging, scratch, sent, rsts, rst_peer } = &mut *self.link;
        let n = pdkit::recv(rx, packet, self.audit)?;
        let packet = packet.get(..n).unwrap_or(&[]);
        let tx = TxToken { tx, staging, scratch, audit: self.audit, sent, rsts, rst_peer: *rst_peer };
        Some((RxToken { packet }, tx))
    }

    /// No buffer free: smoltcp keeps the segment and retransmits it.
    fn transmit(&mut self, _: Instant) -> Option<TxToken<'_>> {
        match self.link.tx.free() {
            Ok(n) if n > 0 => Some(self.tx_token()),
            Ok(_) => None,
            Err(e) => {
                self.audit.link_error(e);
                None
            }
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// One call into `tlskey` over PPC, as pd-hs's into `key`: `req` in the
/// message registers, at most `reply.len()` reply words copied out, then
/// every register up to `MAX_WORDS` zeroed. Returns the reply label and the
/// words copied.
fn key_call(label: u64, req: &[u64], reply: &mut [u64]) -> (u64, usize) {
    if req.len() > MAX_WORDS {
        return (tlskey_core::ERR_BAD_REQUEST, 0);
    }
    with_msg_regs_mut(|mrs| {
        for (dst, src) in mrs.iter_mut().zip(req) {
            *dst = *src;
        }
    });
    let info = TLSKEY.pp_call(MessageInfo::new(label, req.len()));
    let n = info.count().min(reply.len()).min(MAX_WORDS);
    with_msg_regs(|mrs| {
        for (dst, src) in reply.iter_mut().zip(mrs.iter().take(n)) {
            *dst = *src;
        }
    });
    with_msg_regs_mut(|mrs| mrs.iter_mut().take(MAX_WORDS).for_each(|w| *w = 0));
    (info.label(), n)
}

/// `tlskey`'s boot seed, the hedged RNG's key (M6 plan C7). An Unavailable
/// `tlskey` (its unseal, blob or scalar failed) is audited with its code,
/// and `tls` halts before any listener exists (M6 plan C12).
fn boot_seed(audit: &mut Audit) -> Secret<SEED_LEN> {
    let mut reply = [0u64; tlskey_core::BOOT_SEED_REPLY_WORDS];
    let (label, n) = key_call(LABEL_BOOT_SEED, &[], &mut reply);
    let mut seed = Secret::<SEED_LEN>::zero();
    let ok = label == OK
        && n == reply.len()
        && tlskey_core::unpack32(&reply).map(|mut b| {
            seed.as_mut_bytes().copy_from_slice(&b);
            b.zeroize();
        }) == Some(());
    reply.zeroize();
    if !ok {
        if let Some(code) = tlskey_core::unavailable_code(label) {
            audit.record(Event::KeyUnavailable { code });
            audit.halt(halt::KEY_UNAVAILABLE)
        }
        audit.halt(halt::INIT_FAILED)
    }
    seed
}

/// `tlskey`'s `TlsSign` (M6 plan C5, C12) as the handshake's signer. Each
/// call's wall time is measured, as `hs` measures its key calls: `sign_us`
/// is the longest since the last report. An Unavailable answer is left in
/// `unavailable` for the PD to audit and halt on once the record's call
/// has returned (and wiped the slot).
struct KeySigner<'a> {
    sign_us: &'a mut Option<u32>,
    unavailable: &'a mut Option<u32>,
}

impl Signer for KeySigner<'_> {
    fn sign(&mut self, transcript_hash: &[u8; HASH_LEN]) -> Result<[u8; 64], Refusal> {
        let r = self.call(transcript_hash);
        // What the call left below this frame (M6 plan C7, S-R3-2).
        tls_core::scrub_session_stack();
        r
    }
}

impl KeySigner<'_> {
    #[inline(never)]
    fn call(&mut self, transcript_hash: &[u8; HASH_LEN]) -> Result<[u8; 64], Refusal> {
        let req = tlskey_core::pack32(transcript_hash);
        let mut reply = [0u64; tlskey_core::TLS_SIGN_REPLY_WORDS];
        let start = cpu::cntpct();
        let (label, n) = key_call(LABEL_TLS_SIGN, &req, &mut reply);
        let us = cpu::ticks_to_ns(cpu::cntpct().saturating_sub(start), cpu::cntfrq()) / 1000;
        let us = u32::try_from(us).unwrap_or(u32::MAX);
        *self.sign_us = Some(self.sign_us.map_or(us, |w| w.max(us)));
        if label != OK {
            *self.unavailable = tlskey_core::unavailable_code(label);
            return Err(Refusal::Internal);
        }
        let (r, s) = reply.split_at(4);
        let mut sig = [0u8; 64];
        let (sig_r, sig_s) = sig.split_at_mut(32);
        match (n == reply.len(), tlskey_core::unpack32(r), tlskey_core::unpack32(s)) {
            (true, Some(r), Some(s)) => {
                sig_r.copy_from_slice(&r);
                sig_s.copy_from_slice(&s);
                Ok(sig)
            }
            _ => Err(Refusal::Internal),
        }
    }
}

struct Hw;

impl HedgeHw for Hw {
    fn rndr(&mut self) -> Option<u64> {
        cpu::rndr()
    }
    fn counter(&mut self) -> u64 {
        cpu::cntpct()
    }
}

/// One listener's backend socket: opened when the slot asks to connect,
/// aborted when it says so, released once its RST is out.
#[derive(Clone, Copy, Default)]
struct Backend {
    handle: Option<SocketHandle>,
    /// Our source port, from `TLS_PORTS`: how its RST is recognised.
    port: u16,
    /// The backend's FIN was seen.
    fin: bool,
    /// Aborted: the slot awaits its RST.
    aborting: bool,
    /// The aborted socket still had a 4-tuple, so a RST is due from it.
    rst_due: bool,
}

/// One listener's socket and the connection it holds.
#[derive(Clone, Copy, Default)]
struct Listener {
    handle: SocketHandle,
    /// The socket's timeout was raised for the established connection.
    raised: bool,
    /// The connection's slot, from admission to release.
    slot: Option<usize>,
    /// The client's address and port, for matching the abort's RST once
    /// smoltcp has forgotten the 4-tuple.
    peer: Peer,
    /// Aborted: the slot is wiped and awaits the socket's RST.
    aborting: bool,
    /// The aborted socket still had a 4-tuple, so a RST is due from it;
    /// without one (the peer's RST or a TCP timeout closed it first)
    /// nothing will be dispatched.
    rst_due: bool,
    backend: Backend,
}

struct Tls {
    outside: Link,
    inside: Link,
    audit: Audit,
    iface: Interface,
    sockets: SocketSet<'static>,
    inside_iface: Interface,
    backend_sockets: SocketSet<'static>,
    listeners: [Listener; MAX_CONNS],
    table: &'static mut Table,
    record: &'static mut [u8; RECORD_BUF],
    out: &'static mut [u8; OUT_BUF],
    rng: Hedged<Hw>,
    /// The next backend source port, as an offset into `TLS_PORTS`.
    next_port: u16,
    /// The longest `TlsSign` since the last report, and its gate.
    sign_us: Option<u32>,
    sign_wait: CostHighWater,
    /// `tlskey` answered a `TlsSign` Unavailable with this code (C12).
    unavailable: Option<u32>,
    stack: cpu::StackProbe,
}

fn now() -> Instant {
    Instant::from_micros(i64::try_from(cpu::now_ns() / 1000).unwrap_or(i64::MAX))
}

/// A listening socket over listener `i`'s buffers, which are wiped first.
///
/// # Safety
/// As `socket_buffers`.
unsafe fn listener_socket(i: usize) -> Option<tcp::Socket<'static>> {
    // SAFETY: the caller's.
    let (rx, tx) = unsafe { socket_buffers(i)? };
    rx.zeroize();
    tx.zeroize();
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(&mut rx[..]), tcp::SocketBuffer::new(&mut tx[..]));
    s.set_ack_delay(None);
    s.set_nagle_enabled(false);
    s.set_timeout(Some(LISTEN_TIMEOUT));
    s.listen(config::HTTPS_PORT).ok()?;
    Some(s)
}

/// A socket over listener `i`'s backend buffers, wiped first, connecting
/// from `port` to the backend.
///
/// # Safety
/// As `backend_buffers`.
unsafe fn backend_socket(i: usize, iface: &mut Interface, port: u16) -> Option<tcp::Socket<'static>> {
    // SAFETY: the caller's.
    let (rx, tx) = unsafe { backend_buffers(i)? };
    rx.zeroize();
    tx.zeroize();
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(&mut rx[..]), tcp::SocketBuffer::new(&mut tx[..]));
    s.set_ack_delay(None);
    s.set_nagle_enabled(false);
    let (ip, backend_port) = config::BACKEND;
    let local = IpListenEndpoint { addr: Some(IpAddress::Ipv4(Ipv4Address::from(config::INSIDE_IP))), port };
    s.connect(iface.context(), (IpAddress::Ipv4(Ipv4Address::from(ip)), backend_port), local).ok()?;
    Some(s)
}

/// An interface on a raw IP medium with one address. Every peer is reached
/// through the PD on the other end of the link (`ingress` frames to the
/// router, `inner` to the backend's neighbour entry), so the default route's
/// gateway is never looked up.
fn interface(dev: &mut Dev<'_>, ours: [u8; 4], seed: u64) -> Option<Interface> {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let mut iface = Interface::new(config, dev, now());
    let ours = Ipv4Address::from(ours);
    let mut added = false;
    iface.update_ip_addrs(|addrs| added = addrs.push(IpCidr::new(IpAddress::Ipv4(ours), 32)).is_ok());
    (added && iface.routes_mut().add_default_ipv4_route(ours).is_ok()).then_some(iface)
}

#[protection_domain]
fn init() -> Tls {
    // SAFETY: first thing in init, with this PD's stack_size (layout checks
    // it against the system file).
    let stack = unsafe { cpu::StackProbe::paint(layout::TLS_STACK_SIZE) };
    // SAFETY: each link's regions are mapped into this PD and its one peer
    // only, sized as in `layout` (checked by tools/laws and layout tests);
    // `itl`'s and `ntl`'s data regions are read-only here.
    let (rx, tx, to_inner, from_inner, mut audit) = unsafe {
        (
            pdkit::rx(
                memory_region_symbol!(itl_used: *mut u8),
                memory_region_symbol!(itl_free: *mut u8),
                memory_region_symbol!(itl_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(tli_used: *mut u8),
                memory_region_symbol!(tli_free: *mut u8),
                memory_region_symbol!(tli_data: *mut u8),
            ),
            pdkit::tx(
                memory_region_symbol!(tln_used: *mut u8),
                memory_region_symbol!(tln_free: *mut u8),
                memory_region_symbol!(tln_data: *mut u8),
            ),
            pdkit::rx(
                memory_region_symbol!(ntl_used: *mut u8),
                memory_region_symbol!(ntl_free: *mut u8),
                memory_region_symbol!(ntl_data: *mut u8),
            ),
            Audit::new(memory_region_symbol!(audit_tls: *mut u8), Channel::new(ch::CH_AUDIT)),
        )
    };
    if cpu::checked_frequency(cpu::cntfrq()).is_none() {
        audit.halt(halt::NO_CLOCK);
    }
    // The boot seed is `tls`'s first call to `tlskey`: an Unavailable
    // `tlskey` shows here, audited once, and tls halts before listening.
    let mut rng = Hedged::new(boot_seed(&mut audit), Hw);
    // One ISN seed per interface (smoltcp's PCG32, RM6-7).
    let (mut seed, mut inside_seed) = ([0u8; 8], [0u8; 8]);
    if rng.fill(&mut seed).is_err() || rng.fill(&mut inside_seed).is_err() {
        audit.halt(halt::RNDR);
    }
    let mut outside = Link::new(rx, tx, client_rst);
    let mut inside = Link::new(from_inner, to_inner, backend_rst);
    let iface = interface(&mut Dev { link: &mut outside, audit: &mut audit }, config::OUTSIDE_IP, u64::from_le_bytes(seed));
    let inside_iface =
        interface(&mut Dev { link: &mut inside, audit: &mut audit }, config::INSIDE_IP, u64::from_le_bytes(inside_seed));
    let (Some(iface), Some(inside_iface)) = (iface, inside_iface) else { audit.halt(halt::INIT_FAILED) };
    let st = STORAGE.0.get();
    // SAFETY: init runs once and is the only place these parts of the
    // storage are handed out; from here the socket sets own the socket
    // slots, the PD the table and record buffers, for the life of the
    // system. Raw places keep the parts disjoint from the socket buffers.
    let (slots, backend_slots, record, out, table) = unsafe {
        (
            &mut *addr_of_mut!((*st).sockets),
            &mut *addr_of_mut!((*st).backend_sockets),
            &mut *addr_of_mut!((*st).record),
            &mut *addr_of_mut!((*st).out),
            &mut *addr_of_mut!((*st).table),
        )
    };
    // SAFETY: `Table` is its `slots` array, each written here before the
    // table is read; slot by slot, so at most one slot is ever built on the
    // stack.
    let table = unsafe {
        let first = addr_of_mut!((*table.as_mut_ptr()).slots).cast::<Slot>();
        for i in 0..MAX_CONNS {
            first.add(i).write(Slot::new());
        }
        table.assume_init_mut()
    };
    let mut sockets = SocketSet::new(&mut slots[..]);
    let mut listeners = [Listener::default(); MAX_CONNS];
    for (i, l) in listeners.iter_mut().enumerate() {
        // SAFETY: no socket over listener i's buffers exists yet.
        match unsafe { listener_socket(i) } {
            Some(s) => l.handle = sockets.add(s),
            None => audit.halt(halt::INIT_FAILED),
        }
    }
    // The boot seed's copies in the frames below.
    tls_core::scrub_session_stack();
    audit.ready();
    let mut tls = Tls {
        outside,
        inside,
        audit,
        iface,
        sockets,
        inside_iface,
        backend_sockets: SocketSet::new(&mut backend_slots[..]),
        listeners,
        table,
        record,
        out,
        rng,
        next_port: 0,
        sign_us: None,
        sign_wait: CostHighWater::tls_sign(),
        unavailable: None,
        stack,
    };
    tls.audit.flush();
    tls
}

/// The length of the next record on `s`, if it is complete. A header that
/// fails its checks counts alone, so the session refuses it at once.
fn complete_record(s: &mut tcp::Socket<'_>) -> Option<usize> {
    let mut head = [0u8; RECORD_HEADER_LEN];
    if s.peek_slice(&mut head).ok()? < RECORD_HEADER_LEN {
        return None;
    }
    // Only the length is used here; the session checks the header again
    // with its own first-record rule.
    let len = match tls_wire::record::header(&head, true) {
        Ok(h) => RECORD_HEADER_LEN.saturating_add(h.len),
        Err(_) => RECORD_HEADER_LEN,
    };
    (s.recv_queue() >= len).then_some(len)
}

/// One whole record from `s` into `buf`, if one is complete.
fn take_record<'b>(s: &mut tcp::Socket<'_>, buf: &'b mut [u8; RECORD_BUF]) -> Option<&'b [u8]> {
    let len = complete_record(s)?;
    let n = s.recv_slice(buf.get_mut(..len)?).ok()?;
    buf.get(..n)
}

/// The peer has sent its FIN.
fn fin_received(s: &tcp::Socket<'_>) -> bool {
    matches!(s.state(), tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait)
}

/// Free room in `s`'s send buffer.
fn room(s: &tcp::Socket<'_>) -> usize {
    s.send_capacity().saturating_sub(s.send_queue())
}

/// Queues `bytes` whole on `s`, or nothing.
fn send_all(s: &mut tcp::Socket<'_>, bytes: &[u8]) -> bool {
    room(s) >= bytes.len() && s.send_slice(bytes) == Ok(bytes.len())
}

fn record_outcome(audit: &mut Audit, o: Outcome) {
    audit.record(match o {
        Outcome::TlsRefused(r) => Event::TlsRefused { reason: r.code() },
        Outcome::TlsClosed(c) => Event::TlsClosed { reason: c.code() },
        Outcome::HttpRefused(s) => Event::HttpRefused { status: s.index() },
        Outcome::TlsTimeout(t) => Event::TlsTimeout { stage: t.stage() },
        Outcome::BackendUnavailable => Event::BackendUnavailable,
    });
}

/// After a slot call that sealed records (`to_client` > 0): the record
/// key's copies in the dead frames of the seal, from the frame that made
/// the call (inlined, so no frame of its own sits over them).
#[inline(always)]
fn scrub_if_sealed(next: &Next) {
    if next.to_client > 0 {
        tls_core::scrub_session_stack();
    }
}

/// One listener's connection for one pass: its slot, its client socket and
/// what its backend socket needs.
struct Conn<'a, 'r> {
    i: usize,
    l: &'a mut Listener,
    client: &'a mut tcp::Socket<'static>,
    slot: &'a mut Slot,
    backends: &'a mut SocketSet<'static>,
    inside_iface: &'a mut Interface,
    next_port: &'a mut u16,
    record: &'a mut [u8; RECORD_BUF],
    out: &'a mut [u8; OUT_BUF],
    ctx: &'a mut Ctx<'r, Hedged<Hw>, KeySigner<'r>>,
    audit: &'a mut Audit,
    now: u64,
}

impl Conn<'_, '_> {
    /// The backend socket, while it carries the connection (not aborted).
    fn backend(&mut self) -> Option<&mut tcp::Socket<'static>> {
        let h = self.l.backend.handle.filter(|_| !self.l.backend.aborting)?;
        Some(self.backends.get_mut::<tcp::Socket>(h))
    }

    /// Carries out what the slot asked, in `Next`'s order. A send that does
    /// not fit (none should, given the room checks) ends the connection.
    fn apply(&mut self, next: Next) {
        let sent = next.to_client == 0 || send_all(self.client, self.out.get(..next.to_client).unwrap_or(&[]));
        if next.connect {
            self.connect();
        }
        if next.abort_backend {
            self.abort_backend();
        }
        if next.action == Action::Abort {
            abort(self.l, self.client);
        }
        for o in next.outcomes.iter() {
            record_outcome(self.audit, o);
        }
        if !sent {
            let next = self.slot.error(self.now);
            self.apply(next);
        }
    }

    /// A backend socket from the next free port of `TLS_PORTS`; none can
    /// be made, the backend is unavailable (502).
    fn connect(&mut self) {
        let (start, count) = config::TLS_PORTS;
        let mut opened = None;
        for _ in 0..count {
            let port = start.wrapping_add(*self.next_port % count);
            *self.next_port = (*self.next_port % count).wrapping_add(1);
            // A port another backend socket still holds is skipped.
            let held = |s: &tcp::Socket<'_>| s.local_endpoint().is_some_and(|e| e.port == port);
            if self.backends.iter().filter_map(|(_, s)| tcp::Socket::downcast(s)).any(held) {
                continue;
            }
            // SAFETY: listener i's backend socket was released (removed and
            // dropped) before its slot could ask for another connect.
            opened = unsafe { backend_socket(self.i, self.inside_iface, port) }.map(|s| (self.backends.add(s), port));
            break;
        }
        match opened {
            Some((handle, port)) => self.l.backend = Backend { handle: Some(handle), port, ..Backend::default() },
            None => {
                self.l.backend = Backend::default();
                let next = self.slot.backend_rst(self.out, self.now);
                scrub_if_sealed(&next);
                self.apply(next);
            }
        }
    }

    /// The slot dropped the backend: its socket (if one was made) is
    /// aborted and its RST awaited from the next transmits of the inside
    /// interface.
    fn abort_backend(&mut self) {
        let b = &mut self.l.backend;
        b.aborting = true;
        b.rst_due = false;
        if let Some(h) = b.handle {
            let s = self.backends.get_mut::<tcp::Socket>(h);
            b.rst_due = s.remote_endpoint().is_some();
            s.abort();
        }
    }

    /// A client record may be handed over: always during the handshake
    /// (its flight fits the empty send buffer), afterwards only with room
    /// for the most a call writes.
    fn may_write(&self) -> bool {
        self.slot.stage() == Some(Stage::Handshake) || room(self.client) >= MAX_CLIENT_OUT
    }

    /// The connection's events this pass, then its timers.
    fn serve(&mut self) {
        // The peer's RST or a TCP timeout closed the socket under the
        // connection (a RST in SYN-RECEIVED puts it back to Listen, where a
        // new client must not inherit this slot).
        let gone = matches!(self.client.state(), tcp::State::Closed | tcp::State::Listen);
        match self.slot.stage() {
            Some(_) if gone => {
                let next = self.slot.client_gone(self.now);
                self.apply(next);
            }
            Some(_) => self.proxy(),
            // Closing: close_notify or the alert drained, then (after
            // close_notify) any inbound record, FIN or reset ends the linger.
            None => {
                let mut action = Action::None;
                if self.client.send_queue() == 0 || gone {
                    action = self.slot.drained(self.now);
                }
                if action == Action::None && (self.client.recv_queue() > 0 || fin_received(self.client) || gone) {
                    action = self.slot.inbound();
                }
                self.apply(Next { action, ..Next::default() });
            }
        }
        let next = self.slot.timers(self.now, self.out);
        scrub_if_sealed(&next);
        self.apply(next);
    }

    /// An open connection's events, in the order the flow needs them.
    fn proxy(&mut self) {
        if self.slot.stage() == Some(Stage::BackendConnect) && self.backend().is_some_and(|s| s.may_send()) {
            let next = self.slot.backend_connected(self.now);
            self.apply(next);
        }
        // Client records, each only once the bytes the last one carried for
        // the backend have gone.
        loop {
            self.push_to_backend();
            if self.slot.stage().is_none() || !self.slot.reads_client() || !self.may_write() {
                break;
            }
            let Some(rec) = take_record(self.client, self.record) else { break };
            let next = self.slot.client_record(rec, self.out, self.ctx, self.now);
            // Secrets the session moved (Rust moves are copies that nothing
            // wipes) and libcrux's frames, below this one.
            tls_core::scrub_session_stack();
            self.apply(next);
        }
        self.relay_backend();
        // The client's FIN once its complete records have been read: before
        // the response ended, so the backend is aborted with it.
        if self.slot.stage().is_some() && fin_received(self.client) && complete_record(self.client).is_none() {
            let next = self.slot.client_fin(self.now);
            self.apply(next);
        }
    }

    /// The slot's bytes for the backend into its socket's free room.
    fn push_to_backend(&mut self) {
        if self.slot.stage() != Some(Stage::Streaming) {
            return;
        }
        let Some(h) = self.l.backend.handle.filter(|_| !self.l.backend.aborting) else { return };
        let s = self.backends.get_mut::<tcp::Socket>(h);
        loop {
            let data = self.slot.to_backend();
            if data.is_empty() {
                return;
            }
            let n = s.send_slice(data).unwrap_or(0);
            if n == 0 {
                return;
            }
            self.slot.backend_sent(n, self.now);
        }
    }

    /// The backend's bytes to the client in chunks, while the client socket
    /// has room for each; then its FIN once every byte before it has gone,
    /// or its close without one.
    fn relay_backend(&mut self) {
        let Some(h) = self.l.backend.handle.filter(|_| !self.l.backend.aborting) else { return };
        while self.slot.stage() == Some(Stage::Streaming) && room(self.client) >= MAX_CLIENT_OUT {
            let s = self.backends.get_mut::<tcp::Socket>(h);
            if !s.can_recv() {
                break;
            }
            let (slot, out, now) = (&mut *self.slot, &mut *self.out, self.now);
            let next = s.recv(|data| {
                let n = data.len().min(BACKEND_CHUNK);
                (n, slot.backend_data(data.get(..n).unwrap_or(&[]), out, now))
            });
            match next {
                Ok(next) => {
                    scrub_if_sealed(&next);
                    self.apply(next);
                }
                Err(_) => break,
            }
        }
        if !matches!(self.slot.stage(), Some(Stage::BackendConnect | Stage::Streaming))
            || room(self.client) < MAX_CLIENT_OUT
        {
            return;
        }
        let s = self.backends.get_mut::<tcp::Socket>(h);
        self.l.backend.fin |= fin_received(s);
        let next = match backend_end(self.l.backend.fin, s.recv_queue(), s.state() == tcp::State::Closed) {
            BackendEnd::Fin => self.slot.backend_fin(self.out, self.now),
            BackendEnd::Rst => self.slot.backend_rst(self.out, self.now),
            BackendEnd::Open => return,
        };
        scrub_if_sealed(&next);
        self.apply(next);
    }
}

impl Tls {
    /// One bounded pass: at most PASS_PACKETS segments in on each link,
    /// every connection served, everything due sent on both, then the
    /// aborted sockets whose RST went out (or whose passes ran out)
    /// released before the next poll of their interface. Returns the
    /// segments taken on each link.
    fn pass(&mut self) -> (usize, usize) {
        let t = now();
        let now_ns = cpu::now_ns();
        self.outside.rsts.clear();
        self.inside.rsts.clear();
        let mut out_dev = Dev { link: &mut self.outside, audit: &mut self.audit };
        self.iface.poll_maintenance(t);
        let taken_out = ingress(&mut self.iface, t, &mut out_dev, &mut self.sockets);
        let mut in_dev = Dev { link: &mut self.inside, audit: &mut self.audit };
        self.inside_iface.poll_maintenance(t);
        let taken_in = ingress(&mut self.inside_iface, t, &mut in_dev, &mut self.backend_sockets);
        for i in 0..MAX_CONNS {
            self.serve(i, now_ns);
        }
        self.iface.poll_egress(t, &mut Dev { link: &mut self.outside, audit: &mut self.audit }, &mut self.sockets);
        self.inside_iface.poll_egress(
            t,
            &mut Dev { link: &mut self.inside, audit: &mut self.audit },
            &mut self.backend_sockets,
        );
        for i in 0..MAX_CONNS {
            self.after_egress(i);
        }
        if let Some((code, reason)) = halt::after_sign(self.unavailable.take()) {
            self.audit.record(Event::KeyUnavailable { code });
            self.audit.halt(reason);
        }
        (taken_out, taken_in)
    }

    fn serve(&mut self, i: usize, now_ns: u64) {
        let Tls {
            sockets, backend_sockets, inside_iface, listeners, table, record, out, rng, audit, sign_us, unavailable, next_port, ..
        } = self;
        let Some(l) = listeners.get_mut(i) else { return };
        if l.aborting {
            return;
        }
        let client = sockets.get_mut::<tcp::Socket>(l.handle);
        let Some(k) = l.slot else {
            match client.state() {
                tcp::State::Listen => {}
                // Closed before it was seen: nothing was admitted on it.
                tcp::State::Closed => {
                    if client.listen(config::HTTPS_PORT).is_err() {
                        audit.halt(halt::INIT_FAILED);
                    }
                }
                _ => admit(l, client, table, audit, now_ns),
            }
            return;
        };
        let Some(slot) = table.slots.get_mut(k) else { return };
        if client.state() == tcp::State::Established && !l.raised {
            client.set_timeout(Some(IDLE_TIMEOUT));
            l.raised = true;
        }
        let mut signer = KeySigner { sign_us, unavailable };
        let mut ctx = Ctx { cert: config::TLS_CERT, rng, signer: &mut signer };
        Conn {
            i,
            l,
            client,
            slot,
            backends: backend_sockets,
            inside_iface,
            next_port,
            record,
            out,
            ctx: &mut ctx,
            audit,
            now: now_ns,
        }
        .serve();
    }

    /// After the pass's transmits: an aborted backend socket whose RST was
    /// observed on `tln` (or none due, or its passes used up) is removed
    /// and its storage wiped through the static, before the next poll of
    /// the inside interface; an aborted client socket likewise on `tli`,
    /// its listener re-created, once the slot is released (both RSTs done;
    /// M6 plan C8, F-R5-2, F-R7-1).
    fn after_egress(&mut self, i: usize) {
        let Some(l) = self.listeners.get_mut(i) else { return };
        let Some(k) = l.slot else { return };
        let Some(slot) = self.table.slots.get_mut(k) else { return };
        let mut released = false;
        if l.backend.aborting {
            let dispatched = !l.backend.rst_due || self.inside.rsts.contains((config::BACKEND.0, l.backend.port));
            released = slot.abort_pass(Endpoint::Backend, dispatched) == Action::Release;
            if !slot.backend_rst_pending() {
                release_backend(i, &mut l.backend, &mut self.backend_sockets);
            }
        }
        if !released && l.aborting {
            let dispatched = !l.rst_due || self.outside.rsts.contains(l.peer);
            released = slot.abort_pass(Endpoint::Client, dispatched) == Action::Release;
        }
        if !released {
            return;
        }
        // Never left open by a released slot (it aborts the backend before
        // it can release); a socket left here would hold its storage.
        release_backend(i, &mut l.backend, &mut self.backend_sockets);
        // The removed socket, and with it its borrow of the buffers, ends
        // here.
        let _ = self.sockets.remove(l.handle);
        // SAFETY: listener i's socket was just removed from its set and
        // dropped, so nothing else holds its buffers.
        match unsafe { listener_socket(i) } {
            Some(s) => *l = Listener { handle: self.sockets.add(s), ..Listener::default() },
            None => self.audit.halt(halt::INIT_FAILED),
        }
    }
}

/// Up to PASS_PACKETS segments from `dev` into `iface`'s sockets.
fn ingress(iface: &mut Interface, t: Instant, dev: &mut Dev<'_>, sockets: &mut SocketSet<'static>) -> usize {
    let mut taken = 0;
    while taken < PASS_PACKETS {
        match iface.poll_ingress_single(t, dev, sockets) {
            PollIngressSingleResult::None => break,
            _ => taken += 1,
        }
    }
    taken
}

/// Listener `i`'s backend socket, if it has one, removed from its set and
/// its storage wiped through the static (M6 plan C8; the backend path has
/// no value unique to `tls`, so this wipe is reviewed, not red-proved,
/// T-R7-1).
fn release_backend(i: usize, b: &mut Backend, sockets: &mut SocketSet<'static>) {
    if let Some(h) = b.handle.take() {
        // The removed socket, and with it its borrow of the buffers, ends
        // here.
        let _ = sockets.remove(h);
        // SAFETY: listener i's backend socket was just removed from its set
        // and dropped, so nothing else holds its buffers.
        if let Some((rx, tx)) = unsafe { backend_buffers(i) } {
            rx.zeroize();
            tx.zeroize();
        }
    }
    *b = Backend::default();
}

/// A connection leaving Listen gets a slot, or is refused (per-source cap)
/// and aborted like any other.
fn admit(l: &mut Listener, s: &mut tcp::Socket<'_>, table: &mut Table, audit: &mut Audit, now_ns: u64) {
    let Some(ep) = s.remote_endpoint() else { return };
    let IpAddress::Ipv4(addr) = ep.addr;
    let source = addr.octets();
    l.peer = (source, ep.port);
    match table.admit(source, now_ns) {
        Ok(k) => l.slot = Some(k),
        Err(refusal) => {
            audit.record(Event::TlsClosed { reason: Closed::from(refusal).code() });
            // One slot per listener, so a free one always exists; without
            // one the socket is still aborted, and re-listened unobserved.
            l.slot = table.refuse();
            abort(l, s);
        }
    }
}

/// The slot is wiped (by `conn`); the socket is aborted, and its RST is
/// awaited from the next transmits.
fn abort(l: &mut Listener, s: &mut tcp::Socket<'_>) {
    l.rst_due = s.remote_endpoint().is_some();
    s.abort();
    l.aborting = l.slot.is_some();
}

struct Pass<'a> {
    tls: &'a mut Tls,
}

impl ring::pass::Pass for Pass<'_> {
    fn serve(&mut self) -> bool {
        let (outside, inside) = self.tls.pass();
        any_full(&[outside, inside], PASS_PACKETS)
    }

    fn end_pass(&mut self) {
        if core::mem::take(&mut self.tls.outside.sent) {
            INGRESS.notify();
        }
        if core::mem::take(&mut self.tls.inside.sent) {
            INNER.notify();
        }
        self.tls.audit.flush();
    }
}

impl Handler for Tls {
    type Error = Infallible;

    /// A notification from `ingress`, `inner` or the 1 Hz timer: each runs
    /// the passes, the timer's for the connection timers and smoltcp's
    /// retransmissions and timeouts.
    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        run_passes(&mut Pass { tls: self });
        if let Some(us) = self.sign_us.take() {
            let audit = &mut self.audit;
            self.sign_wait.observe_with(us, |ev| audit.record_delivered(ev));
        }
        if channels.contains(TIMER) {
            let audit = &mut self.audit;
            self.stack.deeper_with(|hw, _| {
                audit.record_delivered(Event::StackHighWater { bytes: u32::try_from(hw).unwrap_or(u32::MAX) })
            });
        }
        self.audit.flush();
        Ok(())
    }
}
