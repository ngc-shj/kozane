//! `tls` (M6 plan C1, C3, C7, C8): the HTTPS endpoint. TCP runs in smoltcp
//! on the IP packets `ingress` vetted (`itl`), and every segment goes back
//! out through `ingress`'s `tls_egress` (`tli`); eight listeners on the
//! HTTPS port, each with one connection slot of `tls_core::conn`, which
//! holds the TLS 1.3 session and decides every timeout, close and wipe.
//! The server's CertificateVerify is signed by `tlskey` (`TlsSign` over
//! PPC, M6 plan C12); the randomness is hedged over `tlskey`'s boot seed,
//! RNDR and CNTPCT. Until the proxy lands (plan C4, C10; slice 4) a complete request
//! head gets a fixed response, then close_notify. Tainted (law L1).

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
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tls_core::conn::{Action, CloseCause, Closed, Endpoint, HEAD_BUF_LEN, Slot, Stage, Table, Timeout};
use tls_core::halt;
use tls_core::handshake::{Ctx, Event as TlsEvent, Signer};
use tls_core::rng::{HedgeHw, Hedged, Rng, SEED_LEN};
use tls_core::{Refusal, Secret};
use tls_wire::{HASH_LEN, MAX_CIPHERTEXT, RECORD_HEADER_LEN};
use zeroize::Zeroize;

const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const TIMER: Channel = Channel::new(ch::CH_TIMER);
const TLSKEY: Channel = Channel::new(ch::CH_TLSKEY);

/// Connections at once (plan C10), one listener and one slot each.
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
/// The records one call writes: at most the server's flight (ServerHello,
/// then EncryptedExtensions, Certificate, CertificateVerify and Finished,
/// one record each), which must also fit the empty send buffer.
const OUT_BUF: usize = 8 * 1024;
const FLIGHT_MAX: usize = config::TLS_CERT.len() + 2048;
const _: () = assert!(FLIGHT_MAX <= OUT_BUF && FLIGHT_MAX <= TX_BUF);
/// The largest IP packet either ring carries: Ethernet's.
const MTU: usize = 1500;
const _: () = assert!(MTU <= layout::NET_BUF_SIZE);
/// A listener's timeout: a handshake that never completes frees its slot
/// (smoltcp has no SYN cookies, RM6-7). smoltcp's timeout is per socket,
/// so it is raised to the idle timeout once the connection is established.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(tls_core::conn::IDLE_TIMEOUT_NS / 1_000_000_000);
/// Packets taken from `itl` per pass.
const PASS_PACKETS: usize = layout::NET_BUFFERS;
/// The static per-connection state (plan C10, F18) is bounded.
const TLS_STATE_MAX: usize = 1 << 20;
const _: () = assert!(core::mem::size_of::<Storage>() <= TLS_STATE_MAX);

/// What a complete request head gets until the proxy lands (slice 4).
const FIXED_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsecureos tls ok\n";
const _: () = assert!(FIXED_RESPONSE.len() <= tls_core::handshake::MAX_SERVER_RECORD);

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
    let statuses = [
        Status::BadRequest,
        Status::ContentTooLarge,
        Status::ExpectationFailed,
        Status::HeaderFieldsTooLarge,
        Status::NotImplemented,
    ];
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
/// sockets and their buffers, the connection slots, and the record buffers
/// a pass works in.
struct Storage {
    sockets: [SocketStorage<'static>; MAX_CONNS],
    rx: [[u8; RX_BUF]; MAX_CONNS],
    tx: [[u8; TX_BUF]; MAX_CONNS],
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
// socket buffers are reached again only through `socket_buffers`.
unsafe impl Sync for Static {}

static STORAGE: Static = Static(UnsafeCell::new(Storage {
    sockets: [SocketStorage::EMPTY; MAX_CONNS],
    rx: [[0; RX_BUF]; MAX_CONNS],
    tx: [[0; TX_BUF]; MAX_CONNS],
    record: [0; RECORD_BUF],
    out: [0; OUT_BUF],
    table: MaybeUninit::uninit(),
}));

/// Listener `i`'s socket buffers, through the static.
///
/// # Safety
/// No other reference to them may be live: listener `i`'s socket was never
/// made or has been removed from its set and dropped.
unsafe fn socket_buffers(i: usize) -> Option<(&'static mut [u8; RX_BUF], &'static mut [u8; TX_BUF])> {
    if i >= MAX_CONNS {
        return None;
    }
    let s = STORAGE.0.get();
    // SAFETY: `i` is in bounds; raw places, so no reference to another
    // listener's buffers (held by its socket) is made; exclusivity of these
    // two is the caller's.
    unsafe {
        let rx = addr_of_mut!((*s).rx).cast::<[u8; RX_BUF]>().add(i);
        let tx = addr_of_mut!((*s).tx).cast::<[u8; TX_BUF]>().add(i);
        Some((&mut *rx, &mut *tx))
    }
}

/// The client RSTs this pass's transmits wrote into `tli`, by peer: how an
/// aborted socket's RST is observed (M6 plan C8, F-R6-2).
#[derive(Default)]
struct RstLog {
    peers: [([u8; 4], u16); 2 * MAX_CONNS],
    len: usize,
}

impl RstLog {
    /// A full log drops the entry: its slot waits further passes, at most
    /// `MAX_RST_PASSES` in all.
    fn push(&mut self, peer: ([u8; 4], u16)) {
        if let Some(e) = self.peers.get_mut(self.len) {
            *e = peer;
            self.len += 1;
        }
    }

    fn contains(&self, peer: ([u8; 4], u16)) -> bool {
        self.peers.get(..self.len).unwrap_or(&[]).contains(&peer)
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// The peer of a RST from the HTTPS port in `packet`, an IP packet smoltcp
/// built, read with `wire`'s checked parsers.
fn rst_peer(packet: &[u8]) -> Option<([u8; 4], u16)> {
    let ip = wire::parse_ipv4_packet(packet).ok()?;
    let tcp = wire::parse_tcp(&ip).ok()?;
    (tcp.flags & wire::TCP_RST != 0 && tcp.src_port == config::HTTPS_PORT).then_some((ip.dst, tcp.dst_port))
}

/// `itl` and `tli` as smoltcp's device: one IP packet per buffer.
struct Rings {
    rx: Rx,
    tx: Tx,
    audit: Audit,
    packet: Buf,
    staging: Buf,
    scratch: Buf,
    /// A segment went to `ingress` since it was last notified.
    sent: bool,
    rsts: RstLog,
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
        // Only a RST that reached `tli` counts as dispatched.
        if sent && let Some(peer) = rst_peer(packet) {
            self.rsts.push(peer);
        }
        *self.sent |= sent;
        r
    }
}

impl Rings {
    fn tx_token(&mut self) -> TxToken<'_> {
        TxToken {
            tx: &mut self.tx,
            staging: &mut self.staging,
            scratch: &mut self.scratch,
            audit: &mut self.audit,
            sent: &mut self.sent,
            rsts: &mut self.rsts,
        }
    }
}

impl Device for Rings {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: Instant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        let n = pdkit::recv(&mut self.rx, &mut self.packet, &mut self.audit)?;
        let packet = self.packet.get(..n).unwrap_or(&[]);
        let tx = TxToken {
            tx: &mut self.tx,
            staging: &mut self.staging,
            scratch: &mut self.scratch,
            audit: &mut self.audit,
            sent: &mut self.sent,
            rsts: &mut self.rsts,
        };
        Some((RxToken { packet }, tx))
    }

    /// No buffer free: smoltcp keeps the segment and retransmits it.
    fn transmit(&mut self, _: Instant) -> Option<TxToken<'_>> {
        match self.tx.free() {
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
    peer: ([u8; 4], u16),
    /// Aborted: the slot is wiped and awaits the socket's RST.
    aborting: bool,
    /// The aborted socket still had a 4-tuple, so a RST is due from it;
    /// without one (the peer's RST or a TCP timeout closed it first)
    /// nothing will be dispatched.
    rst_due: bool,
    /// Bytes of the request head in the slot's head buffer.
    head_len: usize,
}

struct Tls {
    rings: Rings,
    /// The backend links (M6 plan C1): mapped, unused until the inside
    /// interface and the proxy arrive (plan C3, C4; slice 4).
    _to_inner: Tx,
    _from_inner: Rx,
    iface: Interface,
    sockets: SocketSet<'static>,
    listeners: [Listener; MAX_CONNS],
    table: &'static mut Table,
    record: &'static mut [u8; RECORD_BUF],
    out: &'static mut [u8; OUT_BUF],
    rng: Hedged<Hw>,
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
    let mut seed = [0u8; 8];
    if rng.fill(&mut seed).is_err() {
        audit.halt(halt::RNDR);
    }
    let mut rings = Rings {
        rx,
        tx,
        audit,
        packet: [0; layout::NET_BUF_SIZE],
        staging: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
        sent: false,
        rsts: RstLog::default(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = u64::from_le_bytes(seed);
    let mut iface = Interface::new(config, &mut rings, now());
    let ours = Ipv4Address::from(config::OUTSIDE_IP);
    let mut added = false;
    iface.update_ip_addrs(|addrs| added = addrs.push(IpCidr::new(IpAddress::Ipv4(ours), 32)).is_ok());
    // Every client is off-link: `ingress` frames every segment to the
    // router, so the route's gateway is never looked up (raw IP medium).
    if !added || iface.routes_mut().add_default_ipv4_route(ours).is_err() {
        rings.audit.halt(halt::INIT_FAILED);
    }
    let st = STORAGE.0.get();
    // SAFETY: init runs once and is the only place these parts of the
    // storage are handed out; from here the socket set owns the socket
    // slots, the PD the table and record buffers, for the life of the
    // system. Raw places keep the parts disjoint from the socket buffers.
    let (slots, record, out, table) = unsafe {
        (
            &mut *addr_of_mut!((*st).sockets),
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
            None => rings.audit.halt(halt::INIT_FAILED),
        }
    }
    // The boot seed's copies in the frames below.
    tls_core::scrub_session_stack();
    rings.audit.ready();
    let mut tls = Tls {
        rings,
        _to_inner: to_inner,
        _from_inner: from_inner,
        iface,
        sockets,
        listeners,
        table,
        record,
        out,
        rng,
        sign_us: None,
        sign_wait: CostHighWater::tls_sign(),
        unavailable: None,
        stack,
    };
    tls.rings.audit.flush();
    tls
}

/// One whole record from `s` into `buf`, if one is complete. A header that
/// fails its checks is taken alone, so the session refuses it at once.
fn take_record<'b>(s: &mut tcp::Socket<'_>, buf: &'b mut [u8; RECORD_BUF]) -> Option<&'b [u8]> {
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
    if s.recv_queue() < len {
        return None;
    }
    let n = s.recv_slice(buf.get_mut(..len)?).ok()?;
    buf.get(..n)
}

/// The client has sent its FIN.
fn fin_received(s: &tcp::Socket<'_>) -> bool {
    matches!(s.state(), tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait)
}

/// Queues `bytes` whole on `s`, or nothing.
fn send_all(s: &mut tcp::Socket<'_>, bytes: &[u8]) -> bool {
    s.send_capacity().saturating_sub(s.send_queue()) >= bytes.len() && s.send_slice(bytes) == Ok(bytes.len())
}

/// What a request head gets until the proxy lands: the fixed response, or
/// the refusal's status (audited).
fn response(head: &[u8], audit: &mut Audit) -> Option<&'static [u8]> {
    let parsed = match http_wire::head_end(head) {
        Ok(None) => return None,
        Ok(Some(end)) => http_wire::request_head(head.get(..end).unwrap_or(head)).map(|_| ()),
        Err(e) => Err(e),
    };
    Some(match parsed {
        Ok(()) => FIXED_RESPONSE,
        Err(e) => {
            audit.record(Event::HttpRefused { status: e.status().index() });
            http_wire::refusal_response(e.status())
        }
    })
}

impl Tls {
    /// One bounded pass: at most PASS_PACKETS segments in, every listener
    /// served, everything due sent, then the aborted sockets whose RST went
    /// out (or whose passes ran out) released before the next poll.
    /// Returns the segments taken.
    fn pass(&mut self) -> usize {
        let t = now();
        let now_ns = cpu::now_ns();
        self.rings.rsts.clear();
        self.iface.poll_maintenance(t);
        let mut taken = 0;
        while taken < PASS_PACKETS {
            match self.iface.poll_ingress_single(t, &mut self.rings, &mut self.sockets) {
                PollIngressSingleResult::None => break,
                _ => taken += 1,
            }
        }
        for i in 0..MAX_CONNS {
            self.serve(i, now_ns);
        }
        self.iface.poll_egress(t, &mut self.rings, &mut self.sockets);
        for i in 0..MAX_CONNS {
            self.after_egress(i);
        }
        if let Some((code, reason)) = halt::after_sign(self.unavailable.take()) {
            self.rings.audit.record(Event::KeyUnavailable { code });
            self.rings.audit.halt(reason);
        }
        taken
    }

    fn serve(&mut self, i: usize, now_ns: u64) {
        let Tls { sockets, listeners, table, record, out, rng, rings, sign_us, unavailable, .. } = self;
        let Some(l) = listeners.get_mut(i) else { return };
        if l.aborting {
            return;
        }
        let s = sockets.get_mut::<tcp::Socket>(l.handle);
        let audit = &mut rings.audit;
        let Some(k) = l.slot else {
            match s.state() {
                tcp::State::Listen => {}
                // Closed before it was seen: nothing was admitted on it.
                tcp::State::Closed => {
                    if s.listen(config::HTTPS_PORT).is_err() {
                        audit.halt(halt::INIT_FAILED);
                    }
                }
                _ => admit(l, s, table, audit, now_ns),
            }
            return;
        };
        let Some(slot) = table.slots.get_mut(k) else { return };
        if s.state() == tcp::State::Established && !l.raised {
            s.set_timeout(Some(IDLE_TIMEOUT));
            l.raised = true;
        }
        // The peer's RST or a TCP timeout closed the socket under the
        // connection (a RST in SYN-RECEIVED puts it back to Listen, where a
        // new client must not inherit this slot).
        let gone = matches!(s.state(), tcp::State::Closed | tcp::State::Listen);
        let mut action = match slot.stage() {
            Some(_) if gone => {
                audit.record(Event::TlsClosed { reason: Closed::PeerReset.code() });
                slot.close(CloseCause::Error, &mut [], now_ns).1
            }
            Some(Stage::Handshake | Stage::Head) => {
                let mut signer = KeySigner { sign_us, unavailable };
                let mut ctx = Ctx { cert: config::TLS_CERT, rng, signer: &mut signer };
                read_records(l, s, slot, record, out, &mut ctx, audit, now_ns)
            }
            // The backend stages arrive with the proxy (slice 4).
            Some(Stage::BackendConnect | Stage::Streaming) => Action::None,
            // Closing: close_notify or the alert drained, then (after
            // close_notify) any inbound record, FIN or reset ends the linger.
            None => {
                let mut a = Action::None;
                if s.send_queue() == 0 || gone {
                    a = slot.drained(now_ns);
                }
                if a == Action::None && (s.recv_queue() > 0 || fin_received(s) || gone) {
                    a = slot.inbound();
                }
                a
            }
        };
        if action == Action::None {
            let (a, timeout) = slot.tick(now_ns);
            if let Some(t) = timeout {
                audit.record(Event::TlsTimeout { stage: t.stage() });
            }
            action = a;
        }
        if action == Action::Abort {
            abort(l, s);
        }
    }

    /// An aborted socket after the pass's transmits: its RST observed (or
    /// none due) or its passes used up → removed, its storage wiped through
    /// the static, the listener re-created, all before the next poll of
    /// the outside interface (M6 plan C8, F-R5-2).
    fn after_egress(&mut self, i: usize) {
        let Some(l) = self.listeners.get_mut(i) else { return };
        let Some(k) = l.slot.filter(|_| l.aborting) else { return };
        let Some(slot) = self.table.slots.get_mut(k) else { return };
        let dispatched = !l.rst_due || self.rings.rsts.contains(l.peer);
        if slot.abort_pass(Endpoint::Client, dispatched) != Action::Release {
            return;
        }
        // The removed socket, and with it its borrow of the buffers, ends
        // here.
        let _ = self.sockets.remove(l.handle);
        // SAFETY: listener i's socket was just removed from its set and
        // dropped, so nothing else holds its buffers.
        match unsafe { listener_socket(i) } {
            Some(s) => *l = Listener { handle: self.sockets.add(s), ..Listener::default() },
            None => self.rings.audit.halt(halt::INIT_FAILED),
        }
    }
}

/// A connection leaving Listen gets a slot, or is refused (per-source cap)
/// and aborted like any other.
fn admit(l: &mut Listener, s: &mut tcp::Socket<'_>, table: &mut Table, audit: &mut Audit, now_ns: u64) {
    let Some(ep) = s.remote_endpoint() else { return };
    let IpAddress::Ipv4(addr) = ep.addr;
    let source = addr.octets();
    l.peer = (source, ep.port);
    l.head_len = 0;
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
    l.head_len = 0;
}

/// Every complete record on `s` through the slot's session, the server's
/// records into the socket, the head collected; a complete head answered,
/// then close_notify. Returns the slot's action.
#[allow(clippy::too_many_arguments)]
fn read_records<R: Rng, S: Signer>(
    l: &mut Listener,
    s: &mut tcp::Socket<'_>,
    slot: &mut Slot,
    record: &mut [u8; RECORD_BUF],
    out: &mut [u8; OUT_BUF],
    ctx: &mut Ctx<'_, R, S>,
    audit: &mut Audit,
    now_ns: u64,
) -> Action {
    while slot.stage().is_some() {
        let Some(rec) = take_record(s, record) else { break };
        let r = slot.on_record(rec, out, ctx, now_ns);
        // Secrets the session moved (Rust moves are copies that nothing
        // wipes) and libcrux's frames, below this one.
        tls_core::scrub_session_stack();
        match r {
            Ok(step) => {
                if !send_all(s, out.get(..step.written).unwrap_or(&[])) {
                    audit.record(Event::TlsClosed { reason: Closed::Error.code() });
                    return slot.close(CloseCause::Error, &mut [], now_ns).1;
                }
                match step.event {
                    TlsEvent::AppData(n) => {
                        l.head_len = l.head_len.saturating_add(slot.append_head(n, l.head_len));
                        let head = slot.head.get(..l.head_len.min(HEAD_BUF_LEN)).unwrap_or(&[]);
                        if let Some(resp) = response(head, audit) {
                            return respond(s, slot, resp, out, audit, now_ns);
                        }
                    }
                    TlsEvent::CloseNotify => {
                        audit.record(Event::TlsClosed { reason: Closed::ClientClosed.code() });
                        return slot.close(CloseCause::ClientClosed, &mut [], now_ns).1;
                    }
                    TlsEvent::None | TlsEvent::Flight | TlsEvent::Connected => {}
                }
            }
            Err(failed) => {
                // The alert is sealed and the slot wiped: transmit, then
                // drain and abort.
                audit.record(Event::TlsRefused { reason: failed.refusal.code() });
                send_all(s, out.get(..failed.written).unwrap_or(&[]));
                return Action::None;
            }
        }
    }
    // The client's FIN before a complete head.
    if slot.stage().is_some() && fin_received(s) {
        audit.record(Event::TlsClosed { reason: Closed::ClientClosed.code() });
        return slot.close(CloseCause::ClientClosed, &mut [], now_ns).1;
    }
    Action::None
}

/// The response `tls` generated itself, in full, then close_notify (C10:
/// sealed into the socket, keys and buffers wiped, then transmitted).
fn respond(s: &mut tcp::Socket<'_>, slot: &mut Slot, resp: &[u8], out: &mut [u8], audit: &mut Audit, now_ns: u64) -> Action {
    let sealed = slot.seal_app(resp, out);
    // The record key's copies in the dead frames of the seal.
    tls_core::scrub_session_stack();
    let sent = sealed.is_ok_and(|n| send_all(s, out.get(..n).unwrap_or(&[])));
    if !sent {
        audit.record(Event::TlsClosed { reason: Closed::Error.code() });
        return slot.close(CloseCause::Error, &mut [], now_ns).1;
    }
    let (n, action) = slot.close(CloseCause::SelfResponse, out, now_ns);
    tls_core::scrub_session_stack();
    audit.record(Event::TlsClosed { reason: Closed::SelfResponse.code() });
    send_all(s, out.get(..n).unwrap_or(&[]));
    action
}

struct Pass<'a> {
    tls: &'a mut Tls,
}

impl ring::pass::Pass for Pass<'_> {
    fn serve(&mut self) -> bool {
        let n = self.tls.pass();
        any_full(&[n], PASS_PACKETS)
    }

    fn end_pass(&mut self) {
        if core::mem::take(&mut self.tls.rings.sent) {
            INGRESS.notify();
        }
        self.tls.rings.audit.flush();
    }
}

impl Handler for Tls {
    type Error = Infallible;

    /// A notification from `ingress` or the 1 Hz timer: both run the
    /// passes, the timer's for the connection timers and smoltcp's
    /// retransmissions and timeouts.
    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        run_passes(&mut Pass { tls: self });
        if let Some(us) = self.sign_us.take() {
            let audit = &mut self.rings.audit;
            self.sign_wait.observe_with(us, |ev| audit.record_delivered(ev));
        }
        if channels.contains(TIMER) {
            let audit = &mut self.rings.audit;
            self.stack.deeper_with(|hw, _| {
                audit.record_delivered(Event::StackHighWater { bytes: u32::try_from(hw).unwrap_or(u32::MAX) })
            });
        }
        self.rings.audit.flush();
        Ok(())
    }
}
