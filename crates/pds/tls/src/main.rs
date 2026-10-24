//! `tls` (M6 plan C1, C3): the HTTPS endpoint. TCP runs in smoltcp on the
//! IP packets `ingress` vetted (`itl`), and every segment goes back out
//! through `ingress`'s `tls_egress` (`tli`); eight listeners on the HTTPS
//! port. Until the TLS server lands (plan C7) each connection's bytes are
//! echoed back. Tainted (law L1); holds no secret yet.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;

use audit_event::Event;
use layout::tls as ch;
use pdkit::{Audit, Buf, Rx, Tx};
use ring::pass::{any_full, run_passes};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, memory_region_symbol, protection_domain};
use smoltcp::iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const TIMER: Channel = Channel::new(ch::CH_TIMER);

/// Connections at once (plan C10), one listener each.
const MAX_CONNS: usize = 8;
// One backend source port per connection at least (config validates
// `TLS_PORTS` against the same bound, plan C3).
const _: () = assert!(config::TLS_PORTS.1 as usize >= MAX_CONNS);
const RX_BUF: usize = 16 * 1024;
const TX_BUF: usize = 8 * 1024;
/// The largest IP packet either ring carries: Ethernet's.
const MTU: usize = 1500;
const _: () = assert!(MTU <= layout::NET_BUF_SIZE);
/// A listener's timeout: a handshake that never completes frees its slot
/// (smoltcp has no SYN cookies, RM6-7). smoltcp's timeout is per socket,
/// so it is raised to the idle timeout once the connection is established.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Packets taken from `itl` per pass.
const PASS_PACKETS: usize = layout::NET_BUFFERS;

/// `Halted` reasons (the record's `a`), stable per M5 plan C6.
mod halt {
    /// CNTFRQ is 0: no clock, so no TCP timer would ever fire.
    pub const NO_CLOCK: u32 = 1;
    /// RNDR failed: no seed for smoltcp's initial sequence numbers.
    pub const RNDR: u32 = 2;
    /// The interface or a listener could not be set up.
    pub const INIT_FAILED: u32 = 3;
}

/// The sockets and their buffers: too large for the stack, where the
/// handler state lives, so static.
struct Storage {
    sockets: [SocketStorage<'static>; MAX_CONNS],
    rx: [[u8; RX_BUF]; MAX_CONNS],
    tx: [[u8; TX_BUF]; MAX_CONNS],
}

struct Static(UnsafeCell<Storage>);

// SAFETY: a PD runs one thread, and only `init` (once) takes the storage.
unsafe impl Sync for Static {}

static STORAGE: Static = Static(UnsafeCell::new(Storage {
    sockets: [SocketStorage::EMPTY; MAX_CONNS],
    rx: [[0; RX_BUF]; MAX_CONNS],
    tx: [[0; TX_BUF]; MAX_CONNS],
}));

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
        *self.sent |= pdkit::send(self.tx, self.scratch, packet, self.audit);
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

struct Tls {
    rings: Rings,
    /// The backend links (M6 plan C1): mapped, unused until the inside
    /// interface and the proxy arrive (plan C3, C4).
    _to_inner: Tx,
    _from_inner: Rx,
    iface: Interface,
    sockets: SocketSet<'static>,
    listeners: [Listener; MAX_CONNS],
    stack: cpu::StackProbe,
}

/// One listener's socket, and whether its timeout was raised for the
/// connection it holds.
#[derive(Clone, Copy, Default)]
struct Listener {
    handle: SocketHandle,
    raised: bool,
}

fn now() -> Instant {
    Instant::from_micros(i64::try_from(cpu::now_ns() / 1000).unwrap_or(i64::MAX))
}

fn listen(s: &mut tcp::Socket<'_>) -> bool {
    s.set_timeout(Some(LISTEN_TIMEOUT));
    s.listen(config::HTTPS_PORT).is_ok()
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
    // The hedged RNG seeded by `key` replaces RNDR alone here (plan C7).
    let seed = cpu::rndr().unwrap_or_else(|| audit.halt(halt::RNDR));
    let mut rings = Rings {
        rx,
        tx,
        audit,
        packet: [0; layout::NET_BUF_SIZE],
        staging: [0; layout::NET_BUF_SIZE],
        scratch: [0; layout::NET_BUF_SIZE],
        sent: false,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let mut iface = Interface::new(config, &mut rings, now());
    let ours = Ipv4Address::from(config::OUTSIDE_IP);
    let mut added = false;
    iface.update_ip_addrs(|addrs| added = addrs.push(IpCidr::new(IpAddress::Ipv4(ours), 32)).is_ok());
    // Every client is off-link: `ingress` frames every segment to the
    // router, so the route's gateway is never looked up (raw IP medium).
    if !added || iface.routes_mut().add_default_ipv4_route(ours).is_err() {
        rings.audit.halt(halt::INIT_FAILED);
    }
    // SAFETY: init runs once and is the only place the storage is reached;
    // from here the socket set owns it for the life of the system.
    let Storage { sockets: slots, rx: rx_bufs, tx: tx_bufs } = unsafe { &mut *STORAGE.0.get() };
    let mut sockets = SocketSet::new(&mut slots[..]);
    let mut listeners = [Listener::default(); MAX_CONNS];
    for ((l, rx), tx) in listeners.iter_mut().zip(rx_bufs.iter_mut()).zip(tx_bufs.iter_mut()) {
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(&mut rx[..]), tcp::SocketBuffer::new(&mut tx[..]));
        s.set_ack_delay(None);
        s.set_nagle_enabled(false);
        if !listen(&mut s) {
            rings.audit.halt(halt::INIT_FAILED);
        }
        l.handle = sockets.add(s);
    }
    rings.audit.ready();
    Tls { rings, _to_inner: to_inner, _from_inner: from_inner, iface, sockets, listeners, stack }
}

/// Echoes what `s` has received, as far as its send buffer has room.
/// Temporary: the TLS server replaces it (plan C7).
fn echo(s: &mut tcp::Socket<'_>) {
    let mut chunk = [0u8; 1024];
    while s.can_recv() && s.can_send() {
        let room = s.send_capacity().saturating_sub(s.send_queue()).min(chunk.len());
        let Some(buf) = chunk.get_mut(..room) else { break };
        let n = match s.recv_slice(buf) {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        if s.send_slice(buf.get(..n).unwrap_or(&[])).is_err() {
            break;
        }
    }
    chunk.fill(0);
}

impl Tls {
    /// One bounded pass: at most PASS_PACKETS segments in, every socket
    /// served, everything due sent. Returns the segments taken.
    fn pass(&mut self) -> usize {
        let t = now();
        self.iface.poll_maintenance(t);
        let mut taken = 0;
        while taken < PASS_PACKETS {
            match self.iface.poll_ingress_single(t, &mut self.rings, &mut self.sockets) {
                PollIngressSingleResult::None => break,
                _ => taken += 1,
            }
        }
        for l in &mut self.listeners {
            let s = self.sockets.get_mut::<tcp::Socket>(l.handle);
            match s.state() {
                // Closed by RST, timeout or a finished close: listen again.
                tcp::State::Closed => {
                    l.raised = false;
                    // The port is nonzero and the socket closed, so this
                    // cannot fail; if it did, a slot would be lost unseen.
                    if !listen(s) {
                        self.rings.audit.halt(halt::INIT_FAILED);
                    }
                }
                tcp::State::Established if !l.raised => {
                    s.set_timeout(Some(IDLE_TIMEOUT));
                    l.raised = true;
                }
                _ => {}
            }
            echo(s);
            // The client sent FIN: what it sent is echoed, so close too.
            if s.state() == tcp::State::CloseWait {
                s.close();
            }
        }
        self.iface.poll_egress(t, &mut self.rings, &mut self.sockets);
        taken
    }
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
    /// passes, the timer's for smoltcp's retransmissions and timeouts.
    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        run_passes(&mut Pass { tls: self });
        if channels.contains(TIMER) {
            let audit = &mut self.rings.audit;
            self.stack.deeper_with(|hw, _| {
                audit.record_delivered(Event::StackHighWater { bytes: u32::try_from(hw).unwrap_or(u32::MAX) })
            });
            self.rings.audit.flush();
        }
        Ok(())
    }
}
