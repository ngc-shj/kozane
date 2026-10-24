//! Connection slots (M6 plan C8, C10): admission with the per-source cap,
//! the stage timers on an injected clock, close sequencing, and the wipe.
//! The PD wires smoltcp and the rings to this; every decision about when a
//! connection's secrets go and when its sockets may be released is here.
//!
//! Stages: Handshake → Head → BackendConnect → Streaming. The proxy flow
//! through them (the head parsed and rewritten by `http-wire`, the backend
//! connect, the request and response streamed) is [`proxy`]'s, driven by
//! the PD's events.
//!
//! Close: close_notify only after a clean backend FIN or a response `tls`
//! generated in full ([`CloseCause::BackendFin`],
//! [`CloseCause::SelfResponse`]); then, once the send buffer has drained,
//! at most [`CLOSE_LINGER_NS`] for any inbound record or FIN (not
//! decrypted: the keys are gone), then abort. Every other cause, and every
//! timeout, aborts at once (RST, no close_notify: truncation is visible).
//! An aborted socket's RST is dispatched by smoltcp at a later poll; the PD
//! reports each poll pass ([`Slot::abort_pass`]) and releases the socket
//! (removes it, wipes its storage, re-creates the listener) when told. If
//! the RST never goes out, the slot is released after
//! [`MAX_RST_PASSES`] passes anyway. The backend socket is aborted as the
//! connection leaves its open stages, whatever the cause (after a clean
//! FIN it has nothing left to carry), and its RST is awaited the same way;
//! the slot is released once both are done.

use tls_wire::Refusal;

use crate::handshake::{Buffers, Ctx, Event, RX_BUF_LEN, Session, Signer, Step, TX_BUF_LEN};
use crate::rng::Rng;
use crate::wipe;

mod proxy;

pub use proxy::{BACKEND_CHUNK, BAD_GATEWAY, BackendEnd, MAX_CLIENT_OUT, Next, Outcome, Outcomes, backend_end};

pub const MAX_CONNS: usize = 8;
/// Connections one source address may hold (S17).
pub const MAX_PER_SOURCE: usize = 2;

const NS_PER_SEC: u64 = 1_000_000_000;
pub const HANDSHAKE_TIMEOUT_NS: u64 = 10 * NS_PER_SEC;
pub const HEAD_TIMEOUT_NS: u64 = 10 * NS_PER_SEC;
pub const BACKEND_CONNECT_TIMEOUT_NS: u64 = 5 * NS_PER_SEC;
pub const IDLE_TIMEOUT_NS: u64 = 30 * NS_PER_SEC;
pub const LIFETIME_NS: u64 = 120 * NS_PER_SEC;
/// After close_notify has drained: the wait for an inbound record or FIN.
pub const CLOSE_LINGER_NS: u64 = 2 * NS_PER_SEC;
/// Poll passes an aborted socket's RST may take before the slot is
/// released without it (M6 plan C8, F-R5-1).
pub const MAX_RST_PASSES: u8 = 8;

/// The request head and its rewrite (M6 plan C9, C10; filled in slice 4).
pub const HEAD_BUF_LEN: usize = 8 * 1024;
pub const REWRITE_BUF_LEN: usize = 9 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Handshake,
    Head,
    BackendConnect,
    Streaming,
}

/// Which timer fired; audited as `TLS_TIMEOUT_BASE + stage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeout {
    Handshake = 0,
    Head = 1,
    BackendConnect = 2,
    Idle = 3,
    Lifetime = 4,
}

impl Timeout {
    /// Every variant, in stage order.
    pub const ALL: [Timeout; 5] = [Self::Handshake, Self::Head, Self::BackendConnect, Self::Idle, Self::Lifetime];

    pub const fn stage(self) -> u16 {
        self as u16
    }

    /// The name `audit` prints (`tls` checks audit-event's table).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Handshake => "Handshake",
            Self::Head => "Head",
            Self::BackendConnect => "BackendConnect",
            Self::Idle => "Idle",
            Self::Lifetime => "Lifetime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitRefusal {
    /// Every slot is taken.
    Full,
    /// The source already holds [`MAX_PER_SOURCE`] connections.
    PerSource,
}

/// What the PD does next for a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    #[default]
    None,
    /// Abort the client socket (RST, no close_notify), poll, and report
    /// each pass with [`Slot::abort_pass`].
    Abort,
    /// The RSTs are out, or their passes ran out: remove the sockets, wipe
    /// their storage, re-create the listener. The slot is free.
    Release,
}

/// Why a connection ends (C10 close rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCause {
    /// The backend closed cleanly after the response.
    BackendFin,
    /// `tls` generated the whole response itself before any backend byte
    /// (a refusal status).
    SelfResponse,
    /// The backend reset the connection.
    BackendRst,
    /// The client's FIN or close_notify before the response ended.
    ClientClosed,
    /// An error after the response started.
    Error,
}

/// Why `tls` ended a connection, audited as `TLS_CLOSED_BASE + code`: a
/// [`CloseCause`], an [`AdmitRefusal`], or the client socket closed under
/// the connection by the peer's RST or a TCP timeout (`PeerReset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    BackendFin,
    SelfResponse,
    BackendRst,
    ClientClosed,
    Error,
    SlotsFull,
    PerSource,
    PeerReset,
}

impl Closed {
    /// Every variant, in code order.
    pub const ALL: [Closed; 8] = [
        Self::BackendFin,
        Self::SelfResponse,
        Self::BackendRst,
        Self::ClientClosed,
        Self::Error,
        Self::SlotsFull,
        Self::PerSource,
        Self::PeerReset,
    ];

    pub const fn code(self) -> u16 {
        self as u16
    }

    /// The name `audit` prints (`tls` checks audit-event's table).
    pub const fn name(self) -> &'static str {
        match self {
            Self::BackendFin => "BackendFin",
            Self::SelfResponse => "SelfResponse",
            Self::BackendRst => "BackendRst",
            Self::ClientClosed => "ClientClosed",
            Self::Error => "Error",
            Self::SlotsFull => "SlotsFull",
            Self::PerSource => "PerSource",
            Self::PeerReset => "PeerReset",
        }
    }
}

impl From<CloseCause> for Closed {
    fn from(c: CloseCause) -> Self {
        match c {
            CloseCause::BackendFin => Self::BackendFin,
            CloseCause::SelfResponse => Self::SelfResponse,
            CloseCause::BackendRst => Self::BackendRst,
            CloseCause::ClientClosed => Self::ClientClosed,
            CloseCause::Error => Self::Error,
        }
    }
}

impl From<AdmitRefusal> for Closed {
    fn from(r: AdmitRefusal) -> Self {
        match r {
            AdmitRefusal::Full => Self::SlotsFull,
            AdmitRefusal::PerSource => Self::PerSource,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Client,
    Backend,
}

/// An aborted socket's RST: still to be seen, and the passes so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RstWait {
    pending: bool,
    passes: u8,
}

impl RstWait {
    const fn new(pending: bool) -> Self {
        Self { pending, passes: 0 }
    }

    fn pass(&mut self, dispatched: bool) {
        if !self.pending {
            return;
        }
        self.passes = self.passes.saturating_add(1);
        if dispatched || self.passes >= MAX_RST_PASSES {
            self.pending = false;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Free,
    Open { stage: Stage, since: u64 },
    /// close_notify (`linger`) or a fatal alert sealed; waiting for the
    /// send buffer to drain.
    Draining { linger: bool },
    /// close_notify drained: an inbound record or FIN, or the deadline,
    /// aborts.
    Lingering { until: u64 },
    Aborting { client: RstWait },
}

/// Bytes still to go to the backend: `[at, end)` of a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Span {
    at: usize,
    end: usize,
}

impl Span {
    const EMPTY: Self = Self { at: 0, end: 0 };

    fn is_empty(self) -> bool {
        self.at >= self.end
    }
}

/// A refused record: the alert (if any) is in `out[..written]` and the
/// slot is wiped; transmit, then report [`Slot::drained`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed {
    pub refusal: Refusal,
    pub written: usize,
}

pub struct Slot {
    phase: Phase,
    source: [u8; 4],
    accepted: u64,
    last_activity: u64,
    close_started: u64,
    /// A backend socket exists and has not been aborted yet.
    backend_open: bool,
    backend_rst: RstWait,
    /// The request head collected so far in [`Slot::head`].
    head_len: usize,
    /// Request body bytes still to come from the client and go on.
    body_left: usize,
    /// The rewritten head and the body bytes that came with it, in
    /// [`Slot::rewrite`]; then body bytes in the record buffer.
    pending_rewrite: Span,
    pending_rx: Span,
    session: Session,
    rx: [u8; RX_BUF_LEN],
    tx: [u8; TX_BUF_LEN],
    pub head: [u8; HEAD_BUF_LEN],
    pub rewrite: [u8; REWRITE_BUF_LEN],
}

impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}

impl Slot {
    pub fn new() -> Self {
        Self {
            phase: Phase::Free,
            source: [0; 4],
            accepted: 0,
            last_activity: 0,
            close_started: 0,
            backend_open: false,
            backend_rst: RstWait::new(false),
            head_len: 0,
            body_left: 0,
            pending_rewrite: Span::EMPTY,
            pending_rx: Span::EMPTY,
            session: Session::new(),
            rx: [0; RX_BUF_LEN],
            tx: [0; TX_BUF_LEN],
            head: [0; HEAD_BUF_LEN],
            rewrite: [0; REWRITE_BUF_LEN],
        }
    }

    pub fn is_free(&self) -> bool {
        self.phase == Phase::Free
    }

    pub fn stage(&self) -> Option<Stage> {
        match self.phase {
            Phase::Open { stage, .. } => Some(stage),
            _ => None,
        }
    }

    pub fn source(&self) -> [u8; 4] {
        self.source
    }

    pub(crate) fn open(&mut self, source: [u8; 4], now: u64) {
        self.reset();
        self.phase = Phase::Open { stage: Stage::Handshake, since: now };
        self.source = source;
        self.accepted = now;
        self.last_activity = now;
    }

    /// Bytes moved on the connection: resets only the idle timer, never the
    /// handshake or head timers.
    pub fn activity(&mut self, now: u64) {
        self.last_activity = now;
    }

    /// The next stage, from now: Head after the handshake, BackendConnect
    /// once the head is complete, Streaming once the backend connected.
    pub fn advance(&mut self, now: u64) {
        if let Phase::Open { stage, .. } = self.phase {
            let next = match stage {
                Stage::Handshake => Stage::Head,
                Stage::Head => {
                    self.backend_open = true;
                    Stage::BackendConnect
                }
                Stage::BackendConnect | Stage::Streaming => Stage::Streaming,
            };
            self.phase = Phase::Open { stage: next, since: now };
        }
    }

    /// One client record through the TLS session. The handshake's end moves
    /// the slot to [`Stage::Head`]. On a refusal the alert is sealed into
    /// `out`, everything is wiped and the slot drains then aborts.
    pub fn on_record<R: Rng, S: Signer>(
        &mut self,
        record: &[u8],
        out: &mut [u8],
        ctx: &mut Ctx<'_, R, S>,
        now: u64,
    ) -> Result<Step, Failed> {
        if !matches!(self.phase, Phase::Open { .. }) {
            return Err(Failed { refusal: Refusal::Closed, written: 0 });
        }
        self.activity(now);
        let mut bufs = Buffers { rx: &mut self.rx, tx: &mut self.tx, out };
        match self.session.on_record(record, &mut bufs, ctx) {
            Ok(step) => {
                if step.event == Event::Connected {
                    self.advance(now);
                }
                Ok(step)
            }
            Err(refusal) => {
                let written = self.session.fail(refusal, &mut bufs);
                self.wipe_buffers();
                self.abort_backend();
                self.close_started = now;
                self.phase = Phase::Draining { linger: false };
                Err(Failed { refusal, written })
            }
        }
    }

    /// Application data to the client: one record, at most 4 KiB.
    pub fn seal_app(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Refusal> {
        let mut bufs = Buffers { rx: &mut self.rx, tx: &mut self.tx, out };
        self.session.seal_app(data, &mut bufs)
    }

    /// The decrypted application data an `AppData(n)` step left.
    pub fn app_data(&self, n: usize) -> &[u8] {
        self.rx.get(..n).unwrap_or(&[])
    }

    /// Moves the application data an `AppData(n)` step left into
    /// [`Slot::head`] at `at`, as far as the head buffer has room, and wipes
    /// it from the record buffer. Returns the bytes moved.
    pub fn append_head(&mut self, n: usize, at: usize) -> usize {
        let data = self.rx.get_mut(..n).unwrap_or(&mut []);
        let room = self.head.get_mut(at..).unwrap_or(&mut []);
        let moved = data.len().min(room.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..moved), data.get(..moved)) {
            dst.copy_from_slice(src);
        }
        wipe(data);
        moved
    }

    /// Ends the connection for `cause`. A clean end seals close_notify into
    /// `out` (returned length), wipes, and drains; every other cause wipes
    /// and aborts at once. Either way an open backend socket is aborted.
    pub fn close(&mut self, cause: CloseCause, out: &mut [u8], now: u64) -> (usize, Action) {
        if !matches!(self.phase, Phase::Open { .. }) {
            return (0, Action::None);
        }
        self.close_started = now;
        match cause {
            CloseCause::BackendFin | CloseCause::SelfResponse => {
                let mut bufs = Buffers { rx: &mut self.rx, tx: &mut self.tx, out };
                let n = self.session.close(&mut bufs);
                self.wipe_buffers();
                self.abort_backend();
                self.phase = Phase::Draining { linger: true };
                (n, Action::None)
            }
            CloseCause::BackendRst | CloseCause::ClientClosed | CloseCause::Error => (0, self.abort()),
        }
    }

    /// The send buffer has drained (close_notify or the alert acknowledged).
    pub fn drained(&mut self, now: u64) -> Action {
        match self.phase {
            Phase::Draining { linger: true } => {
                self.phase = Phase::Lingering { until: now.saturating_add(CLOSE_LINGER_NS) };
                Action::None
            }
            Phase::Draining { linger: false } => self.abort(),
            _ => Action::None,
        }
    }

    /// An inbound record or FIN while lingering: not decrypted, abort.
    pub fn inbound(&mut self) -> Action {
        match self.phase {
            Phase::Lingering { .. } => self.abort(),
            _ => Action::None,
        }
    }

    /// One poll pass after an abort, with whether `endpoint`'s RST was
    /// dispatched in it. The backend's passes count from its own abort,
    /// which may come before the client's (a clean close drains first).
    /// Release once every aborted socket's RST went out or used up its
    /// passes.
    pub fn abort_pass(&mut self, endpoint: Endpoint, dispatched: bool) -> Action {
        if endpoint == Endpoint::Backend {
            self.backend_rst.pass(dispatched);
        }
        let Phase::Aborting { mut client } = self.phase else { return Action::None };
        if endpoint == Endpoint::Client {
            client.pass(dispatched);
        }
        if client.pending || self.backend_rst.pending {
            self.phase = Phase::Aborting { client };
            Action::None
        } else {
            self.reset();
            Action::Release
        }
    }

    /// The aborted backend socket's RST is still awaited: until it is not,
    /// the PD keeps the socket in its set and its storage unreleased (the
    /// same C8 order as the client socket's, on the inside interface).
    pub fn backend_rst_pending(&self) -> bool {
        self.backend_rst.pending
    }

    /// The timers at `now`. A fired timeout wipes the slot and aborts it
    /// (the timeout is returned for the audit); the linger's end aborts
    /// without one.
    pub fn tick(&mut self, now: u64) -> (Action, Option<Timeout>) {
        let since = |t: u64| now.saturating_sub(t);
        let fired = match self.phase {
            Phase::Free | Phase::Aborting { .. } => return (Action::None, None),
            _ if since(self.accepted) >= LIFETIME_NS => Some(Timeout::Lifetime),
            Phase::Open { stage: Stage::Handshake, since: t } if since(t) >= HANDSHAKE_TIMEOUT_NS => Some(Timeout::Handshake),
            Phase::Open { stage: Stage::Head, since: t } if since(t) >= HEAD_TIMEOUT_NS => Some(Timeout::Head),
            Phase::Open { stage: Stage::BackendConnect, since: t } if since(t) >= BACKEND_CONNECT_TIMEOUT_NS => {
                Some(Timeout::BackendConnect)
            }
            Phase::Open { stage: Stage::Streaming, .. } if since(self.last_activity) >= IDLE_TIMEOUT_NS => Some(Timeout::Idle),
            // The whole close is bounded by the idle timeout (F-N4).
            Phase::Draining { .. } | Phase::Lingering { .. } if since(self.close_started) >= IDLE_TIMEOUT_NS => {
                Some(Timeout::Idle)
            }
            Phase::Lingering { until } if now >= until => return (self.abort(), None),
            _ => None,
        };
        match fired {
            Some(t) => (self.abort(), Some(t)),
            None => (Action::None, None),
        }
    }

    fn abort(&mut self) -> Action {
        self.abort_backend();
        let mut bufs = Buffers { rx: &mut self.rx, tx: &mut self.tx, out: &mut [] };
        self.session.wipe(&mut bufs);
        self.wipe_buffers();
        self.phase = Phase::Aborting { client: RstWait::new(true) };
        Action::Abort
    }

    /// The backend socket, if one is open, is to be aborted now; its RST
    /// is awaited from here.
    fn abort_backend(&mut self) {
        if self.backend_open {
            self.backend_open = false;
            self.backend_rst = RstWait::new(true);
        }
    }

    /// Free, as [`Slot::new`] makes one, in place: the PD's slots are static
    /// and too large to rebuild on its stack.
    fn reset(&mut self) {
        self.phase = Phase::Free;
        self.source = [0; 4];
        self.accepted = 0;
        self.last_activity = 0;
        self.close_started = 0;
        self.backend_rst = RstWait::new(false);
        self.backend_open = false;
        self.session.reset();
        self.wipe_buffers();
    }

    /// Every plaintext buffer, and the proxy's places in them.
    fn wipe_buffers(&mut self) {
        wipe(&mut self.rx);
        wipe(&mut self.tx);
        wipe(&mut self.head);
        wipe(&mut self.rewrite);
        self.head_len = 0;
        self.body_left = 0;
        self.pending_rewrite = Span::EMPTY;
        self.pending_rx = Span::EMPTY;
    }

    /// Keys, secrets and every buffer zero (M6 plan C8, T-N15).
    #[cfg(test)]
    pub(crate) fn is_zeroized(&self) -> bool {
        self.session.is_zeroized()
            && [&self.rx[..], &self.tx[..], &self.head[..], &self.rewrite[..]].iter().all(|b| b.iter().all(|&x| x == 0))
    }
}

/// Every slot, with admission.
pub struct Table {
    pub slots: [Slot; MAX_CONNS],
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Self { slots: core::array::from_fn(|_| Slot::new()) }
    }

    /// A slot for a new connection from `source`: at most
    /// [`MAX_PER_SOURCE`] per source (slots still closing count), at most
    /// [`MAX_CONNS`] in all.
    pub fn admit(&mut self, source: [u8; 4], now: u64) -> Result<usize, AdmitRefusal> {
        let held = self.slots.iter().filter(|s| !s.is_free() && s.source == source).count();
        if held >= MAX_PER_SOURCE {
            return Err(AdmitRefusal::PerSource);
        }
        let (i, slot) = self.slots.iter_mut().enumerate().find(|(_, s)| s.is_free()).ok_or(AdmitRefusal::Full)?;
        slot.open(source, now);
        Ok(i)
    }

    /// A free slot taken straight into the abort sequence, for a connection
    /// refused at admission: it holds no session and no source (it counts
    /// toward no cap), only the client socket's RST to await, so the
    /// refused socket is released like every other aborted one (M6 plan
    /// C8). None when every slot is taken.
    pub fn refuse(&mut self) -> Option<usize> {
        let (i, slot) = self.slots.iter_mut().enumerate().find(|(_, s)| s.is_free())?;
        slot.reset();
        slot.phase = Phase::Aborting { client: RstWait::new(true) };
        Some(i)
    }
}

/// The static per-connection state the PD holds (C10, F18), checked
/// against `TLS_STATE_MAX` there with the socket buffers added.
pub const SLOT_BUFFERS_LEN: usize = RX_BUF_LEN + TX_BUF_LEN + HEAD_BUF_LEN + REWRITE_BUF_LEN;
