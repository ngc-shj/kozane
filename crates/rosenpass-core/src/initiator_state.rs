//! The initiator's handshake state core (M9 plan C7): the phase, the session
//! id it awaits, and the retransmission counter and deadlines. No
//! cryptography, so Kani can check it without compiling libcrux.
//!
//! Every transition is a total function from a state to a new state or a
//! `StateError`; the caller assigns the new state only on `Ok`, so an error
//! leaves the state unchanged (I7.3). Time is the caller's monotonic `now`
//! in ns. Timing follows upstream rosenpass `9e72f1eb`
//! (`rosenpass/src/protocol/constants.rs` and `protocol.rs`).

use rosenpass_wire::SID_LEN;

const NS_PER_MS: u64 = 1_000_000;

/// The first retransmission delay: upstream `RETRANSMIT_DELAY_BEGIN` = 0.5 s
/// (`rosenpass/src/protocol/constants.rs:53`).
pub const RETRANSMIT_DELAY_BEGIN_NS: u64 = 500 * NS_PER_MS;
/// The factor the delay grows by per retransmission: upstream
/// `RETRANSMIT_DELAY_GROWTH` = 2.0 (`constants.rs:50`).
pub const RETRANSMIT_DELAY_GROWTH: u64 = 2;
/// The largest delay: upstream `RETRANSMIT_DELAY_END` = 10.0 s
/// (`constants.rs:56`).
pub const RETRANSMIT_DELAY_END_NS: u64 = 10_000 * NS_PER_MS;
/// The jitter factor: upstream `RETRANSMIT_DELAY_JITTER` = 0.5
/// (`constants.rs:60`), as `RETRANSMIT_DELAY_JITTER_NUM / _DEN`.
pub const RETRANSMIT_DELAY_JITTER_NUM: u64 = 1;
pub const RETRANSMIT_DELAY_JITTER_DEN: u64 = 2;
/// A handshake dies this long after it started: upstream `REJECT_AFTER_TIME`
/// = 180.0 s (`constants.rs:28`), the `IniHsPtr` lifetime (`protocol.rs:1662`).
pub const REJECT_AFTER_TIME_NS: u64 = 180_000 * NS_PER_MS;
/// The initiator rekeys this long after a handshake completed: upstream
/// `REKEY_AFTER_TIME_INITIATOR` = 130.0 s (`constants.rs:19`).
pub const REKEY_AFTER_TIME_INITIATOR_NS: u64 = 130_000 * NS_PER_MS;

/// Jitter draws per stored message, one per retransmission (cyclically).
/// Upstream draws a fresh `rand::random::<f64>()` at each retransmission
/// (`protocol.rs:3147`); a sans-IO `tick` has no RNG, so the draws are
/// taken when the message is stored.
pub const JITTER_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    SentInitHello,
    SentInitConf,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// The message does not belong in this phase.
    UnexpectedMessage,
    /// The message names another session.
    UnknownSession,
    /// The handshake is past `REJECT_AFTER_TIME_NS`.
    Expired,
    /// A deadline would not fit in a u64.
    Overflow,
}

/// What a `tick` asks of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    Nothing,
    /// Send the stored message again.
    Retransmit,
    /// The handshake died; the state is `Idle` again.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitiatorState {
    phase: Phase,
    sidi: [u8; SID_LEN],
    /// When the handshake started (upstream `InitiatorHandshake::created_at`,
    /// kept across the RespHello).
    created_at: u64,
    retry_at: u64,
    /// Upstream `tx_count`: retransmissions registered for the stored message.
    tx_count: u32,
    jitter: [u8; JITTER_LEN],
    established_at: u64,
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Upstream `register_retransmission` (`protocol.rs:3140-3147`):
/// `BEGIN · GROWTH^min(log_GROWTH(END/BEGIN), n) · JITTER · (1 + u)` with
/// u ∈ [0, 1). The capped power is `min(BEGIN · GROWTH^n, END)`; u is
/// `jitter / 256`, so the factor `JITTER · (1 + u)` is
/// `NUM · (256 + jitter) / (DEN · 256)`, `(256 + jitter) / 512` at 0.5.
pub fn retransmit_delay(n: u32, jitter: u8) -> Option<u64> {
    let base = RETRANSMIT_DELAY_GROWTH
        .checked_pow(n)
        .and_then(|g| RETRANSMIT_DELAY_BEGIN_NS.checked_mul(g))
        .map_or(RETRANSMIT_DELAY_END_NS, |d| d.min(RETRANSMIT_DELAY_END_NS));
    base.checked_mul(RETRANSMIT_DELAY_JITTER_NUM)?
        .checked_mul(u64::from(jitter).checked_add(256)?)?
        .checked_div(RETRANSMIT_DELAY_JITTER_DEN.checked_mul(256)?)
}

impl InitiatorState {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            sidi: [0; SID_LEN],
            created_at: 0,
            retry_at: 0,
            tx_count: 0,
            jitter: [0; JITTER_LEN],
            established_at: 0,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The session id of the handshake in flight or last completed.
    pub fn sidi(&self) -> [u8; SID_LEN] {
        self.sidi
    }

    fn in_flight(&self) -> bool {
        matches!(self.phase, Phase::SentInitHello | Phase::SentInitConf)
    }

    fn expires_at(&self) -> u64 {
        self.created_at.saturating_add(REJECT_AFTER_TIME_NS)
    }

    fn live(&self, now: u64) -> bool {
        now < self.expires_at()
    }

    /// When `tick` next has something to do: the retransmission or the
    /// handshake's death, whichever is first. None outside a handshake.
    pub fn deadline(&self) -> Option<u64> {
        self.in_flight().then(|| self.retry_at.min(self.expires_at()))
    }

    /// When the established session is due for a new handshake.
    pub fn rekey_at(&self) -> Option<u64> {
        (self.phase == Phase::Established).then(|| self.established_at.saturating_add(REKEY_AFTER_TIME_INITIATOR_NS))
    }

    /// Upstream `register_retransmission`: the next retry and the count.
    fn registered(mut self, now: u64) -> Result<Self, StateError> {
        let slot = usize::try_from(self.tx_count).ok().and_then(|n| n.checked_rem(JITTER_LEN));
        let jitter = slot.and_then(|i| self.jitter.get(i)).copied().ok_or(StateError::Overflow)?;
        let delay = retransmit_delay(self.tx_count, jitter).ok_or(StateError::Overflow)?;
        self.retry_at = now.checked_add(delay).ok_or(StateError::Overflow)?;
        self.tx_count = self.tx_count.saturating_add(1);
        Ok(self)
    }

    /// Upstream `store_msg_for_retransmission` (`protocol.rs:3093-3102`).
    fn stored(mut self, now: u64, jitter: [u8; JITTER_LEN]) -> Result<Self, StateError> {
        self.jitter = jitter;
        self.tx_count = 0;
        self.registered(now)
    }

    /// The handshake in flight in `phase` for `sid`, still alive.
    fn awaiting(&self, now: u64, sid: [u8; SID_LEN], phases: &[Phase]) -> Result<(), StateError> {
        if !phases.contains(&self.phase) {
            return Err(StateError::UnexpectedMessage);
        }
        if sid != self.sidi {
            return Err(StateError::UnknownSession);
        }
        if !self.live(now) {
            return Err(StateError::Expired);
        }
        Ok(())
    }

    /// An InitHello for `sidi` was sent. From any phase: a new handshake
    /// replaces the one in flight, as upstream's `handle_initiation` does.
    pub fn start(&self, now: u64, sidi: [u8; SID_LEN], jitter: [u8; JITTER_LEN]) -> Result<Self, StateError> {
        let next = Self { phase: Phase::SentInitHello, sidi, created_at: now, ..Self::new() };
        next.stored(now, jitter)
    }

    /// A RespHello for our session authenticated; the InitConf was sent.
    pub fn resp_hello(&self, now: u64, sid: [u8; SID_LEN], jitter: [u8; JITTER_LEN]) -> Result<Self, StateError> {
        self.awaiting(now, sid, &[Phase::SentInitHello])?;
        Self { phase: Phase::SentInitConf, ..*self }.stored(now, jitter)
    }

    /// The EmptyData for our session authenticated: retransmission stops
    /// (upstream `handle_resp_conf` takes the handshake, `protocol.rs:4253`).
    pub fn empty_data(&self, now: u64, sid: [u8; SID_LEN]) -> Result<Self, StateError> {
        self.awaiting(now, sid, &[Phase::SentInitConf])?;
        Ok(Self { phase: Phase::Established, sidi: self.sidi, established_at: now, ..Self::new() })
    }

    /// A CookieReply for our session opened: retransmit at once (upstream
    /// `register_immediate_retransmission`, `protocol.rs:3155-3163`).
    pub fn cookie_reply(&self, now: u64, sid: [u8; SID_LEN]) -> Result<Self, StateError> {
        self.awaiting(now, sid, &[Phase::SentInitHello, Phase::SentInitConf])?;
        Ok(Self { retry_at: now, tx_count: self.tx_count.saturating_add(1), ..*self })
    }

    /// Upstream's `PeerPtr` and `IniHsPtr` polls (`protocol.rs:3022`,
    /// `:3047-3055`): a dead handshake is dropped silently, a due one is
    /// retransmitted and the next retry registered.
    pub fn tick(&self, now: u64) -> Result<(Self, Tick), StateError> {
        if !self.in_flight() {
            return Ok((*self, Tick::Nothing));
        }
        if !self.live(now) {
            return Ok((Self::new(), Tick::Expired));
        }
        if now < self.retry_at {
            return Ok((*self, Tick::Nothing));
        }
        Ok((self.registered(now)?, Tick::Retransmit))
    }
}

#[cfg(kani)]
#[path = "proofs.rs"]
mod proofs;
