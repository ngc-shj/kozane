//! The `tpm` PD's core (M5 plan C9): which client command reaches the
//! device. `key`, `pqkey`, `tlskey` (M6 plan C12) and `auditkey` (M8 plan
//! C10) are separate L2 domains that share `tpm` as a callee, so this is
//! where L2 between them is enforced (S11).
//!
//! - Allowlist by command code: CreatePrimary, StartAuthSession, PolicyPCR,
//!   PolicyAuthValue, Import, Load, Unseal, FlushContext, PCR_Read.
//!   Anything else, PCR_Extend included, is refused before any device write.
//!   One per-client row (M8 plan C3, I3.2): ReadClock, for `auditkey`
//!   alone, once, before its Done; for every other client it is off the
//!   list like any other command.
//! - Handle ownership: the handles CreatePrimary, StartAuthSession and Load
//!   return belong to the client that asked. PolicyPCR and PolicyAuthValue
//!   need an owned session, Unseal an owned object (and every session in
//!   its auth area owned or the password session), Import and Load an owned
//!   parent, FlushContext an owned handle; a successful flush drops the
//!   entry, so a reused handle number belongs to its new owner (S16, S19).
//! - One flow per client per boot: CreatePrimary, StartAuthSession, Load,
//!   Unseal and ReadClock at most once each. A client that sent Done or Failed is
//!   refused everything.
//! - One flow at a time (swtpm, like small TPMs, holds three transient
//!   objects; two flows need four): a Fresh client is told Busy while any
//!   other client is Unsealing, so a started flow always runs to its end.
//!   Busy is decided after every validity and ownership refusal (a Fresh
//!   client owns nothing, so NotOwned stays what it gets on another's
//!   handle) and before the once-bits and the state change; it changes
//!   nothing, and the PD answers it RSP_BUSY, which `tpm2::boot` retries.
//! - The cap: once every client is Done or Failed, `cap` yields the one
//!   PCR_Extend of PCR 8 the core itself issues; from then on everything is
//!   refused (the clients already are). `run_cap` runs it on the device,
//!   retried at most `CAP_ATTEMPTS` times, and keeps the verdict (confirmed
//!   by the TPM's own response, or failed) apart from `capped`, which is set
//!   whatever the device answers.
//! - The cap barrier (post-M6 plan P3): a Done client asks `cap_status`
//!   before it releases its key: Pending until the cap has run, then its
//!   verdict. Every other client is refused, so a domain whose flow failed
//!   holds no key to release anyway.
//! - The `policy` client (M8 plan C3) is not a raw client: it sends no TPM
//!   command. The gate runs its four operations itself on the device
//!   ([`PolicyTransport`]): State (NV_ReadPublic of both indices, each Name
//!   compared with the expected one, NV_Read of both, PCR_Read of PCR 9),
//!   at most one Advance (the same reads, NV_Increment of the counter only
//!   if the version is the one the client expects, the reads again), then
//!   Done or Failed. They use no handle slot and no flow, so they
//!   interleave with the raw flows. Each operation is spent when it starts,
//!   so a failed State allows no Advance and no Advance runs twice: at most
//!   one increment per boot.
//! - With a `policy` PD in the system (`policy_present`, M8 deviation D-6)
//!   the cap also waits for its Done or Failed; without one, every policy
//!   operation is refused and the cap is exactly the M7 one.
//!
//! The device's responses are A7's: a handle that is not of the expected
//! kind, or that is already recorded, fails the client instead of being
//! recorded.

use crate::{
    CC_CLEAR, CC_CREATE_PRIMARY, CC_FLUSH_CONTEXT, CC_HIERARCHY_CHANGE_AUTH, CC_IMPORT, CC_LOAD, CC_NV_DEFINE_SPACE,
    CC_NV_INCREMENT, CC_NV_READ, CC_NV_READ_PUBLIC, CC_NV_UNDEFINE_SPACE, CC_NV_UNDEFINE_SPACE_SPECIAL, CC_NV_WRITE,
    CC_NV_WRITE_LOCK, CC_PCR_EXTEND, CC_PCR_READ, CC_POLICY_AUTH_VALUE, CC_POLICY_PCR, CC_READ_CLOCK, CC_START_AUTH_SESSION,
    CC_UNSEAL,
    DIGEST_LEN, IPC_MSG_BYTES, NAME_LEN, NV_INCREMENT_CMD_LEN, NV_POLICY_BASE, NV_POLICY_CTR, NV_READ_CMD_LEN,
    NV_READ_PUBLIC_CMD_LEN, PCR_EXTEND_CMD_LEN, PCR_READ_CMD_LEN, RH_NULL, RH_OWNER, RS_PW, Reader, ST_NO_SESSIONS,
    ST_SESSIONS, nv_increment, nv_read, nv_read_public, parse_nv_increment, parse_nv_read, parse_nv_read_public,
    parse_pcr_extend, parse_slot_pcr_read, slot_pcr_read,
};

/// `key`, `pqkey`, `tlskey` and `auditkey`, in the `tpm` PD's client order.
pub const CLIENTS: usize = 4;
/// `auditkey`'s client index (M8 plan C3, C10): the fourth raw client.
pub const AUDITKEY: usize = 3;
const _: () = assert!(AUDITKEY < CLIENTS);
/// Each client owns at most a primary, a session and an object.
const SLOTS: usize = CLIENTS * 3;
/// The most sessions one auth area may carry (TPM 2.0 Part 1).
const MAX_SESSIONS: usize = 3;

/// What the cap extends PCR 8 with: a fixed value that no measurement
/// (a sha256 output) is expected to equal.
pub const CAP_DIGEST: [u8; DIGEST_LEN] = [0xFF; DIGEST_LEN];

/// Tries of the cap's PCR_Extend before its verdict is Failed.
pub const CAP_ATTEMPTS: usize = 3;
/// One cap attempt's overall deadline: every TIS wait inside it (locality,
/// commandReady, each burst, Expect, execution, valid) is bounded by what is
/// left of it (post-M6 plan P3, round 3 R3-3). `tpm2::boot` sizes the cap
/// barrier's timeout from it and `CAP_ATTEMPTS`.
pub const CAP_ATTEMPT_DEADLINE_NS: u64 = 30_000_000_000;

/// The device the cap's PCR_Extend goes to (the `tpm` PD's TIS).
pub trait CapTransport {
    /// Sends `cmd` and returns the device's response, or None if the
    /// device did not answer within `budget_ns`, the attempt's overall
    /// deadline.
    fn attempt(&mut self, cmd: &[u8], budget_ns: u64) -> Option<&[u8]>;
}

/// The cap's outcome once it has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapVerdict {
    /// The TPM's own response confirmed the extend.
    Confirmed,
    /// No attempt was confirmed: PCR 8 may still hold its sealed value.
    Failed,
}

/// What `cap_status` answers a Done client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapStatus {
    /// The cap has not run: some client has not finished.
    Pending,
    Confirmed,
    Failed,
}

/// Whether one attempt's outcome confirms the extend: a response came, it
/// is PCR_Extend's well-formed success. A transport failure, a non-zero
/// response code and a short or malformed response are failures alike.
pub fn extend_confirmed(outcome: Option<&[u8]>) -> bool {
    outcome.is_some_and(|r| parse_pcr_extend(r).is_ok())
}

/// The allowlist (C9), in flow order.
pub const ALLOWED: [u32; 9] = [
    CC_CREATE_PRIMARY,
    CC_START_AUTH_SESSION,
    CC_POLICY_PCR,
    CC_POLICY_AUTH_VALUE,
    CC_IMPORT,
    CC_LOAD,
    CC_UNSEAL,
    CC_FLUSH_CONTEXT,
    CC_PCR_READ,
];

/// Commands no raw client may send (M8 plan C3, I3.2), each off
/// `ALLOWED`: the device never defines, writes, deletes or clears, and the
/// policy indices are read and incremented by the gate alone.
pub const REFUSED: [u32; 10] = [
    CC_NV_INCREMENT,
    CC_NV_READ,
    CC_NV_UNDEFINE_SPACE,
    CC_NV_UNDEFINE_SPACE_SPECIAL,
    CC_NV_WRITE,
    CC_NV_WRITE_LOCK,
    CC_NV_DEFINE_SPACE,
    CC_CLEAR,
    CC_HIERARCHY_CHANGE_AUTH,
    CC_PCR_EXTEND,
];

/// The per-client rows (M8 plan C3, I3.2): a command off `ALLOWED` that
/// one client alone may send, once, before its Done. ReadClock gives
/// `auditkey` the resetCount and restartCount its checkpoints bind (C10).
pub const CLIENT_ONLY: [(u32, usize); 1] = [(CC_READ_CLOCK, AUDITKEY)];

/// Whether `client` may send command code `cc` at all: `ALLOWED`, or a
/// `CLIENT_ONLY` row naming it.
pub fn allowed_for(client: usize, cc: u32) -> bool {
    ALLOWED.contains(&cc) || CLIENT_ONLY.iter().any(|(c, owner)| *c == cc && *owner == client)
}

/// Every command the policy operations send, all on the two policy indices
/// or PCR 9; NV_Increment on the counter only.
pub const POLICY_COMMANDS: [u32; 4] = [CC_NV_READ_PUBLIC, CC_NV_READ, CC_NV_INCREMENT, CC_PCR_READ];

const fn listed(list: &[u32], cc: u32) -> bool {
    match list {
        [] => false,
        [first, rest @ ..] => *first == cc || listed(rest, cc),
    }
}

const fn disjoint(refused: &[u32], allowed: &[u32]) -> bool {
    match refused {
        [] => true,
        [first, rest @ ..] => !listed(allowed, *first) && disjoint(rest, allowed),
    }
}

const _: () = assert!(disjoint(&REFUSED, &ALLOWED));
// The per-client row widens nothing the refused set names, and is not on
// the shared list (or it would be every client's).
const _: () = assert!(!listed(&REFUSED, CC_READ_CLOCK) && !listed(&ALLOWED, CC_READ_CLOCK));
// `read_version` builds NV_ReadPublic and NV_Read in one buffer.
const _: () = assert!(NV_READ_PUBLIC_CMD_LEN <= NV_READ_CMD_LEN);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Fresh,
    Unsealing,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownClient,
    /// The client sent Done or Failed.
    Finished,
    /// PCR 8 is capped.
    Capped,
    /// Not a well-formed command of the flow (length, tag, handle area or
    /// auth area).
    Malformed,
    /// The command code is not on the allowlist, nor on a per-client row
    /// naming this client.
    NotAllowed,
    /// A second CreatePrimary, StartAuthSession, Load, Unseal or ReadClock.
    Repeated,
    /// A handle the client does not own, or not of the kind the command needs.
    NotOwned,
    /// CreatePrimary outside the owner hierarchy, or a bound session.
    Hierarchy,
    /// Another client's flow is under way and this one has not started:
    /// ask again later. Nothing was recorded.
    Busy,
    /// The cap status, asked by a client that has not sent Done.
    NotDone,
}

/// The device the policy operations go to (the `tpm` PD's TIS).
pub trait PolicyTransport {
    /// Sends `cmd` and returns the device's response, or None if the
    /// device did not answer.
    fn transact(&mut self, cmd: &[u8]) -> Option<&[u8]>;
}

/// Where the `policy` client is in its one sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPhase {
    /// Nothing asked yet: State is next.
    Fresh,
    /// State answered: Advance, Done or Failed.
    Stated,
    /// A State that failed, or an Advance (whatever its outcome): Done or
    /// Failed only.
    Spent,
    /// Done or Failed: nothing more.
    Finished,
}

/// Why a policy operation was refused. Every refusal of State or Advance
/// is final for the boot: the operation is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// The system has no `policy` PD (`policy_present` false).
    Absent,
    /// PCR 8 is capped.
    Capped,
    /// The client sent Done or Failed.
    Finished,
    /// Out of sequence: a second State, an Advance without a successful
    /// State, or a second Advance.
    Order,
    /// An index's Name is not the expected one, or no Name is expected
    /// (all zero: the configuration has no `[policy]`).
    Name,
    /// `counter - base` is above `u32::MAX`.
    Range,
    /// Advance's expected version is not the current one: no increment.
    Stale,
    /// The device did not answer, or answered an error or a malformed
    /// response.
    Device,
}

/// What State answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyState {
    /// The logical version, `counter - base`.
    pub current: u32,
    pub pcr9: [u8; DIGEST_LEN],
}

/// One command to the device and its response, parsed by `parse` into an
/// owned value; any failure is `Device`.
fn exchange<T>(
    device: &mut impl PolicyTransport,
    cmd: Option<usize>,
    buf: &[u8],
    parse: impl FnOnce(&[u8]) -> Result<T, crate::RspError>,
) -> Result<T, PolicyRefusal> {
    let cmd = buf.get(..cmd.ok_or(PolicyRefusal::Device)?).ok_or(PolicyRefusal::Device)?;
    parse(device.transact(cmd).ok_or(PolicyRefusal::Device)?).map_err(|_| PolicyRefusal::Device)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Primary,
    Session,
    Object,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    handle: u32,
    client: usize,
    kind: Kind,
}

/// A forwarded command, handed back with the device's response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forward {
    client: usize,
    cc: u32,
    /// FlushContext's handle.
    flushed: u32,
}

impl Forward {
    pub fn client(&self) -> usize {
        self.client
    }

    pub fn command_code(&self) -> u32 {
        self.cc
    }
}

/// Bits of `Gate::once`.
const ONCE_PRIMARY: u8 = 1;
const ONCE_SESSION: u8 = 2;
const ONCE_LOAD: u8 = 4;
const ONCE_UNSEAL: u8 = 8;
const ONCE_CLOCK: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    states: [State; CLIENTS],
    once: [u8; CLIENTS],
    slots: [Option<Entry>; SLOTS],
    capped: bool,
    /// The cap's verdict, set by `run_cap` alone.
    verdict: Option<CapVerdict>,
    /// The system has a `policy` PD: its operations are served and the cap
    /// waits for its Done or Failed (D-6).
    policy_present: bool,
    policy: PolicyPhase,
    /// The expected Names of `NV_POLICY_CTR` and `NV_POLICY_BASE`.
    names: [[u8; NAME_LEN]; 2],
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// TPM_HT_TRANSIENT and TPM_HT_POLICY_SESSION.
fn kind_matches(kind: Kind, handle: u32) -> bool {
    let ht = handle >> 24;
    match kind {
        Kind::Primary | Kind::Object => ht == 0x80,
        Kind::Session => ht == 0x03,
    }
}

impl Gate {
    /// A gate without a `policy` client: the M7 gate.
    pub const fn new() -> Self {
        Self::with_policy(false, [0; NAME_LEN], [0; NAME_LEN])
    }

    /// A gate that serves the `policy` client iff `present`, expecting the
    /// counter's and the base's Names `ctr_name` and `base_name`.
    pub const fn with_policy(present: bool, ctr_name: [u8; NAME_LEN], base_name: [u8; NAME_LEN]) -> Self {
        Self {
            states: [State::Fresh; CLIENTS],
            once: [0; CLIENTS],
            slots: [None; SLOTS],
            capped: false,
            verdict: None,
            policy_present: present,
            policy: PolicyPhase::Fresh,
            names: [ctr_name, base_name],
        }
    }

    pub fn state(&self, client: usize) -> Option<State> {
        self.states.get(client).copied()
    }

    pub fn is_capped(&self) -> bool {
        self.capped
    }

    pub fn policy_phase(&self) -> PolicyPhase {
        self.policy
    }

    /// What the cap waits for besides the raw clients: the `policy`
    /// client's Done or Failed, if the system has one.
    fn policy_finished(&self) -> bool {
        !self.policy_present || self.policy == PolicyPhase::Finished
    }

    fn owns(&self, client: usize, handle: u32, kind: Option<Kind>) -> bool {
        self.slots.iter().flatten().any(|e| e.client == client && e.handle == handle && kind.is_none_or(|k| e.kind == k))
    }

    fn require(&self, client: usize, handle: u32, kind: Option<Kind>) -> Result<(), Refusal> {
        if self.owns(client, handle, kind) { Ok(()) } else { Err(Refusal::NotOwned) }
    }

    /// Every session in the auth area is the password session or a session
    /// the client owns; the area is consumed exactly.
    fn check_auth(&self, client: usize, r: &mut Reader<'_>) -> Result<(), Refusal> {
        let len = usize::try_from(r.u32().map_err(|_| Refusal::Malformed)?).map_err(|_| Refusal::Malformed)?;
        let mut area = Reader::new(r.take(len).map_err(|_| Refusal::Malformed)?);
        let mut n = 0usize;
        while area.remaining() > 0 {
            n = n.checked_add(1).ok_or(Refusal::Malformed)?;
            if n > MAX_SESSIONS {
                return Err(Refusal::Malformed);
            }
            let handle = area.u32().map_err(|_| Refusal::Malformed)?;
            area.tpm2b(IPC_MSG_BYTES).map_err(|_| Refusal::Malformed)?;
            area.u8().map_err(|_| Refusal::Malformed)?;
            area.tpm2b(IPC_MSG_BYTES).map_err(|_| Refusal::Malformed)?;
            if handle != RS_PW {
                self.require(client, handle, Some(Kind::Session))?;
            }
        }
        if n == 0 { Err(Refusal::Malformed) } else { Ok(()) }
    }

    fn once(&mut self, client: usize, bit: u8) -> Result<(), Refusal> {
        let once = self.once.get_mut(client).ok_or(Refusal::UnknownClient)?;
        if *once & bit != 0 {
            return Err(Refusal::Repeated);
        }
        *once |= bit;
        Ok(())
    }

    /// Decides whether `client`'s command reaches the device. Only an `Ok`
    /// is written to the TPM; the `Forward` comes back with its response.
    pub fn command(&mut self, client: usize, cmd: &[u8]) -> Result<Forward, Refusal> {
        let state = self.state(client).ok_or(Refusal::UnknownClient)?;
        if self.capped {
            return Err(Refusal::Capped);
        }
        if matches!(state, State::Done | State::Failed) {
            return Err(Refusal::Finished);
        }
        if cmd.len() > IPC_MSG_BYTES {
            return Err(Refusal::Malformed);
        }
        let mut r = Reader::new(cmd);
        let tag = r.u16().map_err(|_| Refusal::Malformed)?;
        let size = r.u32().map_err(|_| Refusal::Malformed)?;
        let cc = r.u32().map_err(|_| Refusal::Malformed)?;
        if !allowed_for(client, cc) {
            return Err(Refusal::NotAllowed);
        }
        if usize::try_from(size).ok() != Some(cmd.len()) {
            return Err(Refusal::Malformed);
        }
        let sessions = cc == CC_CREATE_PRIMARY || cc == CC_IMPORT || cc == CC_LOAD || cc == CC_UNSEAL;
        if tag != if sessions { ST_SESSIONS } else { ST_NO_SESSIONS } {
            return Err(Refusal::Malformed);
        }
        let mut flushed = 0;
        let mut handle = || r.u32().map_err(|_| Refusal::Malformed);
        let once = match cc {
            CC_CREATE_PRIMARY => {
                if handle()? != RH_OWNER {
                    return Err(Refusal::Hierarchy);
                }
                Some(ONCE_PRIMARY)
            }
            CC_START_AUTH_SESSION => {
                self.require(client, handle()?, Some(Kind::Primary))?;
                if handle()? != RH_NULL {
                    return Err(Refusal::Hierarchy);
                }
                Some(ONCE_SESSION)
            }
            CC_POLICY_PCR | CC_POLICY_AUTH_VALUE => {
                self.require(client, handle()?, Some(Kind::Session))?;
                None
            }
            CC_IMPORT => {
                self.require(client, handle()?, Some(Kind::Primary))?;
                None
            }
            CC_LOAD => {
                self.require(client, handle()?, Some(Kind::Primary))?;
                Some(ONCE_LOAD)
            }
            CC_UNSEAL => {
                self.require(client, handle()?, Some(Kind::Object))?;
                Some(ONCE_UNSEAL)
            }
            CC_FLUSH_CONTEXT => {
                flushed = handle()?;
                self.require(client, flushed, None)?;
                if r.remaining() != 0 {
                    return Err(Refusal::Malformed);
                }
                None
            }
            // `auditkey`'s row: no handles, no parameters.
            CC_READ_CLOCK => {
                if r.remaining() != 0 {
                    return Err(Refusal::Malformed);
                }
                Some(ONCE_CLOCK)
            }
            _ => None, // PCR_Read: no handles
        };
        if sessions {
            self.check_auth(client, &mut r)?;
        }
        if state == State::Fresh && self.states.iter().enumerate().any(|(c, s)| c != client && *s == State::Unsealing) {
            return Err(Refusal::Busy);
        }
        if let Some(bit) = once {
            self.once(client, bit)?;
        }
        if let Some(s) = self.states.get_mut(client) {
            *s = State::Unsealing;
        }
        Ok(Forward { client, cc, flushed })
    }

    fn fail(&mut self, client: usize) {
        if let Some(s) = self.states.get_mut(client) {
            *s = State::Failed;
        }
    }

    fn record(&mut self, client: usize, handle: u32, kind: Kind) {
        let taken = self.slots.iter().flatten().any(|e| e.handle == handle);
        let free = self.slots.iter_mut().find(|s| s.is_none());
        match free {
            Some(slot) if !taken && kind_matches(kind, handle) => *slot = Some(Entry { handle, client, kind }),
            _ => self.fail(client),
        }
    }

    /// Records what the device's response to `fwd` changes: the handle a
    /// successful CreatePrimary, StartAuthSession or Load returned, or the
    /// entry a successful FlushContext removed. The client parses the
    /// response itself; an error or malformed response changes nothing here.
    pub fn response(&mut self, fwd: Forward, rsp: &[u8]) {
        let mut r = Reader::new(rsp);
        let (Ok(_tag), Ok(size), Ok(rc)) = (r.u16(), r.u32(), r.u32()) else { return };
        if rc != 0 || usize::try_from(size).ok() != Some(rsp.len()) {
            return;
        }
        let kind = match fwd.cc {
            CC_CREATE_PRIMARY => Kind::Primary,
            CC_START_AUTH_SESSION => Kind::Session,
            CC_LOAD => Kind::Object,
            CC_FLUSH_CONTEXT => {
                if let Some(slot) =
                    self.slots.iter_mut().find(|s| s.is_some_and(|e| e.client == fwd.client && e.handle == fwd.flushed))
                {
                    *slot = None;
                }
                return;
            }
            _ => return,
        };
        match r.u32() {
            Ok(handle) => self.record(fwd.client, handle, kind),
            Err(_) => self.fail(fwd.client),
        }
    }

    /// The client's explicit Done (`ok`) or Failed, sent after its flushes.
    pub fn finish(&mut self, client: usize, ok: bool) -> Result<(), Refusal> {
        let s = self.states.get_mut(client).ok_or(Refusal::UnknownClient)?;
        if matches!(*s, State::Done | State::Failed) {
            return Err(Refusal::Finished);
        }
        *s = if ok { State::Done } else { State::Failed };
        Ok(())
    }

    /// Once every client is Done or Failed (the `policy` client too, if
    /// present): the cap's PCR_Extend, exactly once. The core is capped from here on, whatever the device answers.
    pub fn cap(&mut self, out: &mut [u8]) -> Option<usize> {
        let raw_finished = self.states.iter().all(|s| matches!(s, State::Done | State::Failed));
        if self.capped || !raw_finished || !self.policy_finished() {
            return None;
        }
        let len = crate::pcr_extend(out, &CAP_DIGEST)?;
        self.capped = true;
        Some(len)
    }

    /// The cap on `device`: once every client is Done or Failed, the one
    /// PCR_Extend, tried at most `CAP_ATTEMPTS` times, each attempt within
    /// `CAP_ATTEMPT_DEADLINE_NS`, until an attempt is confirmed. A retry
    /// after a lost response may extend PCR 8 twice, which moves it further
    /// from the sealed value (fail-closed, F4). None while the cap is not
    /// due (some client has not finished, or it already ran): no verdict,
    /// and the device is not called.
    pub fn run_cap(&mut self, device: &mut impl CapTransport) -> Option<CapVerdict> {
        let mut cmd = [0u8; PCR_EXTEND_CMD_LEN];
        let n = self.cap(&mut cmd)?;
        let cmd = cmd.get(..n).unwrap_or(&[]);
        let mut verdict = CapVerdict::Failed;
        for _ in 0..CAP_ATTEMPTS {
            if extend_confirmed(device.attempt(cmd, CAP_ATTEMPT_DEADLINE_NS)) {
                verdict = CapVerdict::Confirmed;
                break;
            }
        }
        self.verdict = Some(verdict);
        Some(verdict)
    }

    /// The cap barrier's answer to `client`, which must be Done: Pending
    /// until `run_cap` has given its verdict, then the verdict. Changes
    /// nothing. A gate capped by `cap` alone (no device) stays Pending, so
    /// its clients' barriers time out (fail-closed).
    pub fn cap_status(&self, client: usize) -> Result<CapStatus, Refusal> {
        if self.state(client).ok_or(Refusal::UnknownClient)? != State::Done {
            return Err(Refusal::NotDone);
        }
        Ok(match self.verdict {
            None => CapStatus::Pending,
            Some(CapVerdict::Confirmed) => CapStatus::Confirmed,
            Some(CapVerdict::Failed) => CapStatus::Failed,
        })
    }
    /// Whether a policy operation may start in `phase`.
    fn policy_open(&self, phase: PolicyPhase) -> Result<(), PolicyRefusal> {
        if !self.policy_present {
            return Err(PolicyRefusal::Absent);
        }
        if self.capped {
            return Err(PolicyRefusal::Capped);
        }
        if self.policy == PolicyPhase::Finished {
            return Err(PolicyRefusal::Finished);
        }
        if self.policy != phase {
            return Err(PolicyRefusal::Order);
        }
        Ok(())
    }

    /// The logical version on `device`: both Names checked first, then both
    /// values read. An all-zero expected Name is refused before the device
    /// is asked (fail-closed when the configuration names none).
    fn read_version(&self, device: &mut impl PolicyTransport) -> Result<u32, PolicyRefusal> {
        let mut buf = [0u8; NV_READ_CMD_LEN];
        for (index, name) in [NV_POLICY_CTR, NV_POLICY_BASE].into_iter().zip(self.names.iter()) {
            if name.iter().all(|b| *b == 0) {
                return Err(PolicyRefusal::Name);
            }
            let n = nv_read_public(&mut buf, index);
            let got = exchange(device, n, &buf, |r| parse_nv_read_public(r).map(|p| p.name == name.as_slice()))?;
            if !got {
                return Err(PolicyRefusal::Name);
            }
        }
        let n = nv_read(&mut buf, NV_POLICY_CTR);
        let counter = exchange(device, n, &buf, parse_nv_read)?;
        let n = nv_read(&mut buf, NV_POLICY_BASE);
        let base = exchange(device, n, &buf, parse_nv_read)?;
        u32::try_from(counter.wrapping_sub(base)).map_err(|_| PolicyRefusal::Range)
    }

    /// The policy client's State: the logical version and PCR 9. Spent
    /// whatever the device answers.
    pub fn policy_state(&mut self, device: &mut impl PolicyTransport) -> Result<PolicyState, PolicyRefusal> {
        self.policy_open(PolicyPhase::Fresh)?;
        self.policy = PolicyPhase::Spent;
        let current = self.read_version(device)?;
        let mut buf = [0u8; PCR_READ_CMD_LEN];
        let n = slot_pcr_read(&mut buf);
        let pcr9 = exchange(device, n, &buf, |r| parse_slot_pcr_read(r).copied())?;
        self.policy = PolicyPhase::Stated;
        Ok(PolicyState { current, pcr9 })
    }

    /// The policy client's Advance: after a successful State, once. The
    /// counter is incremented only if the version read now is `expected`;
    /// the answer is the version read after the increment, which the
    /// client compares with `expected + 1` itself.
    pub fn policy_advance(&mut self, expected: u32, device: &mut impl PolicyTransport) -> Result<u32, PolicyRefusal> {
        self.policy_open(PolicyPhase::Stated)?;
        self.policy = PolicyPhase::Spent;
        if self.read_version(device)? != expected {
            return Err(PolicyRefusal::Stale);
        }
        let mut buf = [0u8; NV_INCREMENT_CMD_LEN];
        let n = nv_increment(&mut buf, NV_POLICY_CTR);
        exchange(device, n, &buf, parse_nv_increment)?;
        self.read_version(device)
    }

    /// The policy client's Done or Failed, from any phase but Finished. The
    /// caller then runs the cap, which may now be due.
    pub fn policy_finish(&mut self) -> Result<(), PolicyRefusal> {
        if !self.policy_present {
            return Err(PolicyRefusal::Absent);
        }
        if self.capped {
            return Err(PolicyRefusal::Capped);
        }
        if self.policy == PolicyPhase::Finished {
            return Err(PolicyRefusal::Finished);
        }
        self.policy = PolicyPhase::Finished;
        Ok(())
    }
}
