//! `audit`'s export logic (M8 plan C10, D7), host-testable and used only by
//! `pds/audit`: the line chain and the checkpoint schedule.
//!
//! **The chain.** Every printed line ends in the trailer ` seq=<n>` before
//! its CRLF, `n` counting the boot's lines from 0. `audit` keeps
//! `h = SHA-256(h ‖ line)` over each line without its CRLF, trailer
//! included, from the constant `h0 = SHA-256("kozane-audit-v1\0")`. Boot
//! ID, reset and restart are bound only in signed checkpoints.
//!
//! **The checkpoints.** `audit` makes at most one PPC, to `auditkey`, and
//! only as this machine's `Action::Call`. That action exists only after the
//! ready input, `auditkey`'s one notification at the end of its init, which
//! `ready_input` decodes from the `layout` auditkey channel alone (F32). A
//! checkpoint is due once every source has reported ready (the "ready"
//! checkpoint, once a boot) and whenever the next line reaches the due
//! point. Each checkpoint, signed or not, moves the due point
//! `CHECKPOINT_EVERY` past its own seq. The boot starts as if seq 0 had
//! been signed, as `auditkey`'s seq rule does, so every periodic request is
//! at least `CHECKPOINT_EVERY` past the last signed seq and only the ready
//! one can need the rule's one exemption (deviation D-18). A checkpoint due
//! before the ready input, or answered with anything but a signature, is
//! printed unsigned with a reason code (`REASON_*`, or `auditkey`'s boot
//! error code, which starts at `auditkey_core::CODE_BASE`).

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use auditkey_core::{CHAIN_LEN, Reply, Request};
use layout::audit::{CH_AUDITKEY, CHECKPOINT_EVERY};
use layout::auditkey::{OK, REFUSED, SIGN_REPLY_LEN, SIGN_REPLY_WORDS, SIGN_REQ_WORDS};
use libcrux_sha2::{Digest, Sha256};

/// The chain's domain: `h0` is its SHA-256.
pub const DOMAIN: &[u8; 16] = b"kozane-audit-v1\0";
/// The trailer's text before the decimal seq.
pub const TRAILER: &[u8; 5] = b" seq=";
/// The longest trailer: `TRAILER` and a u64's 20 digits.
pub const TRAILER_MAX: usize = TRAILER.len() + 20;

/// Unsigned checkpoint reasons of `audit`'s own; `auditkey`'s boot error
/// codes start at `auditkey_core::CODE_BASE`, above all of them.
/// The checkpoint fell due before `auditkey`'s notification.
pub const REASON_PENDING: u32 = 1;
/// `auditkey`'s seq rule refused the request.
pub const REASON_REFUSED: u32 = 2;
/// `auditkey` answered with no well-formed signature reply.
pub const REASON_BAD_REPLY: u32 = 3;
const _: () = assert!(REASON_BAD_REPLY < auditkey_core::CODE_BASE);

/// The sources a boot waits for before its ready checkpoint: at most this
/// many (one bit each).
pub const MAX_SOURCES: usize = 32;

/// `h0 = SHA-256(DOMAIN)`.
pub fn h0() -> [u8; CHAIN_LEN] {
    let mut out = [0u8; CHAIN_LEN];
    Sha256::hash(&mut out, DOMAIN);
    out
}

/// `SHA-256(h ‖ line)`: the chain after `line` (without its CRLF).
pub fn link(h: &[u8; CHAIN_LEN], line: &[u8]) -> [u8; CHAIN_LEN] {
    let mut l = Line::after(h);
    l.update(line);
    l.finish()
}

/// `" seq=<n>"` in the first `.1` bytes of `.0`.
pub fn trailer(seq: u64) -> ([u8; TRAILER_MAX], usize) {
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    let mut v = seq;
    loop {
        if let Some(d) = digits.get_mut(n) {
            *d = b'0' | (v.checked_rem(10).unwrap_or(0) as u8);
        }
        n = n.saturating_add(1);
        v = v.checked_div(10).unwrap_or(0);
        if v == 0 || n >= digits.len() {
            break;
        }
    }
    let mut out = [0u8; TRAILER_MAX];
    let (head, rest) = out.split_at_mut(TRAILER.len());
    head.copy_from_slice(TRAILER);
    for (dst, src) in rest.iter_mut().zip(digits.get(..n).unwrap_or(&[]).iter().rev()) {
        *dst = *src;
    }
    (out, TRAILER.len().saturating_add(n))
}

/// One line being hashed: `SHA-256(h ‖ …)` fed as the line is printed.
pub struct Line {
    hasher: Sha256,
}

impl Line {
    fn after(h: &[u8; CHAIN_LEN]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(h);
        Self { hasher }
    }

    /// More of the line's bytes (never its CRLF; each line is far below the
    /// u32 length libcrux's update checks).
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn finish(&self) -> [u8; CHAIN_LEN] {
        let mut out = [0u8; CHAIN_LEN];
        self.hasher.finish(&mut out);
        out
    }
}

/// The boot's chain head and its next line's seq.
pub struct Chain {
    head: [u8; CHAIN_LEN],
    next: u64,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    /// A boot's start: `h0`, and the next line is seq 0.
    pub fn new() -> Self {
        Self { head: h0(), next: 0 }
    }

    /// The chain over every line ended so far.
    pub fn head(&self) -> [u8; CHAIN_LEN] {
        self.head
    }

    /// The seq the next line's trailer carries.
    pub fn next_seq(&self) -> u64 {
        self.next
    }

    /// Starts the next line: its bytes go to `Line::update` as they are
    /// printed, then the line goes back to `end`.
    pub fn begin(&self) -> Line {
        Line::after(&self.head)
    }

    /// Ends `line`: its trailer goes to `out` and into the hash, the head
    /// moves past it and the seq advances (saturating: a u64 of lines is
    /// never printed). Returns the line's seq.
    pub fn end(&mut self, mut line: Line, mut out: impl FnMut(&[u8])) -> u64 {
        let seq = self.next;
        let (t, n) = trailer(seq);
        let t = t.get(..n).unwrap_or(&[]);
        out(t);
        line.update(t);
        self.head = line.finish();
        self.next = seq.saturating_add(1);
        seq
    }
}

/// True only when the notified set holds the `layout` auditkey channel:
/// `auditkey`'s one notification, the ready input (F32). Every channel the
/// PD was notified on goes through here; no other channel counts.
pub fn ready_input(channels: impl IntoIterator<Item = usize>) -> bool {
    channels.into_iter().any(|c| c == CH_AUDITKEY)
}

/// What the PD does next for the checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Idle,
    /// The one PPC: `SIGN` to `auditkey` with these words, then `reply`
    /// with its answer, then the checkpoint line (seq: the request's).
    Call([u64; SIGN_REQ_WORDS]),
    /// The unsigned checkpoint line, with this reason, now.
    Unsigned(u32),
}

/// A checkpoint's outcome once `auditkey` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Signed(Reply),
    Unsigned(u32),
}

/// The checkpoint schedule (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoints {
    /// The ready input arrived.
    notified: bool,
    /// The sources that reported ready, one bit each, and all of them.
    ready: u32,
    all: u32,
    /// The ready checkpoint was taken (once a boot).
    ready_done: bool,
    /// The seq from which a periodic checkpoint is due.
    due: u64,
    /// A `Call` awaits its `reply`.
    in_flight: bool,
}

impl Checkpoints {
    /// A boot's start for `sources` sources (at most `MAX_SOURCES`; more
    /// are clamped): nothing notified, nothing ready, the first periodic
    /// checkpoint due `CHECKPOINT_EVERY` past seq 0.
    pub const fn new(sources: usize) -> Self {
        let n = if sources > MAX_SOURCES { MAX_SOURCES } else { sources };
        let all = if n == MAX_SOURCES { u32::MAX } else { (1u32 << n).wrapping_sub(1) };
        Self { notified: false, ready: 0, all, ready_done: false, due: CHECKPOINT_EVERY, in_flight: false }
    }

    /// The ready input (`ready_input` was true).
    pub fn notified(&mut self) {
        self.notified = true;
    }

    /// Source `i` reported ready; an index past the sources counts nothing.
    pub fn source_ready(&mut self, i: usize) {
        if i < MAX_SOURCES {
            self.ready |= self.all & 1u32.checked_shl(i as u32).unwrap_or(0);
        }
    }

    pub fn is_notified(&self) -> bool {
        self.notified
    }

    /// The seq from which a periodic checkpoint is due.
    pub fn due(&self) -> u64 {
        self.due
    }

    pub fn ready_done(&self) -> bool {
        self.ready_done
    }

    /// Whether a checkpoint is due before the line `next_seq`, given the
    /// chain over the lines before it and the running lost total; at most
    /// one per call. Every checkpoint taken moves the due point
    /// `CHECKPOINT_EVERY` past `next_seq`, its own line's seq.
    pub fn poll(&mut self, next_seq: u64, chain: [u8; CHAIN_LEN], lost: u64) -> Action {
        if self.in_flight {
            return Action::Idle;
        }
        // Seq 0, the boot's first line, counts as signed (D-18): never asked for.
        let ready_due = !self.ready_done && self.notified && self.ready == self.all && next_seq > 0;
        if !ready_due && next_seq < self.due {
            return Action::Idle;
        }
        self.due = next_seq.saturating_add(CHECKPOINT_EVERY);
        self.ready_done |= ready_due;
        if !self.notified {
            return Action::Unsigned(REASON_PENDING);
        }
        self.in_flight = true;
        Action::Call(auditkey_core::encode(&Request { seq: next_seq, chain, lost }))
    }

    /// `auditkey`'s answer to the `Call`: its reply label and the reply
    /// words it returned.
    pub fn reply(&mut self, label: u64, words: &[u64]) -> Outcome {
        self.in_flight = false;
        if label == REFUSED {
            return Outcome::Unsigned(REASON_REFUSED);
        }
        if let Some(code) = auditkey_core::unavailable_code(label) {
            return Outcome::Unsigned(code);
        }
        let mut bytes = [0u8; SIGN_REPLY_LEN];
        let reply = (label == OK && words.len() == SIGN_REPLY_WORDS)
            .then(|| layout::tpm::unpack(words, SIGN_REPLY_LEN, &mut bytes))
            .flatten()
            .and_then(|()| auditkey_core::decode_reply(&bytes));
        match reply {
            Some(r) => Outcome::Signed(r),
            None => Outcome::Unsigned(REASON_BAD_REPLY),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
