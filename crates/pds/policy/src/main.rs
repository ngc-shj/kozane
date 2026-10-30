//! Peer-policy verifier PD (M8 plan C5, laws as amended by C11): passive,
//! untainted, device-less, and the only PD that verifies the two bundle
//! slots U-Boot measured into PCR 9. In `init` it asks `tpm` for the
//! anti-rollback state (its `CH_POLICY` requests, never a TPM command),
//! checks PCR 9 against both slots, verifies each slot's Ed25519 and
//! ML-DSA-65 signatures over `DOMAIN ‖ body` (D1) and parses it, then
//! drives `policy_wire`'s init machine (`after_state`, `after_advance`):
//! the selection and the one ADVANCE are that machine's, not this PD's.
//! It tells `tpm` Done when a bundle is verified and Failed on every other
//! exit (F7), so the cap of PCR 8 never waits on it.
//!
//! It never stops (M7 D4): a refused state, a mismatched PCR 9 or two bad
//! slots leave it answering `Unavailable{reason}` for the boot. Its callers
//! (the barrier PDs, C6) reach it only through `Await`. Its audit lines go
//! to a log page `audit` maps read-only (`audit_event::log`), so nothing
//! of the tainted `audit` reaches it (L1).

#![no_std]
#![no_main]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use audit_event::{Coalescer, Event, log};
use layout::policy as ch;
use layout::tpm as ipc;
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
use libcrux_sha2::{Digest, Sha256};
use limits::{BUNDLE_MAX, SPK_LEN};
use policy_wire::{AdvanceReply, DOMAIN, Outcome, Reject, Slot, SlotView, StateReply, Step};
use release_seq::RELEASE_SEQ;
use sel4_microkit::{Channel, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs_mut};

const TPM: Channel = Channel::new(ch::CH_TPM);
const AUDIT: Channel = Channel::new(ch::CH_AUDIT);
/// The `Await` callers: the barrier PDs (C6), one channel each; a call on
/// any other channel is a bad request.
const CALLERS: [Channel; 5] = [
    Channel::new(ch::CH_HS),
    Channel::new(ch::CH_PQ),
    Channel::new(ch::CH_INGRESS),
    Channel::new(ch::CH_DATA),
    Channel::new(ch::CH_INNER),
];

// `audit` names the reasons from its own table; this PD sees both.
const _: () = assert!(reasons_match());

// Both run only at compile time, where an out-of-bounds index or an
// overflow is a build error.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
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

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn reasons_match() -> bool {
    use audit_event::{POLICY_REASON_NAMES, POLICY_REASONS, POLICY_SLOT_NAMES, POLICY_STATE_REFUSED};
    let all = Reject::ALL;
    if all.len() != POLICY_REASON_NAMES.len() || all.len() != POLICY_REASONS as usize {
        return false;
    }
    if Reject::StateRefused.code() as u16 != POLICY_STATE_REFUSED {
        return false;
    }
    if !str_eq(POLICY_SLOT_NAMES[Slot::A.index() as usize], "A") || !str_eq(POLICY_SLOT_NAMES[Slot::B.index() as usize], "B") {
        return false;
    }
    let mut i = 0;
    while i < all.len() {
        if all[i].code() as usize != i || !str_eq(all[i].name(), POLICY_REASON_NAMES[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// `DOMAIN ‖ body`, the message both signatures cover: the verifiers take
/// one contiguous buffer, and the slots are read-only.
const MESSAGE_MAX: usize = DOMAIN.len() + BUNDLE_MAX;
struct Message(UnsafeCell<[u8; MESSAGE_MAX]>);

// SAFETY: a PD runs one thread, and only `verify` (from init, one slot at a
// time) touches the buffer.
unsafe impl Sync for Message {}

static MESSAGE: Message = Message(UnsafeCell::new([0; MESSAGE_MAX]));

fn slot_bytes(slot: Slot) -> &'static [u8] {
    let p: NonNull<[u8]> = match slot {
        Slot::A => memory_region_symbol!(policy_a: *mut [u8], n = BUNDLE_MAX),
        Slot::B => memory_region_symbol!(policy_b: *mut [u8], n = BUNDLE_MAX),
    };
    // SAFETY: each slot is mapped read-only here for the life of the
    // system, and no PD maps it writable (laws: bundle_slot, C11).
    unsafe { p.as_ref() }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        // At most BUNDLE_MAX, far below the u32 limit libcrux's update checks.
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finish(&mut out);
    out
}

/// What U-Boot extended into PCR 9 (D3): A's digest, then B's, from zero.
fn expected_pcr9() -> [u8; 32] {
    let a = sha256(&[slot_bytes(Slot::A)]);
    let b = sha256(&[slot_bytes(Slot::B)]);
    sha256(&[&sha256(&[&[0; 32], &a]), &b])
}

/// Both signatures over `DOMAIN ‖ body` (D1: Ed25519 and ML-DSA-65, empty
/// context). A key left all zero (no `[policy]` compiled in) never
/// reaches a verifier: fail closed.
fn verify(body: &[u8], sig_ed25519: &[u8; 64], sig_mldsa65: &[u8; 3309]) -> bool {
    if config::POLICY_ED25519_PUB.iter().all(|b| *b == 0) || config::POLICY_MLDSA65_PUB.iter().all(|b| *b == 0) {
        return false;
    }
    // SAFETY: init runs once and is the only caller; no other reference to
    // the buffer exists while this one is used.
    let buf = unsafe { &mut *MESSAGE.0.get() };
    let Some(len) = DOMAIN.len().checked_add(body.len()) else { return false };
    let Some(msg) = buf.get_mut(..len) else { return false };
    let (domain, rest) = msg.split_at_mut(DOMAIN.len());
    domain.copy_from_slice(DOMAIN);
    rest.copy_from_slice(body);
    let ed = libcrux_ed25519::verify(msg, &config::POLICY_ED25519_PUB, sig_ed25519).is_ok();
    let key = MLDSA65VerificationKey::new(config::POLICY_MLDSA65_PUB);
    let ml = ml_dsa_65::verify(&key, msg, b"", &MLDSA65Signature::new(*sig_mldsa65)).is_ok();
    ed & ml
}

/// One slot as `init` judged it: the view `select` takes, and why it is
/// not a signature-verified bundle (the `PolicyRejected` reason), if so.
#[derive(Clone, Copy)]
struct Judged {
    view: SlotView,
    refused: Option<Reject>,
}

fn rp_digest(public: &[u8; SPK_LEN]) -> [u8; 32] {
    secret_blob::blake2s(&[public])
}

/// C5 step 3 for one slot: empty (all zero, as provisioned), else split,
/// verify (D1), then parse against the compiled node.
fn judge(slot: &[u8]) -> Judged {
    let refused = |view, r| Judged { view, refused: Some(r) };
    if slot.iter().all(|b| *b == 0) {
        return refused(SlotView::Empty, Reject::Empty);
    }
    let Ok(unverified) = policy_wire::split(slot) else { return refused(SlotView::Malformed, Reject::Malformed) };
    if !verify(unverified.body(), unverified.sig_ed25519(), unverified.sig_mldsa65()) {
        return refused(SlotView::BadSignature, Reject::BadSignature);
    }
    match policy_wire::parse(slot, &config::node_config(), &rp_digest) {
        Ok(b) => Judged {
            view: SlotView::Valid {
                version: b.version(),
                min_release: b.min_release(),
                prev_sha256: *b.prev_sha256(),
                body_sha256: sha256(&[unverified.body()]),
            },
            refused: None,
        },
        Err(r) => refused(SlotView::Malformed, r),
    }
}

/// `tpm` over its policy channel: one request, its reply's bytes in `out`
/// (exactly `out.len()` of them) if `tpm` answered RSP_OK. The registers
/// are zeroed after the call.
fn tpm_call(kind: u64, req: &[u8], out: &mut [u8]) -> bool {
    let mut words = [0u64; ipc::words(ipc::POLICY_STATE_LEN)];
    let Some(n) = ipc::pack(req, &mut words) else { return false };
    with_msg_regs_mut(|mrs| {
        for (dst, src) in mrs.iter_mut().zip(words.iter().take(n)) {
            *dst = *src;
        }
    });
    let info = TPM.pp_call(MessageInfo::new(ipc::label(kind, req.len()), n));
    let (label, count) = (info.label(), info.count());
    let ok = with_msg_regs_mut(|mrs| {
        let got = ipc::kind(label) == ipc::RSP_OK
            && ipc::arg(label) == out.len()
            && count == ipc::words(out.len())
            && mrs.get(..count).and_then(|w| ipc::unpack(w, out.len(), out)).is_some();
        mrs.iter_mut().take(ipc::MSG_WORDS).for_each(|w| *w = 0);
        got
    });
    if !ok {
        out.fill(0);
    }
    ok
}

fn state() -> StateReply {
    let mut out = [0u8; ipc::POLICY_STATE_LEN];
    match tpm_call(ipc::REQ_POLICY_STATE, &[], &mut out).then(|| ipc::decode_state(&out)).flatten() {
        Some((current, pcr9)) => StateReply::Ok { current, pcr9 },
        None => StateReply::Refused,
    }
}

fn advance(expected: u32) -> AdvanceReply {
    let mut out = [0u8; ipc::POLICY_VALUE_LEN];
    match tpm_call(ipc::REQ_POLICY_ADVANCE, &expected.to_le_bytes(), &mut out).then(|| ipc::decode_value(&out)).flatten() {
        Some(v) => AdvanceReply::Ok(v),
        None => AdvanceReply::Refused,
    }
}

/// The log page's producer: coalesced records (each of `policy`'s is an
/// edge, never coalesced) appended to the page `audit` reads.
struct AuditLog {
    page: NonNull<u64>,
    writer: log::Writer,
    coalescer: Coalescer,
    pending: bool,
}

impl AuditLog {
    fn record(&mut self, ev: Event) {
        let page = self.page;
        let writer = &mut self.writer;
        self.pending |= self.coalescer.record(ev, |r| {
            writer.push(r, |at, word| {
                if at < log::WORDS {
                    // SAFETY: the page is mapped rw here and r in `audit`
                    // alone (laws), at least `log::WORDS` words, 8-aligned,
                    // and `at` is in it.
                    unsafe { page.add(at).write_volatile(word) }
                }
            })
        });
    }

    fn flush(&mut self) {
        if core::mem::take(&mut self.pending) {
            AUDIT.notify();
        }
    }
}

/// `init`'s verdict, and each slot's refusal for `PolicyRejected` when the
/// state was known (`current`).
struct Verdict {
    outcome: Outcome,
    current: Option<u32>,
    slots: [(Slot, Judged); 2],
}

/// C5 steps 1-5: STATE, then (only with a state to judge against) PCR 9
/// and both slots, then `policy_wire`'s machine, and ADVANCE when it asks.
fn decide() -> Verdict {
    let none = Judged { view: SlotView::Empty, refused: None };
    let reply = state();
    let StateReply::Ok { current, .. } = reply else {
        let outcome = match policy_wire::after_state(reply, &[0; 32], RELEASE_SEQ, none.view, none.view) {
            Step::Done(o) => o,
            Step::Advance(_) => Outcome::Unavailable { reason: Reject::StateRefused },
        };
        return Verdict { outcome, current: None, slots: [(Slot::A, none), (Slot::B, none)] };
    };
    let pcr9 = expected_pcr9();
    let (a, b) = (judge(slot_bytes(Slot::A)), judge(slot_bytes(Slot::B)));
    let outcome = match policy_wire::after_state(reply, &pcr9, RELEASE_SEQ, a.view, b.view) {
        Step::Done(o) => o,
        Step::Advance(pending) => policy_wire::after_advance(pending, advance(current)),
    };
    Verdict { outcome, current: Some(current), slots: [(Slot::A, a), (Slot::B, b)] }
}

/// The audit lines (C9): accepted and the release, or unavailable; then
/// each slot not selected that is not a candidate, for its reason (an
/// empty slot is no rejected bundle).
fn report(log: &mut AuditLog, v: &Verdict) {
    match v.outcome {
        Outcome::Verified { slot, version, .. } => {
            log.record(Event::PolicyAccepted { slot: u16::from(slot.index()), version });
            log.record(Event::ReleaseSeq { seq: RELEASE_SEQ });
        }
        Outcome::Unavailable { reason } => {
            log.record(Event::PolicyUnavailable { reason: u16::from(reason.code()), current: v.current.unwrap_or(0) });
        }
    }
    let Some(current) = v.current else { return };
    for (slot, judged) in v.slots {
        if matches!(v.outcome, Outcome::Verified { slot: s, .. } if s == slot) {
            continue;
        }
        let reason = judged.refused.or_else(|| policy_wire::not_candidate(current, RELEASE_SEQ, judged.view));
        let version = match judged.view {
            SlotView::Valid { version, .. } => version,
            _ => 0,
        };
        if let Some(r) = reason.filter(|r| *r != Reject::Empty) {
            log.record(Event::PolicyRejected { slot: u16::from(slot.index()), reason: u16::from(r.code()), version });
        }
    }
}

struct Policy {
    outcome: Outcome,
}

#[protection_domain]
fn init() -> Policy {
    boot_stage::run_init(|_| start())
}

fn start() -> Policy {
    let page = memory_region_symbol!(audit_policy: *mut [u64; log::WORDS]);
    let mut log = AuditLog { page: page.cast(), writer: log::Writer::new(), coalescer: Coalescer::new(), pending: false };
    let verdict = decide();
    // C5 step 6 (F7): Done only for a verified bundle, Failed on every
    // other exit; the cap's verdict goes to the key PDs, not here.
    let finish = match verdict.outcome {
        Outcome::Verified { .. } => ipc::REQ_POLICY_DONE,
        Outcome::Unavailable { .. } => ipc::REQ_POLICY_FAILED,
    };
    let _ = tpm_call(finish, &[], &mut []);
    report(&mut log, &verdict);
    // `policy: ready` whatever the outcome: readiness is that `Await` is
    // answered from here on; the barrier is about `Verified`.
    log.record(Event::Ready);
    log.flush();
    Policy { outcome: verdict.outcome }
}

impl Handler for Policy {
    type Error = Infallible;

    fn protected(&mut self, channel: Channel, msg_info: MessageInfo) -> Result<MessageInfo, Self::Error> {
        if !CALLERS.contains(&channel) || msg_info.label() != ch::AWAIT || msg_info.count() != 0 {
            return Ok(MessageInfo::new(ch::BAD_REQUEST, 0));
        }
        let mut words = [0u64; ipc::words(policy_wire::VERIFIED_REPLY_LEN)];
        let (label, n) = match self.outcome {
            Outcome::Verified { slot, version, body_sha256 } => {
                let reply = policy_wire::verified_reply(slot, version, &body_sha256);
                (ch::VERIFIED, ipc::pack(&reply, &mut words).unwrap_or(0))
            }
            Outcome::Unavailable { reason } => {
                if let Some(w) = words.first_mut() {
                    *w = u64::from(reason.code());
                }
                (ch::UNAVAILABLE, 1)
            }
        };
        with_msg_regs_mut(|mrs| {
            for (i, dst) in mrs.iter_mut().take(ipc::MSG_WORDS).enumerate() {
                *dst = if i < n { words.get(i).copied().unwrap_or(0) } else { 0 };
            }
        });
        Ok(MessageInfo::new(label, n))
    }
}
