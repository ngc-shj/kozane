#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects, clippy::panic)]

extern crate std;

use std::vec::Vec;

use super::*;
use auditkey_core::{Identity, SeqRule, encode_reply, parse};
use layout::auditkey::{BAD_REQUEST, SIGN};

/// SHA-256("kozane-audit-v1\0"), computed outside this crate (Python's
/// hashlib).
const H0: &str = "f165319a95ecc1c4a0d6de045de59ee5be7d1fc36a85f2cef8bee0436f264656";
/// h0, then "audit: ready seq=0", then "eth_out: ready seq=1".
const H1: &str = "e8b341046416f24185f0b360b227b79b107be7d13d67786e955fd807a6abf156";
const H2: &str = "38fe84dfcb98781b3299f594ef004550090b1b65e0fa35cac5ab6bf8963ebb27";

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

/// One printed line through `Chain`, as the PD prints it: the text, then
/// the trailer `end` writes.
fn print(chain: &mut Chain, text: &str) -> (u64, Vec<u8>) {
    let mut line = chain.begin();
    line.update(text.as_bytes());
    let mut printed = text.as_bytes().to_vec();
    let seq = chain.end(line, |t| printed.extend_from_slice(t));
    (seq, printed)
}

#[test]
fn h0_is_the_sha256_of_the_domain() {
    assert_eq!(hex(&h0()), H0);
    assert_eq!(hex(&Chain::new().head()), H0);
}

#[test]
fn the_chain_matches_known_answers_trailer_included() {
    let mut chain = Chain::new();
    assert_eq!(print(&mut chain, "audit: ready"), (0, b"audit: ready seq=0".to_vec()));
    assert_eq!(hex(&chain.head()), H1);
    assert_eq!(print(&mut chain, "eth_out: ready"), (1, b"eth_out: ready seq=1".to_vec()));
    assert_eq!(hex(&chain.head()), H2);
    assert_eq!(chain.next_seq(), 2);
}

#[test]
fn a_line_fed_in_pieces_hashes_as_link_does() {
    let mut chain = Chain::new();
    let before = chain.head();
    let mut line = chain.begin();
    for piece in ["audit: src=", "hs", " HandshakeOk total=", "1", " lost=0"] {
        line.update(piece.as_bytes());
    }
    chain.end(line, |_| {});
    assert_eq!(chain.head(), link(&before, b"audit: src=hs HandshakeOk total=1 lost=0 seq=0"));
}

#[test]
fn the_trailer_is_decimal_without_padding() {
    for (seq, want) in [(0, " seq=0"), (9, " seq=9"), (10, " seq=10"), (64, " seq=64"),
                        (u64::MAX, " seq=18446744073709551615")] {
        let (t, n) = trailer(seq);
        assert_eq!(&t[..n], want.as_bytes(), "seq {seq}");
    }
}

#[test]
fn ready_input_is_true_for_the_auditkey_channel_only() {
    for c in 0..64 {
        assert_eq!(ready_input([c]), c == CH_AUDITKEY, "channel {c}");
    }
    assert!(!ready_input([]));
    assert!(ready_input([layout::audit::CH_INGRESS, CH_AUDITKEY, layout::audit::CH_POLICY]));
    assert!(!ready_input([layout::audit::CH_INGRESS, layout::audit::CH_SUPERVISOR, layout::audit::CH_POLICY]));
}

const SOURCES: usize = 9;

/// A fake `auditkey`: its real seq rule, a signature that names the
/// request's seq, and every call it saw.
struct FakeAuditKey {
    rule: SeqRule,
    calls: Vec<u64>,
    refusals: usize,
    unavailable: Option<u32>,
}

impl FakeAuditKey {
    fn new() -> Self {
        Self { rule: SeqRule::new(), calls: Vec::new(), refusals: 0, unavailable: None }
    }

    fn call(&mut self, label: u64, words: &[u64]) -> (u64, Vec<u64>) {
        let req = parse(words).expect("audit sent a malformed request");
        assert_eq!(label, SIGN);
        self.calls.push(req.seq);
        if let Some(code) = self.unavailable {
            return (auditkey_core::unavailable_label(code), Vec::new());
        }
        match self.rule.next(req.seq) {
            Ok(next) => {
                self.rule = next;
                let mut signature = [0u8; 64];
                signature[..8].copy_from_slice(&req.seq.to_be_bytes());
                let id = Identity { srk_name: [1; 34], boot_id: [2; 16], reset: 3, restart: 0 };
                let bytes = encode_reply(&Reply { signature, identity: id });
                let mut out = [0u64; SIGN_REPLY_WORDS];
                let n = layout::tpm::pack(&bytes, &mut out).expect("fits");
                (OK, out[..n].to_vec())
            }
            Err(_) => {
                self.refusals += 1;
                (REFUSED, Vec::new())
            }
        }
    }
}

/// What the PD printed for a checkpoint: (its line's seq, signed, reason).
type Printed = (u64, bool, u32);

/// The PD's loop, minus the UART: `lines` lines, the sources reporting
/// ready at the seqs in `ready_at` (source i at `ready_at[i]`), and the
/// ready input at `notify_at` (None: never). After every line and after
/// the notification the PD polls once, as `pds/audit` does.
struct Sim {
    chain: Chain,
    cps: Checkpoints,
    key: FakeAuditKey,
    printed: Vec<Printed>,
}

impl Sim {
    fn new() -> Self {
        Self { chain: Chain::new(), cps: Checkpoints::new(SOURCES), key: FakeAuditKey::new(), printed: Vec::new() }
    }

    fn line(&mut self) {
        print(&mut self.chain, "audit: src=ingress ArpReplied total=1 lost=0");
        self.poll();
    }

    fn poll(&mut self) {
        let seq = self.chain.next_seq();
        match self.cps.poll(seq, self.chain.head(), 0) {
            Action::Idle => return,
            Action::Call(words) => {
                assert_eq!(parse(&words).map(|r| (r.seq, r.chain)), Some((seq, self.chain.head())));
                let (label, reply) = self.key.call(SIGN, &words);
                match self.cps.reply(label, &reply) {
                    Outcome::Signed(r) => {
                        assert_eq!(u64::from_be_bytes(r.signature[..8].try_into().unwrap()), seq);
                        self.printed.push((seq, true, 0));
                    }
                    Outcome::Unsigned(reason) => self.printed.push((seq, false, reason)),
                }
            }
            Action::Unsigned(reason) => self.printed.push((seq, false, reason)),
        }
        // The checkpoint line itself, which polls nothing.
        print(&mut self.chain, "audit: checkpoint");
    }

    fn run(&mut self, lines: u64, ready_at: &[u64], notify_at: Option<u64>) {
        for seq in 0..lines {
            for (i, at) in ready_at.iter().enumerate() {
                if *at == seq {
                    self.cps.source_ready(i);
                }
            }
            if notify_at == Some(seq) {
                self.cps.notified();
                self.poll();
            }
            self.line();
        }
    }
}

#[test]
fn a_fake_auditkey_sees_no_call_before_the_ready_input() {
    let mut sim = Sim::new();
    sim.run(400, &[1; SOURCES], None);
    assert!(sim.key.calls.is_empty(), "calls before the ready input: {:?}", sim.key.calls);
    // The periodic checkpoints still print, unsigned, every CHECKPOINT_EVERY.
    assert!(sim.printed.len() >= 4);
    assert!(sim.printed.iter().all(|(_, signed, reason)| !signed && *reason == REASON_PENDING));
    assert_eq!(sim.printed[0].0, CHECKPOINT_EVERY);
}

#[test]
fn the_ready_checkpoint_waits_for_the_ready_input_and_every_source() {
    let mut sim = Sim::new();
    // Every source but the last ready early; the input at 10; the last
    // source at 20: the call follows the last of the two.
    let mut ready = [2; SOURCES];
    ready[SOURCES - 1] = 20;
    sim.run(30, &ready, Some(10));
    assert_eq!(sim.key.calls.len(), 1);
    assert!(sim.key.calls[0] >= 20);
    assert_eq!(sim.printed, std::vec![(sim.key.calls[0], true, 0)]);
    assert!(sim.cps.ready_done());
}

#[test]
fn no_ready_checkpoint_while_a_source_is_not_ready() {
    let mut sim = Sim::new();
    let mut ready = [1; SOURCES];
    ready[3] = u64::MAX;
    sim.run(CHECKPOINT_EVERY - 1, &ready, Some(0));
    assert!(sim.key.calls.is_empty());
    assert!(!sim.cps.ready_done());
}

#[test]
fn auditkey_never_refuses_the_schedule() {
    // Over every notification point and ready point in a grid, the real
    // seq rule admits every call, the exemption is used at most once, and
    // the calls strictly increase.
    for notify in [0u64, 1, 5, 40, 63, 64, 65, 100, 127, 128, 200] {
        for ready in [0u64, 3, 60, 63, 64, 70, 130, 190] {
            let mut sim = Sim::new();
            sim.run(600, &[ready; SOURCES], Some(notify));
            assert_eq!(sim.key.refusals, 0, "notify {notify} ready {ready}: {:?}", sim.key.calls);
            assert!(sim.key.calls.windows(2).all(|w| w[0] < w[1]));
            assert!(sim.printed.iter().filter(|p| p.1).count() == sim.key.calls.len());
            // Each call is CHECKPOINT_EVERY past the last signed one, but
            // for at most one (the ready one, the rule's exemption).
            let mut last = 0u64;
            let mut short = 0;
            for seq in &sim.key.calls {
                if *seq < last + CHECKPOINT_EVERY {
                    short += 1;
                }
                last = *seq;
            }
            assert!(short <= 1, "notify {notify} ready {ready}: {:?}", sim.key.calls);
        }
    }
}

#[test]
fn every_checkpoint_moves_the_due_point_past_its_own_seq() {
    let mut cps = Checkpoints::new(1);
    assert_eq!(cps.due(), CHECKPOINT_EVERY);
    assert_eq!(cps.poll(CHECKPOINT_EVERY - 1, [0; 32], 0), Action::Idle);
    assert_eq!(cps.poll(CHECKPOINT_EVERY, [0; 32], 0), Action::Unsigned(REASON_PENDING));
    assert_eq!(cps.due(), 2 * CHECKPOINT_EVERY);
    assert_eq!(cps.poll(CHECKPOINT_EVERY + 1, [0; 32], 0), Action::Idle);
}

#[test]
fn a_refusal_prints_unsigned_and_schedules_past_the_refused_seq() {
    let mut cps = Checkpoints::new(1);
    cps.notified();
    let words = match cps.poll(CHECKPOINT_EVERY + 5, [7; 32], 2) {
        Action::Call(w) => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(parse(&words), Some(Request { seq: CHECKPOINT_EVERY + 5, chain: [7; 32], lost: 2 }));
    // In flight: nothing else until the reply.
    assert_eq!(cps.poll(10 * CHECKPOINT_EVERY, [0; 32], 0), Action::Idle);
    assert_eq!(cps.reply(REFUSED, &[]), Outcome::Unsigned(REASON_REFUSED));
    assert_eq!(cps.due(), 2 * CHECKPOINT_EVERY + 5);
    assert_eq!(cps.poll(2 * CHECKPOINT_EVERY + 4, [0; 32], 0), Action::Idle);
    assert!(matches!(cps.poll(2 * CHECKPOINT_EVERY + 5, [0; 32], 0), Action::Call(_)));
}

#[test]
fn an_unavailable_auditkey_gives_its_boot_code() {
    let mut sim = Sim::new();
    sim.key.unavailable = Some(0x8e);
    sim.run(200, &[1; SOURCES], Some(2));
    assert!(!sim.printed.is_empty());
    assert!(sim.printed.iter().all(|(_, signed, reason)| !signed && *reason == 0x8e));
}

#[test]
fn a_malformed_reply_is_unsigned() {
    for (label, words) in [(OK, std::vec![0u64; SIGN_REPLY_WORDS - 1]), (OK, std::vec![0u64; SIGN_REPLY_WORDS + 1]),
                           (BAD_REQUEST, std::vec![]), (7, std::vec![0u64; SIGN_REPLY_WORDS])] {
        let mut cps = Checkpoints::new(0);
        cps.notified();
        assert!(matches!(cps.poll(1, [0; 32], 0), Action::Call(_)));
        assert_eq!(cps.reply(label, &words), Outcome::Unsigned(REASON_BAD_REPLY), "label {label}");
    }
}

#[test]
fn a_source_index_past_the_sources_counts_nothing() {
    let mut cps = Checkpoints::new(2);
    cps.notified();
    cps.source_ready(0);
    cps.source_ready(2);
    cps.source_ready(40);
    assert_eq!(cps.poll(1, [0; 32], 0), Action::Idle);
    cps.source_ready(1);
    assert!(matches!(cps.poll(1, [0; 32], 0), Action::Call(_)));
}

#[test]
fn a_heartbeat_is_due_every_heartbeat_s_ticks() {
    let mut hb = Heartbeat::new();
    let due: Vec<(u64, u64)> = (1..=3 * HEARTBEAT_S).filter_map(|i| hb.tick().map(|n| (i, n))).collect();
    assert_eq!(due, [(HEARTBEAT_S, HEARTBEAT_S), (2 * HEARTBEAT_S, 2 * HEARTBEAT_S), (3 * HEARTBEAT_S, 3 * HEARTBEAT_S)]);
}

#[test]
fn the_timer_channel_is_not_the_ready_input() {
    assert!(!ready_input([layout::audit::CH_TIMER]));
    assert!(ready_input([layout::audit::CH_TIMER, CH_AUDITKEY]));
}
