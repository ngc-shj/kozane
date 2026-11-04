//! The residue cases for the Rosenpass initiator (M9 plan C7, I7.2: every
//! transient secret is in a `Secret`, wiped on every exit, errors included;
//! deviation D-16).
//!
//! Each case runs one initiator call on a painted stack the harness owns
//! (`stack.rs`), with the initiator's state in a mapping it owns
//! (`arena.rs`), twice, each time from a fresh state:
//!
//! - without a scrub, to measure how deep the call reaches below its caller,
//!   which `kozane_client::SCRUB_DEPTH` must cover, and to count what it
//!   leaves there (moved-from `Secret`s and libcrux's unwiped state);
//! - then followed by `kozane_client::scrub_stack`, as the client calls it.
//!   The stack must then hold none of the secrets the call handled; the
//!   state none of what the call had to wipe, all of what it keeps, and no
//!   more of any other secret than before.
//!
//! A failure prints one `rp-residue:` line. Two controls: a secret alive in
//! the caller's frame, above the scrub, must be found; and the unscrubbed
//! runs together must leave residue, so the scrub is what clears it.
//!
//! The KEMs and the RNG are deterministic seams replaying values from the
//! heap, shaped like the real ones (`Secret::copy_from` into the result), so
//! the harness knows every byte pattern: the cookie value, the Kyber secret
//! key and both KEM shared keys. The chaining key after IHI8 and tkr are
//! recomputed here from the messages' public fields with `crypto`'s KH and
//! checked against the messages' tags and the OSK. The real KEMs, which
//! the client calls, reach deeper: two more cases measure `start` and
//! `handle_resp_hello` with them, against the scrub's depth.

#![deny(unsafe_code)]

mod arena;
mod scan;
mod stack;

use std::hint::black_box;
use std::process::exit;

use kozane_client::{SCRUB_DEPTH, scrub_stack};
use rosenpass_core::cookie::{self, COOKIE_REPLY_LEN};
use rosenpass_core::crypto::{self, Domains, KEY_LEN, NONCE_LEN, TAG_LEN};
use rosenpass_core::initiator_state::{Phase, REJECT_AFTER_TIME_NS};
use rosenpass_core::{
    Conf, Decaps, DecapsError, ESK_LEN, Encaps, EncapsError, Ephemeral, Error, Initiator, InitiatorKeys, Kyber512,
    McEliece460896, Responder, Rng, RngError, SHK_LEN, SPK_LEN, Secret, Seams, envelope_mac, mac_key, peer_id,
};
use rosenpass_wire::{
    self as wire, ECT_LEN, EMPTY_DATA_LEN, EPK_LEN, INIT_CONF_LEN, INIT_HELLO_LEN, RESP_HELLO_LEN, SCT_LEN,
};

use crate::arena::Arena;
use crate::scan::{FORMS, Form, Needles};
use crate::stack::OwnedStack;

/// The stack each call runs on, and the padding frame between the thread's
/// entry and the call: glibc's thread exit runs above the pad, so it cannot
/// overwrite what the call left.
const STACK: usize = 1 << 20;
const PAD: usize = 64 * 1024;
const PAINT: u8 = 0x5c;
/// Every call must have disturbed at least this much stack below the pad,
/// so that it ran on the scanned stack at all: the control's one frame
/// takes 72 bytes, a CookieReply for another session about 150.
const FLOOR: usize = 64;
const _: () = assert!(SCRUB_DEPTH + PAD < STACK, "the scrub must fit on the scanned stack");

/// The start cases (4 refused draws and the accepted call), RespHello (8),
/// EmptyData (4), CookieReply (3), the expiry tick, the control, and the
/// two with the real KEMs.
const CASES: usize = 5 + 8 + 4 + 3 + 1 + 1 + 2;


// ---- known values ----

/// SplitMix64 from a label's FNV-1a: deterministic bytes per label, every
/// 8-byte window distinctive in practice.
fn stream(label: &str, len: usize) -> Vec<u8> {
    let mut x = label.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(len);
    out
}

fn boxed<const N: usize>(label: &str) -> Box<[u8; N]> {
    stream(label, N).into_boxed_slice().try_into().expect("length")
}

fn key(label: &str) -> &'static [u8; SPK_LEN] {
    Box::leak(boxed::<SPK_LEN>(label))
}

/// Every value the seams hand out, on the heap.
struct Known {
    spki: &'static [u8; SPK_LEN],
    spkr: &'static [u8; SPK_LEN],
    /// Another responder key: the wrong-key initiator is pinned to it.
    spkr_other: &'static [u8; SPK_LEN],
    epk: Box<[u8; EPK_LEN]>,
    esk: Box<[u8; ESK_LEN]>,
    ect: Box<[u8; ECT_LEN]>,
    kyber_ss: Box<[u8; SHK_LEN]>,
    /// IHI5: the initiator's encapsulation to the responder.
    sct_i: Box<[u8; SCT_LEN]>,
    mce_ss_i: Box<[u8; SHK_LEN]>,
    /// RHR5 / RHI5: the responder's encapsulation to the initiator.
    sct_r: Box<[u8; SCT_LEN]>,
    mce_ss_r: Box<[u8; SHK_LEN]>,
    /// What a decapsulation of anything else yields (implicit rejection).
    other_ss: Box<[u8; SHK_LEN]>,
    /// The initiator's draws: cookie 16, sidi 4, Kyber seed 64, McEliece 32,
    /// jitter 16, then RespHello's jitter.
    draws: Vec<u8>,
    reply_cookie: Box<[u8; 16]>,
    control: Box<[u8; 32]>,
}

impl Known {
    fn new() -> Self {
        Self {
            spki: key("spki"),
            spkr: key("spkr"),
            spkr_other: key("spkr-other"),
            epk: boxed("epk"),
            esk: boxed("esk"),
            ect: boxed("ect"),
            kyber_ss: boxed("kyber-ss"),
            sct_i: boxed("sct-i"),
            mce_ss_i: boxed("mce-ss-i"),
            sct_r: boxed("sct-r"),
            mce_ss_r: boxed("mce-ss-r"),
            other_ss: boxed("other-ss"),
            draws: stream("draws", 4096),
            reply_cookie: boxed("reply-cookie"),
            control: boxed("control"),
        }
    }

    fn cookie(&self) -> &[u8] {
        &self.draws[..16]
    }

    fn keys(&self) -> InitiatorKeys<'static> {
        InitiatorKeys { spki: self.spki, spkr: self.spkr }
    }

    fn wrong_keys(&self) -> InitiatorKeys<'static> {
        InitiatorKeys { spki: self.spki, spkr: self.spkr_other }
    }
}

// ---- seams ----

/// The initiator's RNG: replays `Known::draws`, refusing the `fail_at`-th
/// call (1-based) if set.
struct Draws<'a> {
    bytes: &'a [u8],
    at: usize,
    calls: usize,
    fail_at: Option<usize>,
}

impl<'a> Draws<'a> {
    fn new(bytes: &'a [u8], fail_at: Option<usize>) -> Self {
        Self { bytes, at: 0, calls: 0, fail_at }
    }
}

impl Rng for Draws<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(RngError);
        }
        let src = self.bytes.get(self.at..self.at + out.len()).ok_or(RngError)?;
        out.copy_from_slice(src);
        self.at += out.len();
        Ok(())
    }
}

/// Kyber-512 for both sides, shaped like `kem::Kyber512`: the seed is drawn,
/// the key pair and shared key come from `Known`.
struct FakeKyber<'a>(&'a Known);

impl Ephemeral for FakeKyber<'_> {
    fn keygen<R: Rng>(&mut self, rng: &mut R) -> Result<([u8; EPK_LEN], Secret<ESK_LEN>), RngError> {
        let mut seed = [0u8; 64];
        rng.fill(&mut seed)?;
        Ok((*self.0.epk, Secret::copy_from(&self.0.esk)))
    }

    fn decaps(&mut self, _: &Secret<ESK_LEN>, ct: &[u8; ECT_LEN]) -> Secret<SHK_LEN> {
        Secret::copy_from(if ct == &*self.0.ect { &self.0.kyber_ss } else { &self.0.other_ss })
    }
}

impl Encaps<EPK_LEN, ECT_LEN> for FakeKyber<'_> {
    fn encaps<R: Rng>(&mut self, _: &[u8; EPK_LEN], rng: &mut R) -> Result<([u8; ECT_LEN], Secret<SHK_LEN>), EncapsError> {
        rng.fill(&mut [0u8; 32]).map_err(|_| EncapsError::Rng)?;
        Ok((*self.0.ect, Secret::copy_from(&self.0.kyber_ss)))
    }
}

/// McEliece for both sides: encapsulation to the initiator's key is RHR5's,
/// to any other IHI5's.
struct FakeMce<'a>(&'a Known);

impl Encaps<SPK_LEN, SCT_LEN> for FakeMce<'_> {
    fn encaps<R: Rng>(&mut self, pk: &[u8; SPK_LEN], rng: &mut R) -> Result<([u8; SCT_LEN], Secret<SHK_LEN>), EncapsError> {
        rng.fill(&mut [0u8; 32]).map_err(|_| EncapsError::Rng)?;
        let k = self.0;
        if pk[..] == k.spki[..] {
            Ok((*k.sct_r, Secret::copy_from(&k.mce_ss_r)))
        } else {
            Ok((*k.sct_i, Secret::copy_from(&k.mce_ss_i)))
        }
    }
}

/// Decapsulation under one side's key (`pqkey`'s or the client's `rp.sk`):
/// the ciphertext made for that key yields its shared key.
struct FakeDecaps<'a> {
    known: &'a Known,
    responder: bool,
    refuse: bool,
}

impl Decaps for FakeDecaps<'_> {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let k = self.known;
        if self.refuse {
            return Err(DecapsError::Refused);
        }
        let (mine, ss) = if self.responder { (&k.sct_i, &k.mce_ss_i) } else { (&k.sct_r, &k.mce_ss_r) };
        Ok(Secret::copy_from(if sct == &**mine { ss } else { &k.other_ss }))
    }
}

/// The initiator's seams over `known`, with its RNG and decapsulation.
macro_rules! seams {
    ($known:expr, $rng:expr, $refuse:expr) => {
        &mut Seams {
            decaps: &mut FakeDecaps { known: $known, responder: false, refuse: $refuse },
            kyber: &mut FakeKyber($known),
            mceliece: &mut FakeMce($known),
            rng: $rng,
        }
    };
}

// ---- the chain, recomputed for the needles ----

struct Model<'d> {
    d: &'d Domains,
    ck: [u8; KEY_LEN],
}

impl Model<'_> {
    fn mix(&mut self, a: &[u8]) -> &mut Self {
        let k = crypto::kh(&self.ck, &self.d.mix).expect("kh");
        crypto::kh_into(k.expose(), a, &mut self.ck).expect("kh");
        self
    }

    /// The chain's `encrypt_and_mix` of `pt`, checked against the
    /// message's `ct`.
    fn sealed(&mut self, pt: &[u8], ct: &[u8], what: &str) -> &mut Self {
        let k = crypto::kh(&self.ck, &self.d.hs_enc).expect("kh");
        let mut want = vec![0u8; pt.len() + TAG_LEN];
        crypto::aead_seal(&k, &[0; NONCE_LEN], pt, &mut want).expect("seal");
        if want != ct {
            fail(&format!("needle model: {what} differs from the message's"));
        }
        self.mix(ct)
    }
}

/// IHI1–IHI8 over `ih`: the chaining key `Handshake::ck` holds.
fn ck_after_init_hello(k: &Known, d: &Domains, spkr: &[u8; SPK_LEN], ih: &[u8]) -> [u8; KEY_LEN] {
    let ih = wire::InitHello::parse(ih).expect("InitHello");
    let mut m = Model { d, ck: crypto::kh_public(&d.ckinit, spkr).expect("kh") };
    m.mix(&ih.sidi).mix(&ih.epki).mix(spkr).mix(&*k.mce_ss_i).mix(&ih.sctr);
    m.sealed(&peer_id(d, k.spki).expect("pid"), &ih.pidi_ct, "pidi_ct");
    m.mix(k.spki).mix(&[0; KEY_LEN]);
    m.sealed(&[], &ih.auth, "InitHello auth");
    m.ck
}

/// RHI3–RHI7, ICI3, ICI4 and ICI7 from `ck`: the OSK and tkr.
fn osk_and_txkt(k: &Known, d: &Domains, ck: [u8; KEY_LEN], rh: &[u8], ic: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let rh = wire::RespHello::parse(rh).expect("RespHello");
    let ic = wire::InitConf::parse(ic).expect("InitConf");
    let mut m = Model { d, ck };
    m.mix(&rh.sidr).mix(&rh.sidi).mix(&*k.epk).mix(&*k.kyber_ss).mix(&rh.ecti);
    m.mix(k.spki).mix(&*k.mce_ss_r).mix(&rh.scti).mix(&rh.biscuit_ct);
    m.sealed(&[], &rh.auth, "RespHello auth");
    m.mix(&rh.sidi).mix(&rh.sidr);
    m.sealed(&[], &ic.auth, "InitConf auth");
    let osk = crypto::kh(&m.ck, &d.osk).expect("kh");
    let txkt = crypto::kh(&m.ck, &d.res_enc).expect("kh");
    (*osk.expose(), *txkt.expose())
}

// ---- the scan ----

fn fail(why: &str) -> ! {
    println!("rp-residue: {why}");
    exit(1)
}

#[inline(never)]
fn padded(f: impl FnOnce()) {
    let mut pad = [0u8; PAD];
    black_box(&mut pad);
    f();
    black_box(&pad);
}


/// The first control's frame: a secret alive while the scrub runs below
/// it, then kept past its scope.
#[inline(never)]
fn keep_above_scrub(value: &[u8; 32]) {
    let s = Secret::copy_from(value);
    black_box(&s);
    scrub_stack();
    black_box(&s);
    std::mem::forget(s);
}

/// What one case checks: the forms the call handled, which the scrubbed
/// stack must not hold and its state no more of than before; the forms the
/// state must no longer hold; and those it must still hold.
#[derive(Default)]
struct Expect<'a> {
    forms: Vec<(Form, &'a [u8])>,
    gone: Vec<Form>,
    kept: Vec<Form>,
}

impl Expect<'_> {
    fn needles(&self) -> Needles {
        let mut n = Needles::new();
        for (form, bytes) in &self.forms {
            n.add(*form, bytes);
        }
        n
    }
}

/// Matching windows per form.
fn counts(n: &Needles, region: &[u8]) -> [usize; FORMS.len()] {
    let mut c = [0; FORMS.len()];
    for h in n.scan(region) {
        c[h.form] = h.count;
    }
    c
}

struct Scan {
    stack: OwnedStack,
    base: usize,
    cases: usize,
    failed: bool,
    /// The deepest unscrubbed call, below the caller.
    deepest: usize,
    /// Windows the unscrubbed runs left, over all cases.
    unscrubbed: usize,
}

impl Scan {
    /// Paints the stack, runs `f` on it, and returns how deep (from the
    /// top) the paint was disturbed.
    fn run(&mut self, f: impl FnOnce() + Send) -> usize {
        self.stack.bytes_mut().fill(PAINT);
        self.stack.run(|| padded(f));
        STACK - self.stack.bytes().iter().position(|&b| b != PAINT).unwrap_or(STACK)
    }

    fn miss(&mut self, why: String) {
        println!("rp-residue: {why}");
        self.failed = true;
    }

    fn check(&mut self, what: &str, ok: bool) {
        if !ok {
            self.miss(what.to_string());
        }
    }

    /// The matches `e` has in what the last run left on the stack.
    fn left(&self, e: &Expect<'_>, depth: usize) -> [usize; FORMS.len()] {
        counts(&e.needles(), &self.stack.bytes()[STACK - depth..])
    }

    /// The unscrubbed run: how deep `f` reaches below its caller, which the
    /// scrub must cover, and what it leaves.
    fn measure(&mut self, name: &str, e: &Expect<'_>, f: impl FnOnce() + Send) {
        let depth = self.run(f);
        let used = depth.saturating_sub(self.base);
        println!("RP-RESIDUE-DEPTH {name} {used}");
        if used < FLOOR {
            self.miss(format!("{name}: {used} bytes below the caller, floor {FLOOR}"));
        }
        if used > SCRUB_DEPTH {
            self.miss(format!("{name}: {used} bytes below the caller, the scrub covers {SCRUB_DEPTH}"));
        }
        self.deepest = self.deepest.max(used);
        self.unscrubbed += self.left(e, depth).iter().sum::<usize>();
    }

    /// The scrubbed run: `f`, then the client's scrub from the same frame;
    /// nothing `e` names may be left.
    fn scrubbed(&mut self, name: &str, e: &Expect<'_>, f: impl FnOnce() + Send) {
        let depth = self.run(|| {
            f();
            scrub_stack();
        });
        for (form, &n) in FORMS.iter().zip(&self.left(e, depth)) {
            if n > 0 {
                self.miss(format!("{name} left {form} in stack (windows={n})"));
            }
        }
        self.cases += 1;
    }

    /// One initiator call, on a fresh `setup()` each run: unscrubbed, then
    /// scrubbed with its state checked. Returns the scrubbed run's result
    /// and state.
    fn case<T: Send>(
        &mut self,
        name: &str,
        setup: impl Fn() -> Arena<Initiator>,
        e: &Expect<'_>,
        call: impl Fn(&mut Initiator) -> T + Sync,
    ) -> (Option<T>, Arena<Initiator>) {
        let mut a = setup();
        let ini = a.get_mut();
        self.measure(name, e, || {
            black_box(call(ini));
        });

        let mut a = setup();
        let n = e.needles();
        let before = counts(&n, a.bytes());
        let mut out = None;
        let ini = a.get_mut();
        self.scrubbed(name, e, || out = Some(call(ini)));
        let after = counts(&n, a.bytes());
        for (f, form) in FORMS.iter().enumerate() {
            if e.gone.iter().any(|g| *g as usize == f) {
                if after[f] > 0 {
                    self.miss(format!("{name} left {form} in state (windows={})", after[f]));
                }
            } else if e.kept.iter().any(|g| *g as usize == f) {
                if after[f] == 0 {
                    self.miss(format!("{name}: {form} not found in state, which holds it"));
                }
            } else if after[f] > before[f] {
                self.miss(format!("{name} left {form} in state (windows={}, {} before)", after[f], before[f]));
            }
        }
        (out, a)
    }
}

/// The messages of one exchange, made on the main thread (not scanned).
struct Exchange {
    ih: Box<[u8; INIT_HELLO_LEN]>,
    rh: Box<[u8; RESP_HELLO_LEN]>,
    ic: Box<[u8; INIT_CONF_LEN]>,
    ed: Box<[u8; EMPTY_DATA_LEN]>,
    osk: [u8; KEY_LEN],
}

fn responder(k: &Known) -> Responder<'static> {
    let mut r = Responder::new(k.spkr, &[k.spki], &mut Draws::new(&stream("responder", 4096), None)).expect("responder");
    r.tick(0, &mut Draws::new(&stream("biscuit", 64), None)).expect("biscuit key");
    r
}

fn exchange(k: &Known) -> Exchange {
    let mut ini = Initiator::new(&k.keys()).expect("initiator");
    let ih = Box::new(ini.start(&k.keys(), 0, seams!(k, &mut Draws::new(&k.draws, None), false)).expect("start"));
    let mut r = responder(k);
    let mut rh = Box::new([0u8; RESP_HELLO_LEN]);
    let rbytes = stream("responder-hello", 4096);
    let rng = &mut Draws::new(&rbytes, None);
    let rs = &mut Seams {
        decaps: &mut FakeDecaps { known: k, responder: true, refuse: false },
        kyber: &mut FakeKyber(k),
        mceliece: &mut FakeMce(k),
        rng,
    };
    r.handle_init_hello(&*ih, 1, rs, &mut rh).expect("RespHello");
    let draws = &mut Draws::new(&k.draws[200..], None);
    let (ic, osk) = ini.handle_resp_hello(&k.keys(), &*rh, 2, seams!(k, draws, false)).expect("InitConf");
    let Ok(Conf::Fresh(p)) = r.handle_init_conf(&ic, 3) else {
        fail("the responder refused the InitConf");
    };
    let ed = Box::new(r.commit_conf(p, 3).expect("EmptyData"));
    Exchange { ih, rh, ic: Box::new(ic), ed, osk: *osk.expose() }
}

/// A fresh initiator in a mapping, started (on the main thread) with
/// `Known::draws` against `keys`.
fn started(k: &Known, keys: &InitiatorKeys<'static>) -> (Arena<Initiator>, Box<[u8; INIT_HELLO_LEN]>) {
    let mut a = Arena::new(Initiator::new(keys).expect("initiator"));
    let ih = a.get_mut().start(keys, 0, seams!(k, &mut Draws::new(&k.draws, None), false)).expect("start");
    (a, Box::new(ih))
}

/// Recomputes the envelope mac of a message to the initiator after an edit,
/// so only the edit is tested.
fn reseal(k: &Known, msg: &mut [u8]) {
    let key = mac_key(&Domains::v02().expect("domains"), k.spki).expect("mac key");
    let off = msg.len() - 32;
    let mac = envelope_mac(&key, msg).expect("mac");
    msg[off..off + 16].copy_from_slice(&mac);
}

fn flipped<const N: usize>(k: &Known, msg: &[u8; N], at: usize, mac: bool) -> Box<[u8; N]> {
    let mut m = Box::new(*msg);
    m[at] ^= 1;
    if mac {
        reseal(k, &mut *m);
    }
    m
}

/// The CookieReply to `msg` (its mac as associated data) for `sid`.
fn cookie_reply(k: &Known, msg: &[u8], sid: [u8; 4]) -> Box<[u8; COOKIE_REPLY_LEN]> {
    let mac: [u8; 16] = msg[msg.len() - 32..msg.len() - 16].try_into().expect("16");
    let mut out = Box::new([0u8; COOKIE_REPLY_LEN]);
    let value = Secret::copy_from(&k.reply_cookie);
    cookie::seal_cookie_reply(&cookie::cookie_key(k.spkr), sid, &[0x22; 24], &value, &mac, &mut out).expect("reply");
    out
}


// ---- the real KEMs, for the depth the client's calls reach ----

/// Decapsulation under a real McEliece secret key, as the client's
/// `RpDecaps` does it.
struct RealDecaps(&'static [u8; mce460896::SK_LEN]);

impl Decaps for RealDecaps {
    fn decaps(&mut self, sct: &[u8; SCT_LEN]) -> Result<Secret<SHK_LEN>, DecapsError> {
        let mut shk = Secret::<SHK_LEN>::zero();
        mce460896::decaps(self.0, sct, shk.expose_mut());
        Ok(shk)
    }
}

macro_rules! real_seams {
    ($sk:expr, $rng:expr) => {
        &mut Seams { decaps: &mut RealDecaps($sk), kyber: &mut Kyber512, mceliece: &mut McEliece460896, rng: $rng }
    };
}

/// A McEliece key pair from a label's seed, on a thread with room for
/// keygen's 1.1 MB of stack.
fn real_key(label: &'static str) -> (&'static [u8; SPK_LEN], &'static [u8; mce460896::SK_LEN]) {
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(move || {
            let seed = stream(label, 32);
            let mut pk: Box<[u8; SPK_LEN]> = vec![0u8; SPK_LEN].into_boxed_slice().try_into().expect("pk");
            let mut sk: Box<[u8; mce460896::SK_LEN]> =
                vec![0u8; mce460896::SK_LEN].into_boxed_slice().try_into().expect("sk");
            let mut rng = |b: &mut [u8]| {
                b.copy_from_slice(&seed[..b.len()]);
                Ok(())
            };
            mce460896::keypair(&mut rng, &mut pk, &mut sk).expect("keypair");
            (&*Box::leak(pk), &*Box::leak(sk))
        })
        .expect("keygen thread")
        .join()
        .expect("keygen")
}

fn main() {
    if !std::env::args().skip(1).eq(["--run"]) {
        eprintln!("usage: rp-residue --run");
        exit(2);
    }
    println!("RP-RESIDUE-CASES {CASES}");
    let k = Box::new(Known::new());
    let k = &*k;
    let d = Domains::v02().expect("domains");
    let x = exchange(k);
    let ck = ck_after_init_hello(k, &d, k.spkr, &*x.ih);
    let (osk, txkt) = osk_and_txkt(k, &d, ck, &*x.rh, &*x.ic);
    if osk != x.osk {
        fail("needle model: the OSK differs from the initiator's");
    }

    let mut scan =
        Scan { stack: OwnedStack::new(STACK), base: 0, cases: 0, failed: false, deepest: 0, unscrubbed: 0 };
    scan.base = scan.run(|| {});

    // The first control: a secret alive in the caller's frame while the
    // scrub runs below it is found afterwards.
    let control = Expect { forms: vec![(Form::Control, &k.control[..])], ..Expect::default() };
    let depth = scan.run(|| keep_above_scrub(&k.control));
    scan.check("control: kept secret not found in stack", scan.left(&control, depth)[Form::Control as usize] > 0);
    scan.cases += 1;

    let (cookie, esk, ck, txkt) = (k.cookie(), &k.esk[..], &ck[..], &txkt[..]);
    let (kyber_ss, mce_i, mce_r) = (&k.kyber_ss[..], &k.mce_ss_i[..], &k.mce_ss_r[..]);
    let fresh = || Arena::new(Initiator::new(&k.keys()).expect("initiator"));
    let in_hello = || started(k, &k.keys()).0;

    // start: a refused draw at each point (cookie 1, sidi 2, Kyber seed 3,
    // McEliece 4, jitter 5) aborts the handshake and keeps none of it.
    let start_forms = vec![(Form::Cookie, cookie), (Form::Esk, esk), (Form::MceSs, mce_i), (Form::Ck, ck)];
    for (name, fail_at) in [("start.rng-sidi", 2), ("start.rng-kyber", 3), ("start.rng-mceliece", 4), ("start.rng-jitter", 5)] {
        let e = Expect { forms: start_forms.clone(), ..Expect::default() };
        let (r, mut a) = scan.case(name, fresh, &e, |ini| {
            ini.start(&k.keys(), 0, seams!(k, &mut Draws::new(&k.draws, Some(fail_at)), false)).map(|_| ())
        });
        scan.check(&format!("{name}: returned {r:?}, want Err(Rng)"), r == Some(Err(Error::Rng)));
        scan.check(&format!("{name}: the state advanced"), a.get_mut().state().phase() == Phase::Idle);
    }
    {
        let e = Expect { forms: start_forms.clone(), gone: vec![], kept: vec![Form::Cookie, Form::Esk, Form::Ck] };
        let (r, _) = scan.case("start.ok", fresh, &e, |ini| {
            ini.start(&k.keys(), 0, seams!(k, &mut Draws::new(&k.draws, None), false))
        });
        scan.check("start.ok: refused", matches!(r, Some(Ok(ih)) if ih == *x.ih));
    }

    // handle_resp_hello, in SentInitHello. A refusal keeps the handshake
    // (I7.3) and none of what it computed.
    let rh_forms = vec![
        (Form::Cookie, cookie),
        (Form::Esk, esk),
        (Form::Ck, ck),
        (Form::KyberSs, kyber_ss),
        (Form::MceSs, mce_r),
        (Form::Txkt, txkt),
    ];
    let held = vec![Form::Cookie, Form::Esk, Form::Ck];
    let refusals = [
        // auth (offset 970) flipped, the mac not recomputed
        ("resp-hello.bad-mac", flipped(k, &x.rh, 970, false), 2, None, false, Error::BadMac),
        // sidi (offset 8), resealed
        ("resp-hello.unknown-session", flipped(k, &x.rh, 8, true), 2, None, false, Error::UnknownPeer),
        ("resp-hello.expired", x.rh.clone(), REJECT_AFTER_TIME_NS, None, false, Error::UnknownPeer),
        ("resp-hello.rng", x.rh.clone(), 2, Some(1), false, Error::Rng),
        ("resp-hello.decaps-refused", x.rh.clone(), 2, None, true, Error::Decaps(DecapsError::Refused)),
        ("resp-hello.tampered", flipped(k, &x.rh, 970, true), 2, None, false, Error::Auth),
    ];
    for (name, rh, now, fail_at, refuse, want) in refusals {
        let e = Expect { forms: rh_forms.clone(), gone: vec![], kept: held.clone() };
        let (r, mut a) = scan.case(name, in_hello, &e, |ini| {
            let draws = &mut Draws::new(&k.draws[200..], fail_at);
            ini.handle_resp_hello(&k.keys(), &*rh, now, seams!(k, draws, refuse)).err()
        });
        scan.check(&format!("{name}: returned {r:?}, want {want:?}"), r == Some(Some(want)));
        scan.check(&format!("{name}: the state advanced"), a.get_mut().state().phase() == Phase::SentInitHello);
    }
    {
        // A RespHello from the responder the initiator is not pinned to: its
        // own chain, the same shared keys.
        let (_, wih) = started(k, &k.wrong_keys());
        let wck = ck_after_init_hello(k, &d, k.spkr_other, &*wih);
        let mut forms = rh_forms.clone();
        forms[2] = (Form::Ck, &wck[..]);
        let e = Expect { forms, gone: vec![], kept: held.clone() };
        let (r, _) = scan.case("resp-hello.wrong-key", || started(k, &k.wrong_keys()).0, &e, |ini| {
            let draws = &mut Draws::new(&k.draws[200..], None);
            ini.handle_resp_hello(&k.wrong_keys(), &*x.rh, 2, seams!(k, draws, false)).err()
        });
        scan.check(&format!("resp-hello.wrong-key: returned {r:?}, want Auth"), r == Some(Some(Error::Auth)));
    }
    {
        // Accepted: ck and eski are wiped from the state, tkr joins it.
        let e = Expect { forms: rh_forms.clone(), gone: vec![Form::Esk, Form::Ck], kept: vec![Form::Cookie, Form::Txkt] };
        let (r, _) = scan.case("resp-hello.ok", in_hello, &e, |ini| {
            let draws = &mut Draws::new(&k.draws[200..], None);
            ini.handle_resp_hello(&k.keys(), &*x.rh, 2, seams!(k, draws, false))
        });
        scan.check(
            "resp-hello.ok: refused",
            matches!(&r, Some(Ok((ic, o))) if ic == &*x.ic && o.expose()[..] == osk[..]),
        );
    }

    // handle_empty_data, in SentInitConf (or after one was accepted).
    let confirmed = |accept_first: bool| {
        let (mut a, _) = started(k, &k.keys());
        let draws = &mut Draws::new(&k.draws[200..], None);
        a.get_mut().handle_resp_hello(&k.keys(), &*x.rh, 2, seams!(k, draws, false)).expect("InitConf");
        if accept_first {
            a.get_mut().handle_empty_data(&*x.ed, 4).expect("EmptyData");
        }
        a
    };
    let ed_forms = vec![(Form::Cookie, cookie), (Form::Txkt, txkt)];
    let live = vec![Form::Cookie, Form::Txkt];
    for (name, ed, accept_first, want) in [
        // sid (offset 4), resealed
        ("empty-data.unknown-session", flipped(k, &x.ed, 4, true), false, Some(Error::UnknownPeer)),
        // auth (offset 16), resealed
        ("empty-data.tampered", flipped(k, &x.ed, 16, true), false, Some(Error::Auth)),
        ("empty-data.replayed", x.ed.clone(), true, Some(Error::UnknownPeer)),
        ("empty-data.ok", x.ed.clone(), false, None),
    ] {
        // The handshake is wiped once an EmptyData is accepted.
        let e = if accept_first || want.is_none() {
            Expect { forms: ed_forms.clone(), gone: live.clone(), kept: vec![] }
        } else {
            Expect { forms: ed_forms.clone(), gone: vec![], kept: live.clone() }
        };
        let (r, _) = scan.case(name, || confirmed(accept_first), &e, |ini| ini.handle_empty_data(&*ed, 4).err());
        scan.check(&format!("{name}: returned {r:?}, want {want:?}"), r == Some(want));
    }

    // handle_cookie_reply, in SentInitHello.
    let sidi: [u8; 4] = x.ih[4..8].try_into().expect("sidi");
    let mut other_sid = sidi;
    other_sid[0] ^= 1;
    let cr_forms =
        vec![(Form::Cookie, cookie), (Form::Esk, esk), (Form::Ck, ck), (Form::ReplyCookie, &k.reply_cookie[..])];
    for (name, reply, want) in [
        // Sealed to another message's mac (offset 1060): it does not open.
        ("cookie-reply.wrong-mac", cookie_reply(k, &flipped(k, &x.ih, 1060, false)[..], sidi), Some(Error::Auth)),
        ("cookie-reply.unknown-session", cookie_reply(k, &x.ih[..], other_sid), Some(Error::UnknownPeer)),
        ("cookie-reply.ok", cookie_reply(k, &x.ih[..], sidi), None),
    ] {
        let e = if want.is_none() {
            // The new value replaces the old, which is wiped.
            Expect { forms: cr_forms.clone(), gone: vec![Form::Cookie], kept: vec![Form::ReplyCookie, Form::Esk, Form::Ck] }
        } else {
            Expect { forms: cr_forms.clone(), gone: vec![], kept: held.clone() }
        };
        let (r, _) = scan.case(name, in_hello, &e, |ini| ini.handle_cookie_reply(&*reply, 10).err());
        scan.check(&format!("{name}: returned {r:?}, want {want:?}"), r == Some(want));
    }

    {
        // A handshake past its lifetime is dropped by tick, and wiped.
        let e = Expect { forms: cr_forms[..3].to_vec(), gone: held.clone(), kept: vec![] };
        let (r, mut a) = scan.case("tick.expired", in_hello, &e, |ini| ini.tick(REJECT_AFTER_TIME_NS).is_none());
        scan.check("tick.expired: retransmitted", r == Some(true) && a.get_mut().state().phase() == Phase::Idle);
    }

    // The real KEMs, as the client calls them: how deep `start` and an
    // accepted `handle_resp_hello` reach (McEliece decapsulation scrubs 96
    // KiB below itself). Their secrets are not known here; the scrubbed
    // runs only check that the calls complete.
    {
        let (pki, ski) = real_key("real-initiator");
        let (pkr, skr) = real_key("real-responder");
        let keys = InitiatorKeys { spki: pki, spkr: pkr };
        let draws = stream("real-draws", 1 << 18);
        let real_started = || {
            let mut a = Arena::new(Initiator::new(&keys).expect("initiator"));
            let ih = a.get_mut().start(&keys, 0, real_seams!(ski, &mut Draws::new(&draws, None))).expect("start");
            (a, ih)
        };
        let (_, ih) = real_started();
        let mut r = Responder::new(pkr, &[pki], &mut Draws::new(&stream("real-responder-draws", 4096), None)).expect("responder");
        r.tick(0, &mut Draws::new(&stream("real-biscuit", 64), None)).expect("biscuit key");
        let mut rh = Box::new([0u8; RESP_HELLO_LEN]);
        let rdraws = stream("real-responder-hello", 1 << 18);
        r.handle_init_hello(&ih, 1, real_seams!(skr, &mut Draws::new(&rdraws, None)), &mut rh).expect("RespHello");

        let e = Expect::default();
        let fresh_real = || Arena::new(Initiator::new(&keys).expect("initiator"));
        let (s, _) = scan.case("real.start", fresh_real, &e, |ini| {
            ini.start(&keys, 0, real_seams!(ski, &mut Draws::new(&draws, None))).is_ok()
        });
        scan.check("real.start: refused", s == Some(true));
        let (s, _) = scan.case("real.resp-hello", || real_started().0, &e, |ini| {
            ini.handle_resp_hello(&keys, &*rh, 2, real_seams!(ski, &mut Draws::new(&k.draws[200..], None))).is_ok()
        });
        scan.check("real.resp-hello: refused", s == Some(true));
    }

    // The second control: without the scrub, the same calls leave residue.
    println!("RP-RESIDUE-DEEPEST {}", scan.deepest);
    println!("RP-RESIDUE-UNSCRUBBED {}", scan.unscrubbed);
    scan.check("unscrubbed: no residue without the scrub; the scrub is not what clears it", scan.unscrubbed > 0);
    scan.check(&format!("{} cases run, {CASES} planned", scan.cases), scan.cases == CASES);
    if scan.failed {
        exit(1);
    }
    println!("RP-RESIDUE-DONE {}", scan.cases);
}
