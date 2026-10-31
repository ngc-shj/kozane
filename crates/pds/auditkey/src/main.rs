//! Audit checkpoint signer PD (M8 plan C10, D7; laws L1/L2 as amended by
//! C11): passive, device-less, and the only PD that maps the
//! `audit_secrets` region, which holds its Ed25519 seed sealed (envelope
//! kind `audit`). At boot it unseals it through `tpm`, the fourth raw
//! client, and reads the TPM's resetCount and restartCount with ReadClock
//! before its Done (the gate forwards ReadClock for this client alone); it
//! draws the boot ID from `rng` and takes the SRK Name its envelope pins.
//! The whole boot runs in `init`, and its last act, success or not, is one
//! notification to `audit`, which calls `auditkey` only after it (F32).
//! Afterwards it answers `audit`'s `SIGN` (`auditkey_core`): every call
//! runs on `audit`'s scheduling context. A failed boot leaves it
//! Unavailable: no secret held, every call answered with the boot error's
//! code, which `audit` prints (`auditkey` has no audit ring and no console).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use auditkey_core::{BOOT_ID_LEN, BootError, Caller, Identity, Oracle, SRK_NAME_LEN};
use layout::auditkey as ch;
use layout::tpm::{self as ipc, MSG_BYTES, MSG_WORDS};
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs,
    with_msg_regs_mut,
};
use tpm2::boot::{Clock, Transport, UnsealError};
use tpm2::envelope::{Envelope, Kind};
use zeroize::Zeroize;

const AUDIT: Channel = Channel::new(ch::CH_AUDIT);
const TPM: Channel = Channel::new(ch::CH_TPM);

const _: () = assert!(SRK_NAME_LEN == tpm2_wire::NAME_LEN);
/// Every reply fits the registers `handle` copies back.
const MAX_WORDS: usize = ch::SIGN_REPLY_WORDS;
const _: () = assert!(ch::SIGN_REQ_WORDS <= MAX_WORDS && MAX_WORDS <= MSG_WORDS);

/// `tpm` over PPC (M5 plan C9): one TPM command or response per call, its
/// byte length in the label. The registers are zeroed after each call.
struct Ppc;

impl Transport for Ppc {
    fn call(&mut self, label: u64, req: &[u8], rsp: &mut [u8; MSG_BYTES]) -> (u64, usize) {
        let mut words = [0u64; MSG_WORDS];
        let n = ipc::pack(req, &mut words).unwrap_or(0);
        with_msg_regs_mut(|mrs| {
            for (dst, src) in mrs.iter_mut().zip(words.iter().take(n)) {
                *dst = *src;
            }
        });
        let info = TPM.pp_call(MessageInfo::new(label, n));
        let count = info.count().min(MSG_WORDS);
        with_msg_regs(|mrs| {
            for (dst, src) in words.iter_mut().zip(mrs.iter().take(count)) {
                *dst = *src;
            }
        });
        let carried = count.saturating_mul(8);
        let ok = ipc::unpack(words.get(..count).unwrap_or(&[]), carried, rsp).is_some();
        words.fill(0);
        with_msg_regs_mut(|mrs| mrs.iter_mut().take(MSG_WORDS).for_each(|w| *w = 0));
        (info.label(), if ok { carried } else { 0 })
    }

    fn now_ns(&mut self) -> u64 {
        cpu::now_ns()
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        ENTROPY.fill(out)
    }
}

/// The unsealed blob: PD-private memory, never the secrets region, which
/// stays read-only ciphertext.
struct Plaintext(UnsafeCell<[u8; secret_blob::audit::REGION_SIZE]>);

// SAFETY: a PD runs one thread, and only `boot` (once, from init) touches
// the buffer mutably; afterwards the oracle only reads it.
unsafe impl Sync for Plaintext {}

static PLAINTEXT: Plaintext = Plaintext(UnsafeCell::new([0; secret_blob::audit::REGION_SIZE]));

fn caller(channel: Channel) -> Option<Caller> {
    (channel == AUDIT).then_some(Caller::Audit)
}

enum AuditKey {
    Ready(Oracle<'static>),
    /// The boot failed with `BootError::code` `code`; nothing else is kept.
    Unavailable { code: u32 },
}

fn region() -> &'static [u8] {
    let p: NonNull<[u8]> = memory_region_symbol!(audit_secrets: *mut [u8], n = secret_blob::audit::REGION_SIZE);
    // SAFETY: the audit_secrets region is mapped read-only into this PD
    // alone (laws L1/L2, checked by tools/laws) for the life of the system.
    unsafe { p.as_ref() }
}

fn boot_error(e: UnsealError) -> BootError {
    match e {
        UnsealError::Rng => BootError::RngUnavailable,
        UnsealError::EnvelopeInvalid => BootError::EnvelopeInvalid,
        UnsealError::TpmUnavailable => BootError::TpmUnavailable,
        UnsealError::SrkMismatch => BootError::SrkMismatch,
        UnsealError::UnsealRefused => BootError::UnsealRefused,
        UnsealError::ResponseInvalid => BootError::TpmResponseInvalid,
        UnsealError::EnvelopeOpen => BootError::EnvelopeOpen,
        UnsealError::CapFailed => BootError::TpmCapFailed,
    }
}

fn boot() -> Result<Oracle<'static>, BootError> {
    let buf = PLAINTEXT.0.get();
    let mut clock = Clock::default();
    // SAFETY: init runs once and is the only caller; no other reference to
    // the buffer exists while this one is used. On an unseal failure the
    // buffer is all zero (tpm2::boot).
    tpm2::boot::unseal(&mut Ppc, region(), Kind::Audit, unsafe { &mut *buf }, Some(&mut clock))
        .map_err(boot_error)?;
    // SAFETY: as above. From here every failure wipes the buffer (here or in
    // `Oracle::boot`); on success the oracle borrows it read-only for the
    // life of the system.
    let plain: &'static mut [u8] = unsafe { &mut *buf };
    // The unseal checked this TPM's SRK against the envelope's pinned Name.
    let srk_name = match Envelope::parse(region(), Kind::Audit).map(|e| <[u8; SRK_NAME_LEN]>::try_from(e.srk_name())) {
        Ok(Ok(name)) => name,
        _ => {
            plain.zeroize();
            return Err(BootError::EnvelopeInvalid);
        }
    };
    let mut boot_id = [0u8; BOOT_ID_LEN];
    if !ENTROPY.fill(&mut boot_id) {
        plain.zeroize();
        return Err(BootError::RngUnavailable);
    }
    let identity = Identity { srk_name, boot_id, reset: clock.reset_count, restart: clock.restart_count };
    Oracle::boot(plain, identity)
}

/// Zeroes, with volatile writes, `auditkey_core::SCRUB_DEPTH` bytes of
/// stack below the caller's frame: where the unseal's frames or a `SIGN`
/// (Ed25519's expanded key and nonce) just ran. `tlskey`'s pattern.
#[inline(never)]
fn scrub_stack() {
    let mut area = [0u64; auditkey_core::SCRUB_DEPTH / 8];
    area.zeroize();
}

/// The unseal's salt and the boot ID (M7 plan C7): the DRBG `rng` seeds.
/// Empty when `rng` gave no seed: the unseal then fails on its salt (and
/// `tpm` still gets this PD's Failed).
static ENTROPY: rng_client::Global = rng_client::Global::new();

#[protection_domain]
fn init() -> AuditKey {
    boot_stage::run_init(|_| start())
}

fn start() -> AuditKey {
    ENTROPY.set(rng_client::Entropy::instantiate(Channel::new(ch::CH_RNG)).ok());
    let booted = boot();
    scrub_stack();
    let state = match booted {
        Ok(oracle) => AuditKey::Ready(oracle),
        Err(e) => AuditKey::Unavailable { code: e.code() },
    };
    // The end of init, ready or Unavailable: `audit` calls only after this
    // (M8 plan C10, F32).
    AUDIT.notify();
    state
}

impl Handler for AuditKey {
    type Error = Infallible;

    fn protected(&mut self, channel: Channel, msg_info: MessageInfo) -> Result<MessageInfo, Self::Error> {
        let mut req = [0u64; MAX_WORDS];
        let count = msg_info.count();
        let mut reply = [0u64; MAX_WORDS];
        let (label, n) = if count > MAX_WORDS {
            (ch::BAD_REQUEST, 0)
        } else {
            with_msg_regs(|mrs| {
                for (dst, src) in req.iter_mut().zip(mrs.iter().take(count)) {
                    *dst = *src;
                }
            });
            let req = req.get(..count).unwrap_or(&[]);
            match self {
                AuditKey::Ready(oracle) => oracle.handle(caller(channel), msg_info.label(), req, &mut reply),
                AuditKey::Unavailable { code } => auditkey_core::unavailable(caller(channel), *code, &mut reply),
            }
        };
        // Ed25519's expanded key in the dead frames, whatever the outcome.
        scrub_stack();
        // Overwrite every register up to MAX_WORDS beyond this reply, so no
        // part of an earlier, longer reply is handed back to `audit`.
        with_msg_regs_mut(|mrs| {
            for (i, dst) in mrs.iter_mut().take(MAX_WORDS).enumerate() {
                *dst = if i < n { reply.get(i).copied().unwrap_or(0) } else { 0 };
            }
        });
        reply.fill(0);
        req.fill(0);
        Ok(MessageInfo::new(label, n))
    }
}
