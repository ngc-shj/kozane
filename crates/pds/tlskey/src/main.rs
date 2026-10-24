//! TLS signing oracle PD (M6 plan C12, laws L1/L2): passive, device-less,
//! and the only PD that maps the `tls_secrets` region, which holds the
//! blob sealed (M5 plan C11). At boot it unseals it through `tpm` (its one
//! PPC callee, C9) into its own memory and checks the scalar against the
//! compiled certificate; afterwards it answers the fixed-size requests
//! defined in `tlskey-core` (`tls` is the only caller). Every call runs on
//! `tls`'s scheduling context, so HTTPS never uses more CPU than `tls`'s
//! budget. The whole unseal runs in `init`, so no caller reaches `tlskey`
//! before it is done (S18). A failed boot leaves it Unavailable (M5 plan
//! C6): no secret held, every call answered with the boot error's code,
//! which `tls` audits before it halts (`tlskey` itself has no audit ring and
//! no console).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use layout::tlskey as ch;
use layout::tpm::{self as ipc, MSG_BYTES, MSG_WORDS};
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs,
    with_msg_regs_mut,
};
use tlskey_core::{BootError, Bucket, Caller, ERR_BAD_REQUEST, Hw, LABEL_TLS_SIGN, MAX_WORDS, Oracle};
use tpm2::boot::Transport;
use tpm2::envelope::Kind;
use zeroize::Zeroize;

const TLS: Channel = Channel::new(ch::CH_TLS);
const TPM: Channel = Channel::new(ch::CH_TPM);

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
        cpu::fill_random(out)
    }
}

/// The unsealed blob: PD-private memory, never the secrets region (M5
/// plan C11), which stays read-only ciphertext.
struct Plaintext(UnsafeCell<[u8; secret_blob::tls::REGION_SIZE]>);

// SAFETY: a PD runs one thread, and only `boot` (once, from init) touches
// the buffer mutably; afterwards the oracle only reads it.
unsafe impl Sync for Plaintext {}

static PLAINTEXT: Plaintext = Plaintext(UnsafeCell::new([0; secret_blob::tls::REGION_SIZE]));

fn caller(channel: Channel) -> Option<Caller> {
    (channel == TLS).then_some(Caller::Tls)
}

/// The boot seed's and each signature's hardware: RNDR and CNTPCT.
struct CpuHw;

impl Hw for CpuHw {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        cpu::fill_random(out)
    }

    fn cntpct(&mut self) -> u64 {
        cpu::cntpct()
    }
}

enum TlsKey {
    Ready { oracle: Oracle<'static>, bucket: Bucket },
    /// The boot failed with `BootError::code` `code`; nothing else is kept.
    Unavailable { code: u32 },
}

fn region() -> &'static [u8] {
    let p: NonNull<[u8]> = memory_region_symbol!(tls_secrets: *mut [u8], n = secret_blob::tls::REGION_SIZE);
    // SAFETY: the tls_secrets region is mapped read-only into this PD alone
    // (laws L1/L2, checked by tools/laws) for the life of the system.
    unsafe { p.as_ref() }
}

fn boot() -> Result<Oracle<'static>, BootError> {
    let buf = PLAINTEXT.0.get();
    // SAFETY: init runs once and is the only caller; no other reference to
    // the buffer exists while this one is used. On an unseal failure the
    // buffer is all zero (tpm2::boot).
    tpm2::boot::unseal(&mut Ppc, region(), Kind::Tls, unsafe { &mut *buf })?;
    // SAFETY: as above. `Oracle::boot` wipes the whole buffer on any of its
    // failures (M5 plan C6: an Unavailable key PD holds no secret); on
    // success it borrows it read-only for the life of the system.
    let plain: &'static mut [u8] = unsafe { &mut *buf };
    Oracle::boot(plain, &config::TLS_PUBLIC, &mut CpuHw)
}

/// Zeroes, with volatile writes, `tlskey_core::SCRUB_DEPTH` bytes of stack
/// below the caller's frame: where the boot's scalar check or a `TLS_SIGN`
/// (libcrux's P-256, SHA-256 and HMAC state) just ran. The
/// `tpm2::boot::scrub_session_stack` pattern.
#[inline(never)]
fn scrub_stack() {
    let mut area = [0u64; tlskey_core::SCRUB_DEPTH / 8];
    area.zeroize();
}

#[protection_domain]
fn init() -> TlsKey {
    let booted = boot();
    // The scalar check's P-256 frames held the scalar, accepted or refused
    // (M6 plan C5, F-N-b).
    scrub_stack();
    match booted {
        Ok(oracle) => TlsKey::Ready { oracle, bucket: Bucket::default() },
        Err(e) => TlsKey::Unavailable { code: e.code() },
    }
}

impl Handler for TlsKey {
    type Error = Infallible;

    fn protected(&mut self, channel: Channel, msg_info: MessageInfo) -> Result<MessageInfo, Self::Error> {
        let mut req = [0u64; MAX_WORDS];
        let count = msg_info.count();
        if count > MAX_WORDS {
            return Ok(MessageInfo::new(ERR_BAD_REQUEST, 0));
        }
        with_msg_regs(|mrs| {
            for (dst, src) in req.iter_mut().zip(mrs.iter().take(count)) {
                *dst = *src;
            }
        });
        let mut reply = [0u64; MAX_WORDS];
        let (label, n) = match self {
            TlsKey::Ready { oracle, bucket } => oracle.handle(
                caller(channel),
                bucket,
                cpu::now_ns(),
                &mut CpuHw,
                msg_info.label(),
                req.get(..count).unwrap_or(&[]),
                &mut reply,
            ),
            TlsKey::Unavailable { code } => tlskey_core::unavailable(caller(channel), *code, &mut reply),
        };
        if msg_info.label() == LABEL_TLS_SIGN {
            // The nonce candidates, K, V and the scalar's copies in the
            // dead P-256/HMAC frames (M6 plan C5), whatever the outcome.
            scrub_stack();
        }
        // Overwrite every register up to MAX_WORDS beyond this reply, so no
        // part of an earlier, longer reply is handed back to `tls`. The
        // reply words themselves stay in `tlskey`'s own IPC buffer until the
        // next call; only `tlskey` can read that buffer, and it holds the
        // scalar anyway. `tls` zeroes its copy after use.
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
