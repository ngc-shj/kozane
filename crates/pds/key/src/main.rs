//! Key oracle PD (plan C10, laws L1/L2): passive, device-less, and the only
//! PD that maps the secrets region, which holds the blob sealed (M5 plan
//! C11). At boot it unseals it through `tpm` (its one PPC callee, C9) into
//! its own memory and validates it against the compiled configuration;
//! afterwards it answers the fixed-size requests defined in `key-core`,
//! each caller limited to its row of the caller → label table (`hs` is the
//! only caller). The whole unseal runs in `init`, so no caller reaches
//! `key` before it is done (S18). A failed boot leaves it Unavailable (M5
//! plan C6): no secret held, every call answered with the boot error's
//! code, which `hs` audits (`key` itself has no audit ring and no console).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use key_core::{BootEntropy, BootError, Bucket, Caller, ERR_BAD_REQUEST, KEY_BURST, KEY_INTERVAL_NS, MAX_WORDS, Oracle};
use layout::key as ch;
use layout::tpm::{self as ipc, MSG_BYTES, MSG_WORDS};
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs,
    with_msg_regs_mut,
};
use tpm2::boot::Transport;
use tpm2::envelope::Kind;
use zeroize::Zeroize;

const HS: Channel = Channel::new(ch::CH_HS);
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
struct Plaintext(UnsafeCell<[u8; secret_blob::REGION_SIZE]>);

// SAFETY: a PD runs one thread, and only `boot` (once, from init) touches
// the buffer.
unsafe impl Sync for Plaintext {}

static PLAINTEXT: Plaintext = Plaintext(UnsafeCell::new([0; secret_blob::REGION_SIZE]));

fn caller(channel: Channel) -> Option<Caller> {
    (channel == HS).then_some(Caller::Hs)
}

/// The boot seed's entropy: RNDR and CNTPCT.
struct Hw;

impl BootEntropy for Hw {
    fn fill_random(&mut self, out: &mut [u8]) -> bool {
        cpu::fill_random(out)
    }

    fn cntpct(&mut self) -> u64 {
        cpu::cntpct()
    }
}

enum Key {
    Ready { oracle: Oracle<'static>, bucket: Bucket },
    /// The boot failed with `BootError::code` `code`; nothing else is kept.
    Unavailable { code: u32 },
}

fn region() -> &'static [u8] {
    let p: NonNull<[u8]> = memory_region_symbol!(secrets: *mut [u8], n = secret_blob::REGION_SIZE);
    // SAFETY: the secrets region is mapped read-only into this PD alone
    // (laws L1/L2, checked by tools/laws) for the life of the system.
    unsafe { p.as_ref() }
}

fn boot() -> Result<Oracle<'static>, BootError> {
    let buf = PLAINTEXT.0.get();
    // SAFETY: init runs once and is the only caller; no other reference to
    // the buffer exists while this one is used.
    tpm2::boot::unseal(&mut Ppc, region(), Kind::Key, unsafe { &mut *buf })?;
    // SAFETY: as above. From here the buffer is only read, for the life of
    // the system (the oracle borrows it).
    let plain: &'static [u8] = unsafe { &*buf };
    let peers = config::PEERS.iter().map(|p| &p.public);
    // Every failure after the unseal wipes the plaintext, not only
    // validation's: an Unavailable `key` holds no secret (M5 plan C6).
    Oracle::boot(plain, &config::GATEWAY_PUBLIC, peers, &mut Hw).inspect_err(|_| {
        // SAFETY: the failed boot's borrow ended with its error, and nothing
        // reads the buffer again.
        unsafe { &mut *buf }.zeroize();
    })
}

#[protection_domain]
fn init() -> Key {
    match boot() {
        Ok(oracle) => Key::Ready { oracle, bucket: Bucket::new(KEY_BURST, KEY_INTERVAL_NS) },
        Err(e) => Key::Unavailable { code: e.code() },
    }
}

impl Handler for Key {
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
            Key::Ready { oracle, bucket } => oracle.handle(
                caller(channel),
                bucket,
                cpu::now_ns(),
                msg_info.label(),
                req.get(..count).unwrap_or(&[]),
                &mut reply,
            ),
            Key::Unavailable { code } => key_core::unavailable(caller(channel), *code, &mut reply),
        };
        // Overwrite every register beyond this reply, so no part of an
        // earlier, longer reply is handed back to `hs`. The reply words
        // themselves stay in `key`'s own IPC buffer until the next call; only
        // `key` can read that buffer, and it holds the static secrets anyway.
        // `hs` zeroes its copy after use.
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
