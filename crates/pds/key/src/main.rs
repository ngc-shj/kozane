//! Key oracle PD (plan C10, laws L1/L2): passive, device-less, and the only
//! PD that maps the secrets region. Validates it against the compiled
//! configuration at boot; afterwards answers the fixed-size requests defined
//! in `key-core`, each caller limited to its row of the caller → label table
//! (`hs` is the only caller). A failed boot leaves it Unavailable (M5 plan
//! C6): no secret held, every call answered with the boot error's code,
//! which `hs` audits (`key` itself has no audit ring and no console).

#![no_std]
#![no_main]

use core::ptr::NonNull;

use key_core::{BootError, Bucket, Caller, ERR_BAD_REQUEST, KEY_BURST, KEY_INTERVAL_NS, MAX_WORDS, Oracle};
use layout::key as ch;
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain, with_msg_regs,
    with_msg_regs_mut,
};
use wg_core::crypto::{self, Key32};

const HS: Channel = Channel::new(ch::CH_HS);

fn caller(channel: Channel) -> Option<Caller> {
    (channel == HS).then_some(Caller::Hs)
}

/// RNDR samples mixed into the boot seed.
const SEED_SAMPLES: usize = 4;

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
    let peers = config::PEERS.iter().map(|p| &p.public);
    let blob = key_core::validate(region(), &config::GATEWAY_PUBLIC, peers)?;

    let mut samples = [0u8; SEED_SAMPLES * 8];
    if !cpu::fill_random(&mut samples) {
        zeroize::Zeroize::zeroize(&mut samples);
        return Err(BootError::RndrUnavailable);
    }
    let seed = crypto::hash(&[blob.boot_seed(), &samples, &cpu::cntpct().to_le_bytes()]);
    zeroize::Zeroize::zeroize(&mut samples);
    let mut seed = seed.map_err(|_| BootError::SeedDerivation)?;
    let seed_key = Key32::copy_from(&seed);
    zeroize::Zeroize::zeroize(&mut seed);
    Ok(Oracle::new(blob, seed_key))
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
