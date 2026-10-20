//! Key oracle PD (plan C10, laws L1/L2): passive, device-less, and the only
//! PD that maps the secrets region. Validates it against the compiled
//! configuration at boot and halts on any mismatch; afterwards answers the
//! fixed-size requests defined in `key-core`, each caller limited to its row
//! of the caller → label table (`hs` is the only caller).

#![no_std]
#![no_main]

use core::ptr::NonNull;

use key_core::{Bucket, Caller, ERR_BAD_REQUEST, KEY_BURST, KEY_INTERVAL_NS, MAX_WORDS, Oracle};
use layout::key as ch;
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, debug_println, memory_region_symbol, protection_domain,
    with_msg_regs, with_msg_regs_mut,
};
use wg_core::crypto::{self, Key32};

const HS: Channel = Channel::new(ch::CH_HS);

fn caller(channel: Channel) -> Option<Caller> {
    (channel == HS).then_some(Caller::Hs)
}

/// RNDR samples mixed into the boot seed.
const SEED_SAMPLES: usize = 4;

struct Key {
    oracle: Oracle<'static>,
    bucket: Bucket,
}

fn halt(msg: &str) -> ! {
    debug_println!("key: {msg}");
    panic!("key: halted");
}

fn region() -> &'static [u8] {
    let p: NonNull<[u8]> = memory_region_symbol!(secrets: *mut [u8], n = secret_blob::REGION_SIZE);
    // SAFETY: the secrets region is mapped read-only into this PD alone
    // (laws L1/L2, checked by tools/laws) for the life of the system.
    unsafe { p.as_ref() }
}

#[protection_domain]
fn init() -> Key {
    let peers = config::PEERS.iter().map(|p| &p.public);
    let blob = key_core::validate(region(), &config::GATEWAY_PUBLIC, peers).unwrap_or_else(|e| halt(e.message()));

    let mut samples = [0u8; SEED_SAMPLES * 8];
    if !cpu::fill_random(&mut samples) {
        halt("RNDR unavailable");
    }
    let mut seed = crypto::hash(&[blob.boot_seed(), &samples, &cpu::cntpct().to_le_bytes()])
        .unwrap_or_else(|_| halt("boot seed derivation failed"));
    samples.fill(0);
    let seed_key = Key32::copy_from(&seed);
    seed.fill(0);
    debug_println!("key: secrets valid ({} peers)", blob.peer_count());
    Key { oracle: Oracle::new(blob, seed_key), bucket: Bucket::new(KEY_BURST, KEY_INTERVAL_NS) }
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
        let (label, n) = self.oracle.handle(
            caller(channel),
            &mut self.bucket,
            cpu::now_ns(),
            msg_info.label(),
            req.get(..count).unwrap_or(&[]),
            &mut reply,
        );
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
