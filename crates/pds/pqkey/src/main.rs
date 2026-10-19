//! McEliece oracle PD (M3 plan C2, laws L1/L2): passive, device-less, and
//! the only PD that maps the `pq_secrets` region. Validates it against the
//! compiled configuration at boot (format, `H(spkm)`, a known-answer
//! decapsulation) and halts on any mismatch; afterwards answers the
//! fixed-size requests defined in `pqkey-core`, each caller limited to its
//! row of the caller → label table (`pq` is the only caller).

#![no_std]
#![no_main]

use core::ptr::NonNull;

use layout::pqkey as ch;
use pqkey_core::{BootEntropy, Bucket, Caller, ERR_BAD_REQUEST, MAX_WORDS, Oracle, PQ_KEY_BURST, PQ_KEY_INTERVAL_NS};
use sel4_microkit::{
    Channel, Handler, Infallible, MessageInfo, debug_println, memory_region_symbol, protection_domain,
    with_msg_regs, with_msg_regs_mut,
};

const PQ: Channel = Channel::new(ch::CH_PQ);

fn caller(channel: Channel) -> Option<Caller> {
    (channel == PQ).then_some(Caller::Pq)
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

struct PqKey {
    oracle: Oracle<'static>,
    bucket: Bucket,
}

fn halt(msg: &str) -> ! {
    debug_println!("pqkey: {msg}");
    panic!("pqkey: halted");
}

fn region() -> &'static [u8] {
    let p: NonNull<[u8]> = memory_region_symbol!(pq_secrets: *mut [u8], n = secret_blob::pq::REGION_SIZE);
    // SAFETY: the pq_secrets region is mapped read-only into this PD alone
    // (laws L1/L2, checked by tools/laws) for the life of the system.
    unsafe { p.as_ref() }
}

#[protection_domain]
fn init() -> PqKey {
    let oracle =
        Oracle::boot(region(), &config::GATEWAY_RP_HASH, &mut Hw).unwrap_or_else(|e| halt(e.message()));
    debug_println!("pqkey: secrets valid");
    PqKey { oracle, bucket: Bucket::new(PQ_KEY_BURST, PQ_KEY_INTERVAL_NS) }
}

impl Handler for PqKey {
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
        // earlier, longer request or reply is handed back to `pq`. The reply
        // words themselves stay in `pqkey`'s own IPC buffer until the next
        // call; only `pqkey` can read that buffer, and it holds the secret
        // key anyway. `pq` zeroes its copy after use.
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
