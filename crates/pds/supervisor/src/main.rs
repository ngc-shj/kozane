//! Supervisor PD (M7 plan C8, Re-plan R1): the Microkit parent of every
//! other PD, so every child's fault reaches it. Each fault is recorded on
//! the page `audit` reads, `audit` is notified (it runs above the
//! supervisor, so it prints before the next line here runs), and the
//! machine resets through PSCI. No fault is answered: the faulting child
//! never resumes. It reads only the child id and the fault label, maps only
//! its record page, and has one channel, out to `audit` (laws L1, L4 as
//! amended).

#![no_std]
#![no_main]

mod reset;

use core::ptr::NonNull;

use layout::supervisor as ch;
use sel4_microkit::{Channel, Child, Handler, Infallible, MessageInfo, memory_region_symbol, protection_domain};
use supervisor_core::{Action, RECORD_WORDS, Record, decide};

struct Supervisor {
    record: NonNull<[u64; RECORD_WORDS]>,
    audit: Channel,
    seq: u64,
}

#[protection_domain]
fn init() -> Supervisor {
    boot_stage::run_init(|_| start())
}

fn start() -> Supervisor {
    Supervisor {
        record: memory_region_symbol!(supervisor_record: *mut [u64; RECORD_WORDS]),
        audit: Channel::new(ch::CH_AUDIT),
        seq: 0,
    }
}

impl Handler for Supervisor {
    type Error = Infallible;

    fn fault(&mut self, child: Child, msg_info: MessageInfo) -> Result<Option<MessageInfo>, Self::Error> {
        self.seq = self.seq.wrapping_add(1);
        let r = Record {
            seq: self.seq,
            child: u32::try_from(child.index()).unwrap_or(u32::MAX),
            label: u32::try_from(msg_info.label()).unwrap_or(u32::MAX),
            lost: self.seq.saturating_sub(1),
        };
        reset::write_record(self.record, r.encode());
        self.audit.notify();
        match decide(child.index(), msg_info.label()) {
            Action::Reset => reset::system_reset(),
        }
    }
}
