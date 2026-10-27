//! The one SMC the supervisor makes (M7 plan C8): PSCI SYSTEM_RESET, through
//! the SMC capability Microkit gives a pd with `smc="true"`, and the record
//! write before it. Nothing else in this crate is `unsafe`, names a
//! capability or an SMC function (tools/supervisor-allowlist).

use core::ptr::NonNull;

use supervisor_core::RECORD_WORDS;

/// SMCCC function ID of PSCI SYSTEM_RESET.
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
/// Microkit's slot for the SMC capability (libmicrokit's ARM_SMC_CAP).
const ARM_SMC_CAP: sel4::CPtrBits = 7;

/// Writes the fault record `audit` prints.
pub fn write_record(record: NonNull<[u64; RECORD_WORDS]>, words: [u64; RECORD_WORDS]) {
    // SAFETY: the record page is mapped rw into this PD and r into `audit`
    // alone (laws), page-aligned, for the life of the system.
    unsafe { record.as_ptr().write_volatile(words) };
}

/// Resets the machine. TF-A's PSCI does not return; if it ever did, the
/// supervisor spins, so no fault is ever answered and no child resumes.
pub fn system_reset() -> ! {
    let args = sel4::sys::seL4_ARM_SMCContext { x0: PSCI_SYSTEM_RESET, ..Default::default() };
    let mut response = sel4::sys::seL4_ARM_SMCContext::default();
    sel4::with_ipc_buffer_mut(|ipc| {
        let _ = ipc.inner_mut().seL4_ARM_SMC_Call(ARM_SMC_CAP, &args, &mut response);
    });
    loop {
        core::hint::spin_loop();
    }
}
