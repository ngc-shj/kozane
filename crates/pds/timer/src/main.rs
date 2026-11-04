//! Timer PD: the ARM generic timer's EL1 physical timer, which seL4 exports
//! to EL0 (CONFIG_EXPORT_PTMR_USER; the kernel keeps the virtual timer),
//! notifies `data`, `hs`, `ingress`, `pq` and `tls` once per second
//! (M9 plan C14), and `audit`, whose count of those ticks is the heartbeat
//! (C3). Notify-only by construction (L1 timer exemption): it takes
//! no PPCs, and its peers cannot notify it, so nothing an attacker controls
//! can reach it.
//!
//! The export is one EL1 register for every thread, so no capability can
//! confine the timer to this PD: that is D13's code-property gate. No other
//! PD's executable code holds a timer write (tools/timer-scan, in
//! `package`), and none may map executable memory (laws).

#![no_std]
#![no_main]

use core::arch::asm;

use layout::timer as ch;
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain};

/// CNTP_CTL_EL0: ENABLE, interrupt not masked (IMASK clear).
const CTL_ENABLE: u64 = 1;
/// CNTP_CTL_EL0.ISTATUS: the timer condition is met.
const CTL_ISTATUS: u64 = 1 << 2;

/// Marks an image built with `fault-inject` (M7 plan C8): tools/release.py
/// refuses one that holds it.
#[cfg(feature = "fault-inject")]
#[used]
static FAULT_INJECT_VARIANT: [u8; 27] = *b"KOZANE-FAULT-INJECT-VARIANT";

#[cfg(feature = "fault-inject")]
const FAULT_TICK: u32 = 30;

const DEVICE: Channel = Channel::new(ch::CH_DEVICE);
const PEERS: [Channel; 6] = [
    Channel::new(ch::CH_DATA),
    Channel::new(ch::CH_HS),
    Channel::new(ch::CH_INGRESS),
    Channel::new(ch::CH_PQ),
    Channel::new(ch::CH_TLS),
    Channel::new(ch::CH_AUDIT),
];

fn cntfrq() -> u64 {
    let v: u64;
    // SAFETY: reads a system register exported to EL0; no memory access.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn cntpct() -> u64 {
    let v: u64;
    // SAFETY: as in `cntfrq`.
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn cntp_ctl() -> u64 {
    let v: u64;
    // SAFETY: CNTP_CTL_EL0 is exported to EL0 (EL0PTEN); no memory access.
    unsafe { asm!("mrs {}, cntp_ctl_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn set_cntp_cval(cval: u64) {
    // SAFETY: as in `cntp_ctl`; it only reprograms this timer's compare value.
    unsafe { asm!("msr cntp_cval_el0, {}", "isb", in(reg) cval, options(nomem, nostack, preserves_flags)) };
}

fn set_cntp_ctl(ctl: u64) {
    // SAFETY: as in `set_cntp_cval`.
    unsafe { asm!("msr cntp_ctl_el0, {}", "isb", in(reg) ctl, options(nomem, nostack, preserves_flags)) };
}

struct Timer {
    /// Counter ticks per tick: the counter frequency, so one tick a second.
    period: u64,
    /// The compare value of the next tick. Advancing it by `period` from
    /// the previous deadline, not from now, keeps the rate free of drift.
    deadline: u64,
    #[cfg(feature = "fault-inject")]
    ticks: u32,
}

impl Timer {
    fn arm(&self) {
        set_cntp_cval(self.deadline);
        set_cntp_ctl(CTL_ENABLE);
    }
}

impl Handler for Timer {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(DEVICE) {
            if cntp_ctl() & CTL_ISTATUS != 0 {
                // A late interrupt skips the ticks it missed instead of
                // bursting them: the peers count seconds, not interrupts.
                let now = cntpct();
                self.deadline = self.deadline.saturating_add(self.period);
                if self.deadline <= now {
                    self.deadline = now.saturating_add(self.period);
                }
                self.arm();
                for peer in PEERS {
                    peer.notify();
                }
                // M7 plan C8's selftest variant: the timer faults on its
                // FAULT_TICK-th tick, once the system is up.
                #[cfg(feature = "fault-inject")]
                {
                    self.ticks = self.ticks.saturating_add(1);
                    if self.ticks == FAULT_TICK {
                        panic!("fault-inject: timer");
                    }
                }
            }
            let _ = DEVICE.irq_ack();
        }
        Ok(())
    }
}

#[protection_domain]
fn init() -> Timer {
    boot_stage::run_init(|_| start())
}

fn start() -> Timer {
    let period = cntfrq();
    if period == 0 {
        panic!("timer: the counter frequency is unset");
    }
    let timer = Timer {
        period,
        deadline: cntpct().saturating_add(period),
        #[cfg(feature = "fault-inject")]
        ticks: 0,
    };
    timer.arm();
    timer
}
