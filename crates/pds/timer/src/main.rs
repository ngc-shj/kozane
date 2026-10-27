//! Timer PD: an sp804 in periodic mode notifies `data`, `hs`, `ingress`,
//! `pq` and `tls` once per second. Notify-only by construction (L1 timer exemption): it
//! maps only its own device page, takes no PPCs, and its peers cannot
//! notify it, so nothing an attacker controls can reach it.

#![no_std]
#![no_main]

use core::ptr::NonNull;

use layout::{TIMER_FREQ_HZ, timer as ch};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, protection_domain, var};

// sp804 timer 1 registers (ARM DDI 0271).
const LOAD: usize = 0x00;
const CONTROL: usize = 0x08;
const INT_CLR: usize = 0x0c;
const MIS: usize = 0x14;

const CTRL_ENABLE: u32 = 1 << 7;
const CTRL_PERIODIC: u32 = 1 << 6;
const CTRL_INT_ENABLE: u32 = 1 << 5;
const CTRL_32BIT: u32 = 1 << 1;

/// Marks an image built with `fault-inject` (M7 plan C8): tools/release.py
/// refuses one that holds it.
#[cfg(feature = "fault-inject")]
#[used]
static FAULT_INJECT_VARIANT: [u8; 27] = *b"KOZANE-FAULT-INJECT-VARIANT";

#[cfg(feature = "fault-inject")]
const FAULT_TICK: u32 = 30;

const DEVICE: Channel = Channel::new(ch::CH_DEVICE);
const PEERS: [Channel; 5] = [
    Channel::new(ch::CH_DATA),
    Channel::new(ch::CH_HS),
    Channel::new(ch::CH_INGRESS),
    Channel::new(ch::CH_PQ),
    Channel::new(ch::CH_TLS),
];

struct Sp804 {
    base: NonNull<u32>,
}

impl Sp804 {
    fn write(&self, offset: usize, value: u32) {
        // SAFETY: `base` is this PD's uncached mapping of the sp804 page and
        // `offset` is one of the register constants above, all in the page.
        unsafe { self.base.byte_add(offset).write_volatile(value) }
    }

    fn read(&self, offset: usize) -> u32 {
        // SAFETY: as in `write`.
        unsafe { self.base.byte_add(offset).read_volatile() }
    }

    fn start_periodic(&self, ticks: u32) {
        self.write(CONTROL, 0);
        self.write(INT_CLR, 1);
        self.write(LOAD, ticks);
        self.write(CONTROL, CTRL_ENABLE | CTRL_PERIODIC | CTRL_INT_ENABLE | CTRL_32BIT);
    }
}

struct Timer {
    device: Sp804,
    #[cfg(feature = "fault-inject")]
    ticks: u32,
}

impl Handler for Timer {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(DEVICE) {
            if self.device.read(MIS) & 1 != 0 {
                self.device.write(INT_CLR, 1);
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
    let vaddr = *var!(timer_mmio_vaddr: usize = 0);
    let base = NonNull::new(vaddr as *mut u32).unwrap_or_else(|| panic!("timer: no mmio mapping"));
    let device = Sp804 { base };
    device.start_periodic(TIMER_FREQ_HZ);
    Timer {
        device,
        #[cfg(feature = "fault-inject")]
        ticks: 0,
    }
}
