//! Timer PD: an sp804 in periodic mode notifies `data` and `hs` once per
//! second. Notify-only by construction (L1 timer exemption): it maps only
//! its own device page, takes no PPCs, and its peers cannot notify it, so
//! nothing an attacker controls can reach it.

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

const DEVICE: Channel = Channel::new(ch::CH_DEVICE);
const PEERS: [Channel; 2] = [Channel::new(ch::CH_DATA), Channel::new(ch::CH_HS)];

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
            }
            let _ = DEVICE.irq_ack();
        }
        Ok(())
    }
}

#[protection_domain]
fn init() -> Timer {
    let vaddr = *var!(timer_mmio_vaddr: usize = 0);
    let base = NonNull::new(vaddr as *mut u32).unwrap_or_else(|| panic!("timer: no mmio mapping"));
    let device = Sp804 { base };
    device.start_periodic(TIMER_FREQ_HZ);
    Timer { device }
}
