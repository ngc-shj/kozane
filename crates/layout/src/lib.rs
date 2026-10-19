//! Sizes and channel numbers shared by PDs and `system/secureos.system`.
//! The .system file must agree with these (checked by this crate's tests).

#![no_std]

/// Slots per network ring; must be >= `NET_BUFFERS` (asserted in `ring::link`).
pub const NET_RING_SLOTS: usize = 64;
pub const NET_BUFFERS: usize = 64;
pub const NET_BUF_SIZE: usize = 2048;
pub const NET_REGION_SIZE: usize = NET_BUFFERS * NET_BUF_SIZE;

/// `audit` drains at most this many records per producer per notification.
pub const AUDIT_RING_SLOTS: usize = 128;

/// Bytes of the `eth_out_dma` region (virtqueues and virtio bounce buffers).
pub const ETH_OUT_DMA_SIZE: usize = 0x200_000;
/// Offset of the virtio-mmio transport within the `eth_out_mmio` page.
pub const ETH_OUT_MMIO_OFFSET: usize = 0xe00;
/// GIC interrupt of QEMU virt virtio-mmio slot 31 (SPI 47).
pub const ETH_OUT_IRQ: usize = 79;

/// Inside NIC: virtio-mmio slot 23 (0xa002e00, own page), placed with QEMU
/// `bus=virtio-mmio-bus.23`; GIC interrupt 48 + 23.
pub const ETH_IN_DMA_SIZE: usize = 0x200_000;
pub const ETH_IN_MMIO_OFFSET: usize = 0xe00;
pub const ETH_IN_IRQ: usize = 71;

/// `data`'s stack_size: its handler state, returned by value from init,
/// lives there (crates/pds/data asserts it fits).
pub const DATA_STACK_SIZE: usize = 0x20_000;

/// sp804 on QEMU virt (coliasgroup patch): 1 MHz input clock, SPI 11.
pub const TIMER_IRQ: usize = 43;
pub const TIMER_FREQ_HZ: u32 = 1_000_000;

pub mod eth_out {
    pub const CH_DEVICE: usize = 0;
    pub const CH_INGRESS: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod eth_in {
    pub const CH_DEVICE: usize = 0;
    pub const CH_INNER: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod ingress {
    pub const CH_ETH_OUT: usize = 1;
    pub const CH_AUDIT: usize = 2;
    pub const CH_HS: usize = 3;
    pub const CH_DATA: usize = 4;
    pub const CH_TIMER: usize = 5;
    pub const CH_PQ: usize = 6;
}

pub mod audit {
    pub const CH_INGRESS: usize = 1;
    pub const CH_ETH_OUT: usize = 2;
    pub const CH_ETH_IN: usize = 3;
    pub const CH_INNER: usize = 4;
    pub const CH_HS: usize = 5;
    pub const CH_DATA: usize = 6;
    pub const CH_PQ: usize = 7;
}

#[cfg(test)]
mod tests;

pub mod timer {
    pub const CH_DEVICE: usize = 0;
    pub const CH_DATA: usize = 1;
    pub const CH_HS: usize = 2;
    pub const CH_INGRESS: usize = 3;
    pub const CH_PQ: usize = 4;
}

pub mod key {
    pub const CH_HS: usize = 1;
}

pub mod hs {
    pub const CH_KEY: usize = 1;
    pub const CH_INGRESS: usize = 2;
    pub const CH_DATA: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
    pub const CH_PQ: usize = 6;
}

pub mod data {
    pub const CH_INGRESS: usize = 1;
    pub const CH_HS: usize = 2;
    pub const CH_INNER: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
}

pub mod inner {
    pub const CH_ETH_IN: usize = 1;
    pub const CH_DATA: usize = 2;
    pub const CH_AUDIT: usize = 3;
}

/// M3: the Rosenpass responder (plan C3).
pub mod pq {
    pub const CH_PQKEY: usize = 1;
    pub const CH_INGRESS: usize = 2;
    pub const CH_HS: usize = 3;
    pub const CH_TIMER: usize = 4;
    pub const CH_AUDIT: usize = 5;
}

/// M3: the McEliece decapsulation oracle (plan C2), a passive key-role PD.
pub mod pqkey {
    pub const CH_PQ: usize = 1;
}
