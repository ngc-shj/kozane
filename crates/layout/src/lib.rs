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

pub mod eth_out {
    pub const CH_DEVICE: usize = 0;
    pub const CH_INGRESS: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod ingress {
    pub const CH_ETH_OUT: usize = 1;
    pub const CH_AUDIT: usize = 2;
}

pub mod audit {
    pub const CH_INGRESS: usize = 1;
    pub const CH_ETH_OUT: usize = 2;
}

#[cfg(test)]
mod tests;
