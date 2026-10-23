//! Inside NIC driver PD (logic in `netdrv`).

#![no_std]
#![no_main]

use layout::{ETH_IN_DMA_SIZE, ETH_IN_MMIO_OFFSET, eth_in as ch};
use sel4_microkit::{Channel, memory_region_symbol, protection_domain, var};

#[protection_domain(heap_size = 256 * 1024)]
fn init() -> netdrv::Driver {
    netdrv::start(netdrv::Params {
        mmio_vaddr: *var!(eth_in_mmio_vaddr: usize = 0),
        mmio_offset: ETH_IN_MMIO_OFFSET,
        dma_vaddr: *var!(eth_in_dma_vaddr: usize = 0),
        dma_paddr: *var!(eth_in_dma_paddr: usize = 0),
        dma_size: ETH_IN_DMA_SIZE,
        rx_used: memory_region_symbol!(inner_rx_used: *mut u8),
        rx_free: memory_region_symbol!(inner_rx_free: *mut u8),
        rx_data: memory_region_symbol!(inner_rx_data: *mut u8),
        tx_used: memory_region_symbol!(inner_tx_used: *mut u8),
        tx_free: memory_region_symbol!(inner_tx_free: *mut u8),
        tx_data: memory_region_symbol!(inner_tx_data: *mut u8),
        audit: memory_region_symbol!(audit_eth_in: *mut u8),
        ch_device: Channel::new(ch::CH_DEVICE),
        ch_peer: Channel::new(ch::CH_INNER),
        ch_audit: Channel::new(ch::CH_AUDIT),
    })
}
