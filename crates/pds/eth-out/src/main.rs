//! Outside NIC driver PD (logic in `netdrv`).

#![no_std]
#![no_main]

use layout::{ETH_OUT_DMA_SIZE, ETH_OUT_MMIO_OFFSET, eth_out as ch};
use sel4_microkit::{Channel, memory_region_symbol, protection_domain, var};

#[protection_domain(heap_size = 256 * 1024)]
fn init() -> netdrv::Driver {
    netdrv::start(netdrv::Params {
        name: "eth_out",
        mmio_vaddr: *var!(eth_out_mmio_vaddr: usize = 0),
        mmio_offset: ETH_OUT_MMIO_OFFSET,
        dma_vaddr: *var!(eth_out_dma_vaddr: usize = 0),
        dma_paddr: *var!(eth_out_dma_paddr: usize = 0),
        dma_size: ETH_OUT_DMA_SIZE,
        rx_used: memory_region_symbol!(net_rx_used: *mut u8),
        rx_free: memory_region_symbol!(net_rx_free: *mut u8),
        rx_data: memory_region_symbol!(net_rx_data: *mut u8),
        tx_used: memory_region_symbol!(net_tx_used: *mut u8),
        tx_free: memory_region_symbol!(net_tx_free: *mut u8),
        tx_data: memory_region_symbol!(net_tx_data: *mut u8),
        audit: memory_region_symbol!(audit_eth_out: *mut u8),
        ch_device: Channel::new(ch::CH_DEVICE),
        ch_peer: Channel::new(ch::CH_INGRESS),
        ch_audit: Channel::new(ch::CH_AUDIT),
    })
}
