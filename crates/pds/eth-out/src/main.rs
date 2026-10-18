//! Outside NIC driver. Copy-only (law L7): frames move between virtio
//! buffers and the `ingress` rings without being interpreted.

#![no_std]
#![no_main]

use core::ptr::NonNull;

use audit_event::{Coalescer, Event, Record};
use layout::{
    AUDIT_RING_SLOTS, ETH_OUT_DMA_SIZE, ETH_OUT_MMIO_OFFSET, NET_BUF_SIZE, NET_BUFFERS, NET_REGION_SIZE, NET_RING_SLOTS,
    eth_out as ch,
};
use ring::Producer;
use ring::link::{LinkError, Receiver, Sender};
use ring::shmem::{Region, ShmRing};
use sel4_microkit::{
    Channel, ChannelSet, Handler, Infallible, debug_println, memory_region_symbol, protection_domain, var,
};
use sel4_virtio_hal_impl::HalImpl;
use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};

const MMIO_SIZE: usize = 0x200;
const QUEUE_SIZE: usize = 16;

const DEVICE: Channel = Channel::new(ch::CH_DEVICE);
const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const AUDIT: Channel = Channel::new(ch::CH_AUDIT);

type NetRing = ShmRing<ring::Desc, NET_RING_SLOTS>;
type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;

struct Driver {
    dev: VirtIONet<HalImpl, MmioTransport<'static>, QUEUE_SIZE>,
    to_ingress: Sender<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    from_ingress: Receiver<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    audit: Producer<AuditRing, Record, AUDIT_RING_SLOTS>,
    coalescer: Coalescer,
    scratch: [u8; NET_BUF_SIZE],
    audit_pending: bool,
}

fn region_ptr(p: NonNull<u8>) -> *mut u8 {
    p.as_ptr()
}

#[protection_domain(heap_size = 256 * 1024)]
fn init() -> Driver {
    // 0 is the default of every patched symbol and also a valid physical
    // address, so an unset value must stop the PD before the device sees it.
    let dma_vaddr = *var!(eth_out_dma_vaddr: usize = 0);
    let dma_paddr = *var!(eth_out_dma_paddr: usize = 0);
    let mmio_vaddr = *var!(eth_out_mmio_vaddr: usize = 0);
    assert!(dma_vaddr != 0 && dma_paddr != 0 && mmio_vaddr != 0, "eth_out: region symbol unset");
    HalImpl::init(ETH_OUT_DMA_SIZE, dma_vaddr, dma_paddr);

    let header = NonNull::new((mmio_vaddr + ETH_OUT_MMIO_OFFSET) as *mut VirtIOHeader)
        .unwrap_or_else(|| panic!("eth_out: mmio vaddr unset"));
    // SAFETY: the .system maps the virtio-mmio page at eth_out_mmio_vaddr,
    // uncached, for this PD only (law L5).
    let transport = unsafe { MmioTransport::new(header, MMIO_SIZE) }
        .unwrap_or_else(|_| panic!("eth_out: bad virtio-mmio header"));
    assert!(transport.device_type() == DeviceType::Network, "eth_out: not a network device");
    let mut dev = VirtIONet::new(transport, NET_BUF_SIZE).unwrap_or_else(|_| panic!("eth_out: device init"));

    // SAFETY: the .system maps each region below into this PD and `ingress`
    // only, sized as in `layout`; rings are 4-byte aligned page starts.
    let (to_ingress, from_ingress, audit) = unsafe {
        (
            Sender::new(
                NetRing::producer(region_ptr(memory_region_symbol!(net_rx_used: *mut u8))),
                NetRing::consumer(region_ptr(memory_region_symbol!(net_rx_free: *mut u8))),
                Region::new(region_ptr(memory_region_symbol!(net_rx_data: *mut u8)), NET_REGION_SIZE),
            ),
            Receiver::new(
                NetRing::consumer(region_ptr(memory_region_symbol!(net_tx_used: *mut u8))),
                NetRing::producer(region_ptr(memory_region_symbol!(net_tx_free: *mut u8))),
                Region::new(region_ptr(memory_region_symbol!(net_tx_data: *mut u8)), NET_REGION_SIZE),
            ),
            Producer::new(AuditRing::producer(region_ptr(memory_region_symbol!(audit_eth_out: *mut u8)))),
        )
    };

    dev.ack_interrupt();
    let _ = DEVICE.irq_ack();
    debug_println!("eth_out: ready");
    Driver {
        dev,
        to_ingress,
        from_ingress,
        audit,
        coalescer: Coalescer::new(),
        scratch: [0; NET_BUF_SIZE],
        audit_pending: false,
    }
}

impl Driver {
    fn audit(&mut self, ev: Event) {
        let audit = &mut self.audit;
        // Notify on every offer, including a full ring (see Coalescer::record).
        self.audit_pending |= self.coalescer.record(ev, |r| audit.push(r).is_ok());
    }

    fn audit_link_error(&mut self, e: LinkError) {
        self.audit(match e {
            LinkError::Corrupt => Event::RingCorrupt,
            LinkError::BadDesc(_) => Event::BadDescriptor,
            LinkError::NoBuffer => Event::RxNoBuffer,
        });
    }

    /// Device → ingress. Returns whether anything was delivered.
    fn pump_rx(&mut self) -> bool {
        let mut delivered = false;
        if let Err(e) = self.to_ingress.reclaim() {
            self.audit_link_error(e);
        }
        while let Ok(rx) = self.dev.receive() {
            let packet = rx.packet();
            let r = self.to_ingress.send_with(&mut self.scratch, |s| {
                let dst = s.get_mut(..packet.len())?;
                dst.copy_from_slice(packet);
                Some(packet.len())
            });
            match r {
                Ok(sent) => delivered |= sent,
                Err(e) => self.audit_link_error(e),
            }
            let _ = self.dev.recycle_rx_buffer(rx);
        }
        delivered
    }

    /// Ingress → device.
    fn pump_tx(&mut self) {
        loop {
            match self.from_ingress.recv_into(&mut self.scratch) {
                Ok(Some(n)) => {
                    let Some(frame) = self.scratch.get(..n) else { continue };
                    let mut tx = self.dev.new_tx_buffer(n);
                    tx.packet_mut().copy_from_slice(frame);
                    if self.dev.send(tx).is_err() {
                        self.audit(Event::TxNoBuffer);
                    }
                }
                Ok(None) => break,
                Err(LinkError::Corrupt) => {
                    self.audit(Event::RingCorrupt);
                    break;
                }
                Err(e) => self.audit_link_error(e),
            }
        }
    }
}

impl Handler for Driver {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(DEVICE) {
            self.dev.ack_interrupt();
            let _ = DEVICE.irq_ack();
        }
        self.pump_tx();
        if self.pump_rx() {
            INGRESS.notify();
        }
        if core::mem::take(&mut self.audit_pending) {
            AUDIT.notify();
        }
        Ok(())
    }
}
