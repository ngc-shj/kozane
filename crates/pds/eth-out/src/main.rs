//! Outside NIC driver. Copy-only (law L7): frames move between virtio
//! buffers and the `ingress` rings without being interpreted.
//!
//! Never waits on the device: rx and tx requests are submitted and their
//! completions reaped on later notifications, so a device that stops
//! completing stalls only its own queue, not this PD.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
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
use virtio_drivers::device::net::VirtIONetRaw;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};

const MMIO_SIZE: usize = 0x200;
const QUEUE_SIZE: usize = 16;
/// virtio-net header (at most 12 bytes) plus a full frame, with slack.
const RAW_BUF: usize = NET_BUF_SIZE + 64;

const DEVICE: Channel = Channel::new(ch::CH_DEVICE);
const INGRESS: Channel = Channel::new(ch::CH_INGRESS);
const AUDIT: Channel = Channel::new(ch::CH_AUDIT);

type NetRing = ShmRing<ring::Desc, NET_RING_SLOTS>;
type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;
type Buffers = Box<[[u8; RAW_BUF]]>;

struct Driver {
    dev: VirtIONetRaw<HalImpl, MmioTransport<'static>, QUEUE_SIZE>,
    /// Heap-allocated so they never move while the device holds them.
    rx_bufs: Buffers,
    tx_bufs: Buffers,
    /// Indexed by virtio token (head descriptor id, < QUEUE_SIZE): which
    /// buffer the in-flight request uses.
    rx_inflight: [Option<usize>; QUEUE_SIZE],
    tx_inflight: [Option<usize>; QUEUE_SIZE],
    /// Submitted length per tx buffer (transmit_complete needs the same slice).
    tx_len: [usize; QUEUE_SIZE],
    tx_idle: [bool; QUEUE_SIZE],
    to_ingress: Sender<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    from_ingress: Receiver<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    audit: Producer<AuditRing, Record, AUDIT_RING_SLOTS>,
    coalescer: Coalescer,
    scratch: [u8; NET_BUF_SIZE],
    audit_pending: bool,
    /// Set when the device breaks the virtqueue protocol; the PD stops using it.
    device_dead: bool,
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
    let dev = VirtIONetRaw::new(transport).unwrap_or_else(|_| panic!("eth_out: device init"));

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

    let mut drv = Driver {
        dev,
        rx_bufs: vec![[0u8; RAW_BUF]; QUEUE_SIZE].into_boxed_slice(),
        tx_bufs: vec![[0u8; RAW_BUF]; QUEUE_SIZE].into_boxed_slice(),
        rx_inflight: [None; QUEUE_SIZE],
        tx_inflight: [None; QUEUE_SIZE],
        tx_len: [0; QUEUE_SIZE],
        tx_idle: [true; QUEUE_SIZE],
        to_ingress,
        from_ingress,
        audit,
        coalescer: Coalescer::new(),
        scratch: [0; NET_BUF_SIZE],
        audit_pending: false,
        device_dead: false,
    };
    for i in 0..QUEUE_SIZE {
        drv.post_rx(i);
    }
    drv.dev.ack_interrupt();
    let _ = DEVICE.irq_ack();
    debug_println!("eth_out: ready");
    // Frames may complete before the first interrupt is delivered.
    drv.service();
    drv
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

    /// The device broke the virtqueue protocol (unknown token, failed
    /// completion): stop using it rather than guess at its state.
    fn device_broke(&mut self) {
        if !self.device_dead {
            self.device_dead = true;
            self.audit(Event::DeviceFault);
        }
    }

    /// Hands rx buffer `i` to the device.
    fn post_rx(&mut self, i: usize) {
        let Some(buf) = self.rx_bufs.get_mut(i) else { return };
        // SAFETY: the buffer is heap-allocated and not touched again until
        // its token comes back from poll_receive and receive_complete.
        match unsafe { self.dev.receive_begin(buf) } {
            Ok(token) => match self.rx_inflight.get_mut(usize::from(token)) {
                Some(slot @ None) => *slot = Some(i),
                _ => self.device_broke(),
            },
            Err(_) => self.device_broke(),
        }
    }

    /// Device → ingress. Returns whether anything was delivered.
    fn pump_rx(&mut self) -> bool {
        let mut delivered = false;
        if let Err(e) = self.to_ingress.reclaim() {
            self.audit_link_error(e);
        }
        // At most one queue's worth per call, so a steady stream cannot keep
        // this loop running and delay the ingress notification indefinitely.
        for _ in 0..QUEUE_SIZE {
            if self.device_dead {
                break;
            }
            let Some(token) = self.dev.poll_receive() else { break };
            let Some(i) = self.rx_inflight.get_mut(usize::from(token)).and_then(Option::take) else {
                self.device_broke();
                break;
            };
            let Some(buf) = self.rx_bufs.get_mut(i) else { break };
            // SAFETY: `buf` is the buffer submitted with this token.
            let Ok((hdr, len)) = (unsafe { self.dev.receive_complete(token, buf) }) else {
                self.device_broke();
                break;
            };
            // A used length beyond the buffer is a protocol violation, not a
            // frame to drop quietly.
            let Some(packet) = buf.get(hdr..hdr.saturating_add(len)) else {
                self.device_broke();
                break;
            };
            if packet.len() > NET_BUF_SIZE {
                self.audit(Event::FrameTooLong);
                self.post_rx(i);
                continue;
            }
            let r = self.to_ingress.send_with(&mut self.scratch, |s| {
                s.get_mut(..packet.len())?.copy_from_slice(packet);
                Some(packet.len())
            });
            match r {
                Ok(sent) => delivered |= sent,
                Err(e) => self.audit_link_error(e),
            }
            self.post_rx(i);
        }
        delivered
    }

    /// Reaps finished transmissions, freeing their buffers.
    fn reap_tx(&mut self) {
        while !self.device_dead {
            let Some(token) = self.dev.poll_transmit() else { break };
            let Some(i) = self.tx_inflight.get_mut(usize::from(token)).and_then(Option::take) else {
                self.device_broke();
                break;
            };
            let len = self.tx_len.get(i).copied().unwrap_or(0);
            let Some(frame) = self.tx_bufs.get(i).and_then(|b| b.get(..len)) else { break };
            // SAFETY: `frame` is the same slice submitted with this token.
            if unsafe { self.dev.transmit_complete(token, frame) }.is_err() {
                self.device_broke();
                break;
            }
            if let Some(idle) = self.tx_idle.get_mut(i) {
                *idle = true;
            }
        }
    }

    /// Ingress → device, without waiting. While every tx buffer is in
    /// flight, frames stay queued in the ring; ingress then runs out of
    /// buffers and reports TxNoBuffer itself.
    fn pump_tx(&mut self) {
        self.reap_tx();
        while !self.device_dead {
            let Some(i) = self.tx_idle.iter().position(|idle| *idle) else { break };
            let n = match self.from_ingress.recv_into(&mut self.scratch) {
                Ok(Some(n)) => n,
                Ok(None) => break,
                Err(LinkError::Corrupt) => {
                    self.audit(Event::RingCorrupt);
                    break;
                }
                Err(e) => {
                    self.audit_link_error(e);
                    continue;
                }
            };
            let Some(buf) = self.tx_bufs.get_mut(i) else { break };
            let Ok(hdr) = self.dev.fill_buffer_header(buf) else { break };
            let total = hdr.saturating_add(n);
            let (Some(dst), Some(src)) = (buf.get_mut(hdr..total), self.scratch.get(..n)) else {
                self.audit(Event::TxNoBuffer);
                continue;
            };
            dst.copy_from_slice(src);
            let Some(frame) = buf.get(..total) else { continue };
            // SAFETY: the buffer is heap-allocated and not touched again
            // until reap_tx completes its token.
            match unsafe { self.dev.transmit_begin(frame) } {
                Ok(token) => match self.tx_inflight.get_mut(usize::from(token)) {
                    Some(slot @ None) => {
                        *slot = Some(i);
                        if let (Some(l), Some(idle)) = (self.tx_len.get_mut(i), self.tx_idle.get_mut(i)) {
                            *l = total;
                            *idle = false;
                        }
                    }
                    _ => self.device_broke(),
                },
                Err(_) => self.audit(Event::TxNoBuffer),
            }
        }
    }

    fn service(&mut self) {
        self.pump_tx();
        if self.pump_rx() {
            INGRESS.notify();
        }
        if core::mem::take(&mut self.audit_pending) {
            AUDIT.notify();
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
        self.service();
        Ok(())
    }
}
