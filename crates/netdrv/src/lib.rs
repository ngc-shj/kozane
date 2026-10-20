//! virtio-net driver logic shared by the outside (`eth_out`) and inside
//! (`eth_in`) driver PDs. Copy-only (law L7): frames move between virtio
//! buffers and the rings of the PD on the other side without being
//! interpreted.
//!
//! Never waits on the device: rx and tx requests are submitted and their
//! completions reaped on later notifications, so a device that stops
//! completing stalls only its own queue, not this PD.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use core::ptr::NonNull;

use audit_event::{Coalescer, Event, Record};
use layout::{AUDIT_RING_SLOTS, NET_BUF_SIZE, NET_BUFFERS, NET_REGION_SIZE, NET_RING_SLOTS};
use ring::Producer;
use ring::link::{LinkError, Receiver, Sender};
use ring::shmem::{Region, ShmRing};
use sel4_microkit::{Channel, ChannelSet, Handler, Infallible, debug_println};
use sel4_virtio_hal_impl::HalImpl;
use virtio_drivers::device::net::VirtIONetRaw;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};

const MMIO_SIZE: usize = 0x200;
const QUEUE_SIZE: usize = 16;
/// virtio-net header (at most 12 bytes) plus a full frame, with slack.
const RAW_BUF: usize = NET_BUF_SIZE + 64;

type NetRing = ShmRing<ring::Desc, NET_RING_SLOTS>;
type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;
type Buffers = Box<[[u8; RAW_BUF]]>;

/// What a driver binary hands over: values patched in by the Microkit tool
/// (symbol names differ per PD, so the binaries read them) and its channels.
pub struct Params {
    pub name: &'static str,
    pub mmio_vaddr: usize,
    pub mmio_offset: usize,
    pub dma_vaddr: usize,
    pub dma_paddr: usize,
    pub dma_size: usize,
    /// Rings and data region towards the peer PD (rx: device → peer).
    pub rx_used: NonNull<u8>,
    pub rx_free: NonNull<u8>,
    pub rx_data: NonNull<u8>,
    pub tx_used: NonNull<u8>,
    pub tx_free: NonNull<u8>,
    pub tx_data: NonNull<u8>,
    pub audit: NonNull<u8>,
    pub ch_device: Channel,
    pub ch_peer: Channel,
    pub ch_audit: Channel,
}

pub struct Driver {
    name: &'static str,
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
    to_peer: Sender<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    from_peer: Receiver<NetRing, NetRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>,
    audit: Producer<AuditRing, Record, AUDIT_RING_SLOTS>,
    coalescer: Coalescer,
    scratch: [u8; NET_BUF_SIZE],
    audit_pending: bool,
    /// Set when the device breaks the virtqueue protocol; the PD stops using it.
    device_dead: bool,
    ch_device: Channel,
    ch_peer: Channel,
    ch_audit: Channel,
}

/// Initialises the device and the rings. Panics (halting the PD, fail-closed)
/// on unset symbols or a device that is not a virtio-net.
pub fn start(p: Params) -> Driver {
    // 0 is the default of every patched symbol and also a valid physical
    // address, so an unset value must stop the PD before the device sees it.
    assert!(p.dma_vaddr != 0 && p.dma_paddr != 0 && p.mmio_vaddr != 0, "netdrv: region symbol unset");
    HalImpl::init(p.dma_size, p.dma_vaddr, p.dma_paddr);

    let header = NonNull::new(p.mmio_vaddr.wrapping_add(p.mmio_offset) as *mut VirtIOHeader)
        .unwrap_or_else(|| panic!("netdrv: mmio vaddr unset"));
    // SAFETY: the .system maps the virtio-mmio page at mmio_vaddr, uncached,
    // for this PD only (law L5).
    let transport = unsafe { MmioTransport::new(header, MMIO_SIZE) }
        .unwrap_or_else(|_| panic!("netdrv: bad virtio-mmio header"));
    assert!(transport.device_type() == DeviceType::Network, "netdrv: not a network device");
    let dev = VirtIONetRaw::new(transport).unwrap_or_else(|_| panic!("netdrv: device init"));

    // SAFETY: the .system maps each region into this PD and its peer only,
    // sized as in `layout`; rings are 4-byte aligned page starts.
    let (to_peer, from_peer, audit) = unsafe {
        (
            Sender::new(
                NetRing::producer(p.rx_used.as_ptr()),
                NetRing::consumer(p.rx_free.as_ptr()),
                Region::new(p.rx_data.as_ptr(), NET_REGION_SIZE),
            ),
            Receiver::new(
                NetRing::consumer(p.tx_used.as_ptr()),
                NetRing::producer(p.tx_free.as_ptr()),
                Region::new(p.tx_data.as_ptr(), NET_REGION_SIZE),
            ),
            Producer::new(AuditRing::producer(p.audit.as_ptr())),
        )
    };

    let mut drv = Driver {
        name: p.name,
        dev,
        rx_bufs: vec![[0u8; RAW_BUF]; QUEUE_SIZE].into_boxed_slice(),
        tx_bufs: vec![[0u8; RAW_BUF]; QUEUE_SIZE].into_boxed_slice(),
        rx_inflight: [None; QUEUE_SIZE],
        tx_inflight: [None; QUEUE_SIZE],
        tx_len: [0; QUEUE_SIZE],
        tx_idle: [true; QUEUE_SIZE],
        to_peer,
        from_peer,
        audit,
        coalescer: Coalescer::new(),
        scratch: [0; NET_BUF_SIZE],
        audit_pending: false,
        device_dead: false,
        ch_device: p.ch_device,
        ch_peer: p.ch_peer,
        ch_audit: p.ch_audit,
    };
    for i in 0..QUEUE_SIZE {
        drv.post_rx(i);
    }
    drv.dev.ack_interrupt();
    let _ = drv.ch_device.irq_ack();
    debug_println!("{}: ready", drv.name);
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
            // A broken take/release protocol is a local fault, reported as a
            // dead link.
            LinkError::Held => Event::RingCorrupt,
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

    /// Device → peer PD, one queue's worth at most. Returns (delivered
    /// anything, stopped at the bound with completions possibly pending).
    fn pump_rx(&mut self) -> (bool, bool) {
        let mut delivered = false;
        if let Err(e) = self.to_peer.reclaim() {
            self.audit_link_error(e);
        }
        // At most one queue's worth per call, so ingress is notified per
        // batch instead of after an arbitrarily long stream.
        for _ in 0..QUEUE_SIZE {
            if self.device_dead {
                return (delivered, false);
            }
            let Some(token) = self.dev.poll_receive() else { return (delivered, false) };
            let Some(i) = self.rx_inflight.get_mut(usize::from(token)).and_then(Option::take) else {
                self.device_broke();
                return (delivered, false);
            };
            let Some(buf) = self.rx_bufs.get_mut(i) else { return (delivered, false) };
            // SAFETY: `buf` is the buffer submitted with this token.
            let Ok((hdr, len)) = (unsafe { self.dev.receive_complete(token, buf) }) else {
                self.device_broke();
                return (delivered, false);
            };
            // A used length beyond the buffer is a protocol violation, not a
            // frame to drop quietly.
            let Some(packet) = buf.get(hdr..hdr.saturating_add(len)) else {
                self.device_broke();
                return (delivered, false);
            };
            if packet.len() > NET_BUF_SIZE {
                self.audit(Event::FrameTooLong);
                self.post_rx(i);
                continue;
            }
            let r = self.to_peer.send_with(&mut self.scratch, |s| {
                s.get_mut(..packet.len())?.copy_from_slice(packet);
                Some(packet.len())
            });
            match r {
                Ok(sent) => delivered |= sent,
                Err(e) => self.audit_link_error(e),
            }
            self.post_rx(i);
        }
        (delivered, true)
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

    /// Peer PD → device, without waiting. While every tx buffer is in
    /// flight, frames stay queued in the ring; the peer then runs out of
    /// buffers and reports TxNoBuffer itself.
    fn pump_tx(&mut self) {
        self.reap_tx();
        while !self.device_dead {
            let Some(i) = self.tx_idle.iter().position(|idle| *idle) else { break };
            let n = match self.from_peer.recv_into(&mut self.scratch) {
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
        // virtio-drivers negotiates RING_EVENT_IDX: the device interrupts
        // only once the driver has caught up with the used ring, so stopping
        // at the batch bound must not end the handler while completions
        // remain, or rx would wait for an unrelated event.
        loop {
            self.pump_tx();
            let (delivered, more) = self.pump_rx();
            if delivered {
                self.ch_peer.notify();
            }
            if core::mem::take(&mut self.audit_pending) {
                self.ch_audit.notify();
            }
            if !more {
                break;
            }
        }
    }
}

impl Handler for Driver {
    type Error = Infallible;

    fn notified(&mut self, channels: ChannelSet) -> Result<(), Self::Error> {
        if channels.contains(self.ch_device) {
            self.dev.ack_interrupt();
            let _ = self.ch_device.irq_ack();
        }
        self.service();
        Ok(())
    }
}
