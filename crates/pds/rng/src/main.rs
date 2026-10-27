//! Entropy driver PD (M7 plan C6, laws L1/L5 as amended): passive,
//! untainted, the only PD that maps the virtio-rng page, and callee of the
//! PDs that draw randomness (`layout::rng`). Each `SEED` call is one device
//! request on the caller's scheduling context, polled against a CNTPCT
//! deadline (D2: no `request_entropy`, which spins without bound); the
//! answer is 32 device bytes or `UNAVAILABLE` (rng-core decides). A device
//! that is missing or fails to come up leaves the PD up and every answer
//! `UNAVAILABLE`: a callee never stops, so no caller blocks on it (D4). No
//! audit channel and no console: what happened shows in the callers'
//! replies and their audit lines.

#![no_std]
#![no_main]

extern crate alloc;

use core::ptr::NonNull;

use layout::{RNG_DMA_SIZE, RNG_MMIO_OFFSET, rng as ipc};
use rng_core::{Caller, Device, DeviceError, RNG_POLL_NS, SEED_LEN, Secret, Server, Unavailable};
use sel4_microkit::{Channel, Handler, Infallible, MessageInfo, protection_domain, var, with_msg_regs_mut};
use sel4_virtio_hal_impl::HalImpl;
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};

const MMIO_SIZE: usize = 0x200;
const QUEUE_SIZE: usize = 8;
const QUEUE_IDX: u16 = 0;
const SEED_WORDS: usize = SEED_LEN / 8;

fn caller(channel: Channel) -> Option<Caller> {
    [
        (ipc::CH_HS, Caller::Hs),
        (ipc::CH_PQ, Caller::Pq),
        (ipc::CH_INGRESS, Caller::Ingress),
        (ipc::CH_TLS, Caller::Tls),
        (ipc::CH_KEY, Caller::Key),
        (ipc::CH_PQKEY, Caller::Pqkey),
        (ipc::CH_TLSKEY, Caller::Tlskey),
    ]
    .into_iter()
    .find(|(ch, _)| channel == Channel::new(*ch))
    .map(|(_, c)| c)
}

/// The virtqueue driver for one request at a time (I6.5): a completion is
/// matched to its request by token; a request whose deadline passed stays
/// the device's (`stale`) until it completes, and its bytes are then wiped
/// and never returned; while one is stale no new request is made.
struct Virtio {
    transport: MmioTransport<'static>,
    queue: VirtQueue<HalImpl, QUEUE_SIZE>,
    buf: [u8; SEED_LEN],
    stale: Option<u16>,
}

impl Virtio {
    fn reclaim(&mut self) -> Result<(), DeviceError> {
        let Some(token) = self.stale else { return Ok(()) };
        if self.queue.peek_used() != Some(token) {
            return Err(DeviceError);
        }
        // SAFETY: `token` is the request made from `self.buf`, which has not
        // moved since; the device has returned it.
        let r = unsafe { self.queue.pop_used(token, &[], &mut [&mut self.buf]) };
        self.buf.fill(0);
        self.stale = None;
        r.map(|_| ()).map_err(|_| DeviceError)
    }
}

impl Device for Virtio {
    fn draw(&mut self, out: &mut [u8; SEED_LEN]) -> Result<usize, DeviceError> {
        self.reclaim()?;
        // SAFETY: `self.buf` lives in the handler, which does not move while
        // a request is outstanding (one request at a time, popped below or
        // kept as `stale`).
        let token = unsafe { self.queue.add(&[], &mut [&mut self.buf]) }.map_err(|_| DeviceError)?;
        if self.queue.should_notify() {
            self.transport.notify(QUEUE_IDX);
        }
        let deadline = cpu::now_ns().saturating_add(RNG_POLL_NS);
        while self.queue.peek_used() != Some(token) {
            if cpu::now_ns() >= deadline {
                self.stale = Some(token);
                return Err(DeviceError);
            }
            core::hint::spin_loop();
        }
        // SAFETY: as for `add`; the device returned exactly this request.
        let n = unsafe { self.queue.pop_used(token, &[], &mut [&mut self.buf]) }.map_err(|_| DeviceError);
        out.copy_from_slice(&self.buf);
        self.buf.fill(0);
        n.map(|n| n as usize)
    }
}

struct Rng {
    device: Option<Virtio>,
    server: Server,
}

/// No device answers every request `Unavailable`.
struct NoDevice;

impl Device for NoDevice {
    fn draw(&mut self, _: &mut [u8; SEED_LEN]) -> Result<usize, DeviceError> {
        Err(DeviceError)
    }
}

fn start() -> Option<Virtio> {
    let mmio = *var!(rng_mmio_vaddr: usize = 0);
    let dma_vaddr = *var!(rng_dma_vaddr: usize = 0);
    let dma_paddr = *var!(rng_dma_paddr: usize = 0);
    if mmio == 0 || dma_vaddr == 0 || dma_paddr == 0 {
        return None;
    }
    HalImpl::init(RNG_DMA_SIZE, dma_vaddr, dma_paddr);
    let header = NonNull::new(mmio.wrapping_add(RNG_MMIO_OFFSET) as *mut VirtIOHeader)?;
    // SAFETY: the .system maps the virtio-rng page here, uncached, into this
    // PD alone (L5), for the life of the system.
    let mut transport = unsafe { MmioTransport::new(header, MMIO_SIZE) }.ok()?;
    if transport.device_type() != DeviceType::EntropySource {
        return None;
    }
    transport.begin_init(virtio_drivers::device::common::Feature::empty());
    let queue = VirtQueue::new(&mut transport, QUEUE_IDX, false, false).ok()?;
    transport.finish_init();
    Some(Virtio { transport, queue, buf: [0; SEED_LEN], stale: None })
}

#[protection_domain(heap_size = 64 * 1024)]
fn init() -> Rng {
    boot_stage::run_init(|_| boot())
}

fn boot() -> Rng {
    Rng { device: start(), server: Server::new() }
}

impl Handler for Rng {
    type Error = Infallible;

    fn protected(&mut self, channel: Channel, msg_info: MessageInfo) -> Result<MessageInfo, Self::Error> {
        let mut seed = Secret::<SEED_LEN>::zero();
        let r = match caller(channel) {
            Some(c) if msg_info.label() == ipc::SEED && msg_info.count() == 0 => {
                let now = cpu::now_ns();
                match self.device.as_mut() {
                    Some(d) => self.server.seed(c, now, d, &mut seed),
                    None => self.server.seed(c, now, &mut NoDevice, &mut seed),
                }
            }
            _ => Err(Unavailable::Device),
        };
        // The seed fits the four registers a reply carries without the IPC
        // buffer, and every register past the reply is overwritten.
        let reply = with_msg_regs_mut(|mrs| {
            mrs.iter_mut().take(SEED_WORDS).for_each(|w| *w = 0);
            match r {
                Ok(()) => {
                    for (w, chunk) in mrs.iter_mut().zip(seed.as_bytes().as_chunks::<8>().0) {
                        *w = u64::from_le_bytes(*chunk);
                    }
                    MessageInfo::new(ipc::SEED, SEED_WORDS)
                }
                Err(e) => {
                    if let Some(w) = mrs.first_mut() {
                        *w = e as u64;
                    }
                    MessageInfo::new(ipc::UNAVAILABLE, 1)
                }
            }
        });
        Ok(reply)
    }
}
