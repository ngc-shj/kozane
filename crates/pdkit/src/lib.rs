//! Plumbing shared by the M2 PDs: byte links over shared memory and an
//! audit producer. Decisions stay in the `*-core` crates; this only wires
//! regions to `ring::link` and coalesced audit records.

#![no_std]

use core::ptr::NonNull;

use audit_event::{Coalescer, Event, Record};
use layout::{AUDIT_RING_SLOTS, NET_BUF_SIZE, NET_BUFFERS, NET_REGION_SIZE, NET_RING_SLOTS};
use ring::Producer;
use ring::link::{LinkError, Receiver, Sender};
use ring::shmem::{Region, ShmRing};
use sel4_microkit::Channel;

pub type DescRing = ShmRing<ring::Desc, NET_RING_SLOTS>;
pub type Rx = Receiver<DescRing, DescRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>;
pub type Tx = Sender<DescRing, DescRing, NET_RING_SLOTS, NET_BUFFERS, NET_BUF_SIZE>;
pub type Buf = [u8; NET_BUF_SIZE];
type AuditRing = ShmRing<Record, AUDIT_RING_SLOTS>;

/// # Safety
/// The three regions must be mapped into this PD and the one peer PD only,
/// with the sizes in `layout`, for the life of the system.
pub unsafe fn rx(used: NonNull<u8>, free: NonNull<u8>, data: NonNull<u8>) -> Rx {
    // SAFETY: per the caller's contract.
    unsafe {
        Receiver::new(
            DescRing::consumer(used.as_ptr()),
            DescRing::producer(free.as_ptr()),
            Region::new(data.as_ptr(), NET_REGION_SIZE),
        )
    }
}

/// # Safety
/// As for `rx`.
pub unsafe fn tx(used: NonNull<u8>, free: NonNull<u8>, data: NonNull<u8>) -> Tx {
    // SAFETY: per the caller's contract.
    unsafe {
        Sender::new(
            DescRing::producer(used.as_ptr()),
            DescRing::consumer(free.as_ptr()),
            Region::new(data.as_ptr(), NET_REGION_SIZE),
        )
    }
}

/// A `tx` that zeroes each buffer when it comes back (links carrying keys).
///
/// # Safety
/// As for `rx`.
pub unsafe fn tx_scrubbing(used: NonNull<u8>, free: NonNull<u8>, data: NonNull<u8>) -> Tx {
    // SAFETY: per the caller's contract.
    unsafe {
        Sender::new_scrubbing(
            DescRing::producer(used.as_ptr()),
            DescRing::consumer(free.as_ptr()),
            Region::new(data.as_ptr(), NET_REGION_SIZE),
        )
    }
}

/// Coalesced audit records to `audit`, notified once per handler run.
pub struct Audit {
    ring: Producer<AuditRing, Record, AUDIT_RING_SLOTS>,
    coalescer: Coalescer,
    pending: bool,
    channel: Channel,
}

impl Audit {
    /// # Safety
    /// `region` must be this PD's audit ring, shared with `audit` only.
    pub unsafe fn new(region: NonNull<u8>, channel: Channel) -> Self {
        // SAFETY: per the caller's contract.
        let ring = Producer::new(unsafe { AuditRing::producer(region.as_ptr()) });
        Self { ring, coalescer: Coalescer::new(), pending: false, channel }
    }

    pub fn record(&mut self, ev: Event) {
        self.record_delivered(ev);
    }

    /// `record`, reporting whether a record reached the ring (false when it
    /// was coalesced away or the ring was full).
    pub fn record_delivered(&mut self, ev: Event) -> bool {
        let ring = &mut self.ring;
        let mut delivered = false;
        // Notify on every offer, including a full ring (see Coalescer::record).
        self.pending |= self.coalescer.record(ev, |r| {
            delivered = ring.push(r).is_ok();
            delivered
        });
        delivered
    }

    pub fn link_error(&mut self, e: LinkError) {
        self.record(match e {
            LinkError::Corrupt => Event::RingCorrupt,
            LinkError::BadDesc(_) => Event::BadDescriptor,
            LinkError::NoBuffer => Event::TxNoBuffer,
        });
    }

    pub fn flush(&mut self) {
        if core::mem::take(&mut self.pending) {
            self.channel.notify();
        }
    }
}

/// Reclaims returned buffers, then sends `data` (copied into a buffer the
/// sender owns). Returns whether it was sent; failures are audited.
pub fn send(tx: &mut Tx, scratch: &mut Buf, data: &[u8], audit: &mut Audit) -> bool {
    if let Err(e) = tx.reclaim() {
        audit.link_error(e);
    }
    let r = tx.send_with(scratch, |s| {
        s.get_mut(..data.len())?.copy_from_slice(data);
        Some(data.len())
    });
    match r {
        Ok(sent) => sent,
        Err(e) => {
            audit.link_error(e);
            false
        }
    }
}

/// Receives one message into `buf`. `Ok(None)` when the link is empty;
/// a bad descriptor is audited and skipped; a corrupt link stops.
pub fn recv(rx: &mut Rx, buf: &mut Buf, audit: &mut Audit) -> Option<usize> {
    loop {
        match rx.recv_into(buf) {
            Ok(r) => return r,
            Err(LinkError::Corrupt) => {
                audit.record(Event::RingCorrupt);
                return None;
            }
            Err(e) => audit.link_error(e),
        }
    }
}
