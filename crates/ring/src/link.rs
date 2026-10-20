//! One direction of buffer exchange, built from a used ring, a free ring, a
//! `Pool` and a data `Region`. The `Sender` starts owning every buffer; the
//! `Receiver` copies each payload into private memory and returns the buffer
//! before the caller looks at the bytes (`recv_into`), or keeps it until the
//! caller has finished with the message (`take_into` / `release`, M3b plan
//! C3), so the sender can count the message in progress as in flight.

use crate::shmem::Region;
use crate::{Consumer, Desc, DescError, Pool, Producer, RingError, SharedAccess};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// A ring is corrupt; this link is dead (fail-closed).
    Corrupt,
    /// The peer sent a descriptor that failed validation; it was dropped.
    BadDesc(DescError),
    /// No buffer is currently owned by this side.
    NoBuffer,
    /// A held receive is outstanding: a second take, or a plain receive,
    /// before `release`. Only a caller that broke the take/release protocol
    /// sees it.
    Held,
}

/// A message taken by `take_into`; its buffer stays held until `release`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// This many bytes were copied out.
    Payload(usize),
    /// The descriptor was accepted but its bytes could not be copied. The
    /// buffer is still held, so the caller still completes the message (its
    /// record, then `release`) and stays in step with the sender.
    Unreadable,
}

impl From<RingError> for LinkError {
    fn from(e: RingError) -> Self {
        match e {
            // N >= M, so a full ring means the peer broke the protocol.
            RingError::Full | RingError::Corrupt => LinkError::Corrupt,
        }
    }
}

fn buf_offset<const BUF: usize>(idx: usize) -> usize {
    idx.saturating_mul(BUF)
}

pub struct Sender<U, F, const N: usize, const M: usize, const BUF: usize> {
    used: Producer<U, Desc, N>,
    free: Consumer<F, Desc, N>,
    pool: Pool<M, BUF>,
    region: Region,
    /// Set once any ring operation fails; the link is never used again.
    dead: bool,
    /// Zero each buffer as it comes back, for links carrying secrets.
    scrub: bool,
}

impl<U, F, const N: usize, const M: usize, const BUF: usize> Sender<U, F, N, M, BUF>
where
    U: SharedAccess<Desc>,
    F: SharedAccess<Desc>,
{
    const RING_HOLDS_ALL_BUFFERS: () = assert!(N >= M, "ring must hold every buffer");

    pub fn new(used: U, free: F, region: Region) -> Self {
        let () = Self::RING_HOLDS_ALL_BUFFERS;
        Self { used: Producer::new(used), free: Consumer::new(free), pool: Pool::new(true), region, dead: false, scrub: false }
    }

    /// A sender that zeroes the whole shared region at construction and
    /// every returned buffer thereafter, so neither boot-time residue nor a
    /// message carrying key material outlives sender ownership/delivery.
    pub fn new_scrubbing(used: U, free: F, region: Region) -> Self {
        let mut sender = Self { scrub: true, ..Self::new(used, free, region) };
        let zero = [0u8; BUF];
        for idx in 0..M {
            if sender.region.write_from(buf_offset::<BUF>(idx), &zero).is_err() {
                // The unsafe constructor contract says the region holds all
                // M buffers. Fail closed if a caller violated that contract.
                sender.dead = true;
                break;
            }
        }
        sender
    }

    /// Takes back buffers the receiver has returned. Stops at the first bad
    /// descriptor and reports it.
    pub fn reclaim(&mut self) -> Result<(), LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        while let Some(d) = self.free.pop().inspect_err(|_| self.dead = true)? {
            let idx = self.pool.accept(d).map_err(LinkError::BadDesc)?;
            if self.scrub {
                // The buffer is ours again; nothing reads it until it is refilled.
                let _ = self.region.write_from(buf_offset::<BUF>(idx), &[0u8; BUF]);
            }
        }
        Ok(())
    }

    /// Buffers held by the receiver, counted after a `reclaim`, so a buffer
    /// already returned is never counted as outstanding. Fails as `reclaim`
    /// does.
    pub fn in_flight(&mut self) -> Result<usize, LinkError> {
        self.reclaim()?;
        Ok(M.saturating_sub(self.pool.mine_count()))
    }

    /// Buffers owned by this side, counted after a `reclaim`.
    pub fn free(&mut self) -> Result<usize, LinkError> {
        self.reclaim()?;
        Ok(self.pool.mine_count())
    }

    /// Fills a free buffer via `fill`, which writes into private scratch
    /// space and returns the length used (or `None` to send nothing), then
    /// hands the buffer to the receiver.
    pub fn send_with(
        &mut self,
        scratch: &mut [u8; BUF],
        fill: impl FnOnce(&mut [u8; BUF]) -> Option<usize>,
    ) -> Result<bool, LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        let idx = self.pool.first_mine().ok_or(LinkError::NoBuffer)?;
        let Some(len) = fill(scratch) else {
            return Ok(false);
        };
        let data = scratch.get(..len).ok_or(LinkError::BadDesc(DescError::TooLong))?;
        self.region
            .write_from(buf_offset::<BUF>(idx), data)
            .map_err(|_| LinkError::BadDesc(DescError::OutOfRange))?;
        let d = self.pool.give(idx, len).ok_or(LinkError::NoBuffer)?;
        // A full ring here means the peer broke the protocol (N >= M); the
        // buffer just given away is lost, so the link must not be reused.
        self.used.push(d).inspect_err(|_| self.dead = true)?;
        Ok(true)
    }
}

pub struct Receiver<U, F, const N: usize, const M: usize, const BUF: usize> {
    used: Consumer<U, Desc, N>,
    free: Producer<F, Desc, N>,
    pool: Pool<M, BUF>,
    region: Region,
    /// Set once any ring operation fails; the link is never used again.
    dead: bool,
    /// The buffer of a message taken by `take_into` and not yet released.
    held: Option<usize>,
}

impl<U, F, const N: usize, const M: usize, const BUF: usize> Receiver<U, F, N, M, BUF>
where
    U: SharedAccess<Desc>,
    F: SharedAccess<Desc>,
{
    const RING_HOLDS_ALL_BUFFERS: () = assert!(N >= M, "ring must hold every buffer");

    pub fn new(used: U, free: F, region: Region) -> Self {
        let () = Self::RING_HOLDS_ALL_BUFFERS;
        Self { used: Consumer::new(used), free: Producer::new(free), pool: Pool::new(false), region, dead: false, held: None }
    }

    /// Copies the next payload into `out` and returns the buffer to the
    /// sender before returning its length. `Ok(None)` when nothing is queued.
    pub fn recv_into(&mut self, out: &mut [u8; BUF]) -> Result<Option<usize>, LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        if self.held.is_some() {
            return Err(LinkError::Held);
        }
        let Some(d) = self.used.pop().inspect_err(|_| self.dead = true)? else {
            return Ok(None);
        };
        let idx = self.pool.accept(d).map_err(LinkError::BadDesc)?;
        // `accept` checked len <= BUF.
        let len = usize::try_from(d.len).map_err(|_| LinkError::BadDesc(DescError::TooLong))?;
        let dst = out.get_mut(..len).ok_or(LinkError::BadDesc(DescError::TooLong))?;
        let copied = self.region.read_into(buf_offset::<BUF>(idx), dst);
        let back = self.pool.give(idx, 0).ok_or(LinkError::NoBuffer)?;
        self.free.push(back).inspect_err(|_| self.dead = true)?;
        copied.map_err(|_| LinkError::BadDesc(DescError::OutOfRange))?;
        Ok(Some(len))
    }

    /// Copies the next payload into `out` and keeps its buffer until
    /// `release`. `Ok(None)` when nothing is queued. A descriptor that fails
    /// validation holds nothing (`BadDesc`); once a descriptor is accepted
    /// the call never fails, because returning the buffer here would be a
    /// return the caller never completed. A copy that fails after that is
    /// `Taken::Unreadable`, still held.
    pub fn take_into(&mut self, out: &mut [u8; BUF]) -> Result<Option<Taken>, LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        if self.held.is_some() {
            return Err(LinkError::Held);
        }
        let Some(d) = self.used.pop().inspect_err(|_| self.dead = true)? else {
            return Ok(None);
        };
        let idx = self.pool.accept(d).map_err(LinkError::BadDesc)?;
        self.held = Some(idx);
        let copied = usize::try_from(d.len).ok().and_then(|len| {
            let dst = out.get_mut(..len)?;
            self.region.read_into(buf_offset::<BUF>(idx), dst).ok().map(|()| len)
        });
        Ok(Some(copied.map_or(Taken::Unreadable, Taken::Payload)))
    }

    /// Returns the held buffer to the sender. `NoBuffer` when nothing is
    /// held; a failed return kills the link, since the sender would then
    /// count a message as in flight that is not.
    pub fn release(&mut self) -> Result<(), LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        let Some(idx) = self.held.take() else {
            return Err(LinkError::NoBuffer);
        };
        let Some(back) = self.pool.give(idx, 0) else {
            self.dead = true;
            return Err(LinkError::Corrupt);
        };
        self.free.push(back).inspect_err(|_| self.dead = true)?;
        Ok(())
    }
}
