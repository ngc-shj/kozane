//! One direction of buffer exchange, built from a used ring, a free ring, a
//! `Pool` and a data `Region`. The `Sender` starts owning every buffer; the
//! `Receiver` copies each payload into private memory and returns the buffer
//! before the caller looks at the bytes.

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
}

impl<U, F, const N: usize, const M: usize, const BUF: usize> Sender<U, F, N, M, BUF>
where
    U: SharedAccess<Desc>,
    F: SharedAccess<Desc>,
{
    const RING_HOLDS_ALL_BUFFERS: () = assert!(N >= M, "ring must hold every buffer");

    pub fn new(used: U, free: F, region: Region) -> Self {
        let () = Self::RING_HOLDS_ALL_BUFFERS;
        Self { used: Producer::new(used), free: Consumer::new(free), pool: Pool::new(true), region, dead: false }
    }

    /// Takes back buffers the receiver has returned. Stops at the first bad
    /// descriptor and reports it.
    pub fn reclaim(&mut self) -> Result<(), LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
        }
        while let Some(d) = self.free.pop().inspect_err(|_| self.dead = true)? {
            self.pool.accept(d).map_err(LinkError::BadDesc)?;
        }
        Ok(())
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
}

impl<U, F, const N: usize, const M: usize, const BUF: usize> Receiver<U, F, N, M, BUF>
where
    U: SharedAccess<Desc>,
    F: SharedAccess<Desc>,
{
    const RING_HOLDS_ALL_BUFFERS: () = assert!(N >= M, "ring must hold every buffer");

    pub fn new(used: U, free: F, region: Region) -> Self {
        let () = Self::RING_HOLDS_ALL_BUFFERS;
        Self { used: Consumer::new(used), free: Producer::new(free), pool: Pool::new(false), region, dead: false }
    }

    /// Copies the next payload into `out` and returns the buffer to the
    /// sender before returning its length. `Ok(None)` when nothing is queued.
    pub fn recv_into(&mut self, out: &mut [u8; BUF]) -> Result<Option<usize>, LinkError> {
        if self.dead {
            return Err(LinkError::Corrupt);
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
}
