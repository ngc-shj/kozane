//! Buffer exchange between two PDs over shared memory.
//!
//! Each direction uses two SPSC rings of `Desc`: a *used* ring carrying
//! filled buffers to the peer and a *free* ring returning them. The peer is
//! untrusted (threat A3): every value read from shared memory may be
//! arbitrary and may change between reads. Therefore:
//!
//! - each side keeps its own index locally and never reads it back;
//! - the peer's index is read once per operation (through `SharedAccess`,
//!   so the Kani model can return a fresh value on every read);
//! - a peer index more than `N` away marks the ring corrupt for good;
//! - descriptors are checked against the buffer pool and its ownership
//!   state before use, and payloads are copied out before parsing.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod link;
pub mod shmem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Desc {
    pub offset: u32,
    pub len: u32,
}

/// Access to one ring's shared state, whose slots hold `T`. Implementations
/// must perform exactly one memory access per call; callers rely on that for
/// the read-once rule. `T` must be valid for every bit pattern, since the peer
/// can write anything into a slot.
pub trait SharedAccess<T: Copy> {
    fn load_peer_index(&self) -> u32;
    fn store_own_index(&self, v: u32);
    fn load_slot(&self, i: usize) -> T;
    fn store_slot(&self, i: usize, d: T);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    Full,
    /// The peer's index is inconsistent with ours. Sticky: the ring is not
    /// used again (fail-closed).
    Corrupt,
}

struct Mask<const N: usize>;

impl<const N: usize> Mask<N> {
    const VALUE: u32 = {
        assert!(N.is_power_of_two() && N <= (1 << 16), "N must be a power of two <= 65536");
        // N <= 65536, so this conversion is exact.
        (N as u32).wrapping_sub(1)
    };
}

fn slot<const N: usize>(idx: u32) -> usize {
    // Masked to < N, which fits in usize.
    (idx & Mask::<N>::VALUE) as usize
}

fn ring_len<const N: usize>() -> u32 {
    Mask::<N>::VALUE.wrapping_add(1)
}

pub struct Producer<A, T, const N: usize> {
    acc: A,
    write: u32,
    corrupt: bool,
    _slot: core::marker::PhantomData<T>,
}

impl<T: Copy, A: SharedAccess<T>, const N: usize> Producer<A, T, N> {
    pub fn new(acc: A) -> Self {
        Self { acc, write: 0, corrupt: false, _slot: core::marker::PhantomData }
    }

    pub fn push(&mut self, d: T) -> Result<(), RingError> {
        if self.corrupt {
            return Err(RingError::Corrupt);
        }
        let read = self.acc.load_peer_index();
        let used = self.write.wrapping_sub(read);
        if used > ring_len::<N>() {
            self.corrupt = true;
            return Err(RingError::Corrupt);
        }
        if used == ring_len::<N>() {
            return Err(RingError::Full);
        }
        self.acc.store_slot(slot::<N>(self.write), d);
        self.write = self.write.wrapping_add(1);
        self.acc.store_own_index(self.write);
        Ok(())
    }

    pub fn is_corrupt(&self) -> bool {
        self.corrupt
    }
}

pub struct Consumer<A, T, const N: usize> {
    acc: A,
    read: u32,
    corrupt: bool,
    _slot: core::marker::PhantomData<T>,
}

impl<T: Copy, A: SharedAccess<T>, const N: usize> Consumer<A, T, N> {
    pub fn new(acc: A) -> Self {
        Self { acc, read: 0, corrupt: false, _slot: core::marker::PhantomData }
    }

    pub fn pop(&mut self) -> Result<Option<T>, RingError> {
        if self.corrupt {
            return Err(RingError::Corrupt);
        }
        let write = self.acc.load_peer_index();
        let avail = write.wrapping_sub(self.read);
        if avail > ring_len::<N>() {
            self.corrupt = true;
            return Err(RingError::Corrupt);
        }
        if avail == 0 {
            return Ok(None);
        }
        let d = self.acc.load_slot(slot::<N>(self.read));
        self.read = self.read.wrapping_add(1);
        self.acc.store_own_index(self.read);
        Ok(Some(d))
    }

    pub fn is_corrupt(&self) -> bool {
        self.corrupt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescError {
    Misaligned,
    OutOfRange,
    TooLong,
    NotWithPeer,
}

/// `M` fixed-size buffers of `BUF` bytes in a data region, with ownership
/// tracked locally: a descriptor from the peer is accepted only for a buffer
/// this side currently believes the peer holds.
pub struct Pool<const M: usize, const BUF: usize> {
    mine: [bool; M],
}

impl<const M: usize, const BUF: usize> Pool<M, BUF> {
    /// `initially_mine` decides which side starts owning every buffer.
    pub const fn new(initially_mine: bool) -> Self {
        Self { mine: [initially_mine; M] }
    }

    pub const fn region_len() -> usize {
        M.saturating_mul(BUF)
    }

    /// Validates a descriptor received from the peer and takes ownership.
    pub fn accept(&mut self, d: Desc) -> Result<usize, DescError> {
        let offset = usize::try_from(d.offset).map_err(|_| DescError::OutOfRange)?;
        let len = usize::try_from(d.len).map_err(|_| DescError::TooLong)?;
        if BUF == 0 || offset.checked_rem(BUF) != Some(0) {
            return Err(DescError::Misaligned);
        }
        let idx = offset.checked_div(BUF).ok_or(DescError::Misaligned)?;
        if len > BUF {
            return Err(DescError::TooLong);
        }
        let owned = self.mine.get_mut(idx).ok_or(DescError::OutOfRange)?;
        if *owned {
            return Err(DescError::NotWithPeer);
        }
        *owned = true;
        Ok(idx)
    }

    /// Hands buffer `idx` to the peer with `len` valid bytes. Returns `None`
    /// if this side does not own it or `len` does not fit.
    pub fn give(&mut self, idx: usize, len: usize) -> Option<Desc> {
        if len > BUF {
            return None;
        }
        let owned = self.mine.get_mut(idx)?;
        if !*owned {
            return None;
        }
        let offset = u32::try_from(idx.checked_mul(BUF)?).ok()?;
        let len = u32::try_from(len).ok()?;
        *owned = false;
        Some(Desc { offset, len })
    }

    /// Takes the first buffer this side owns (for filling), without changing
    /// ownership.
    pub fn first_mine(&self) -> Option<usize> {
        self.mine.iter().position(|m| *m)
    }

    /// Number of buffers this side owns.
    pub fn mine_count(&self) -> usize {
        self.mine.iter().filter(|m| **m).count()
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
