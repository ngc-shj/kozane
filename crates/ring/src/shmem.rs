//! The only `unsafe` in this crate: access to memory shared with another PD.
//!
//! Shared memory can change at any time under us, so it is never turned into
//! a Rust reference to plain data. Indices go through atomics; slots and
//! payload bytes go through volatile accesses on raw pointers.
#![allow(unsafe_code)]
// Offsets below are bounds-checked (or < N) before the addition is made.
#![allow(clippy::arithmetic_side_effects)]

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use core::marker::PhantomData;

use crate::SharedAccess;

/// Layout of one ring in shared memory: two indices, then `N` slots.
#[repr(C)]
struct Header {
    write: AtomicU32,
    read: AtomicU32,
}

const SLOTS_OFFSET: usize = core::mem::size_of::<Header>();

/// Bytes a ring with `N` slots of `T` occupies.
pub const fn ring_bytes<T, const N: usize>() -> usize {
    SLOTS_OFFSET + N * core::mem::size_of::<T>()
}

#[derive(Clone, Copy)]
enum Side {
    Producer,
    Consumer,
}

/// One side's view of a ring in shared memory.
pub struct ShmRing<T, const N: usize> {
    base: *mut u8,
    side: Side,
    _slot: PhantomData<T>,
}

impl<T: Copy, const N: usize> ShmRing<T, N> {
    /// # Safety
    /// `base` must be 4-byte aligned, valid for reads and writes of
    /// `ring_bytes::<T, N>()` bytes for the PD's lifetime, and mapped into
    /// exactly one other PD, which acts as the consumer. `T` must be valid
    /// for every bit pattern and have alignment <= 4.
    pub unsafe fn producer(base: *mut u8) -> Self {
        Self { base, side: Side::Producer, _slot: PhantomData }
    }

    /// # Safety
    /// As for `producer`, with the other PD acting as the producer.
    pub unsafe fn consumer(base: *mut u8) -> Self {
        Self { base, side: Side::Consumer, _slot: PhantomData }
    }

    fn header(&self) -> &Header {
        // SAFETY: `base` is valid and aligned per the constructor contract,
        // and `Header` holds only atomics, which tolerate concurrent writes.
        unsafe { &*(self.base as *const Header) }
    }

    fn slot_ptr(&self, i: usize) -> *mut T {
        // Callers pass a masked index (< N); checked anyway so a bug here
        // halts the PD (fail-closed) instead of touching memory past the ring.
        assert!(i < N, "ring slot index out of range");
        // SAFETY: offset is within `ring_bytes::<T, N>()` because i < N.
        unsafe { self.base.add(SLOTS_OFFSET).cast::<T>().add(i) }
    }
}

impl<T: Copy, const N: usize> SharedAccess<T> for ShmRing<T, N> {
    fn load_peer_index(&self) -> u32 {
        let h = self.header();
        match self.side {
            Side::Producer => h.read.load(Ordering::Acquire),
            Side::Consumer => h.write.load(Ordering::Acquire),
        }
    }

    fn store_own_index(&self, v: u32) {
        let h = self.header();
        match self.side {
            Side::Producer => h.write.store(v, Ordering::Release),
            Side::Consumer => h.read.store(v, Ordering::Release),
        }
    }

    fn load_slot(&self, i: usize) -> T {
        // SAFETY: in bounds (i < N); volatile because the peer may write it.
        unsafe { ptr::read_volatile(self.slot_ptr(i)) }
    }

    fn store_slot(&self, i: usize, d: T) {
        // SAFETY: in bounds (i < N).
        unsafe { ptr::write_volatile(self.slot_ptr(i), d) }
    }
}

/// A shared data region holding the buffers that descriptors point into.
pub struct Region {
    base: *mut u8,
    len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfBounds;

impl Region {
    /// # Safety
    /// `base` must be valid for reads (and, if `write_from` is used, writes)
    /// of `len` bytes for the PD's lifetime.
    pub unsafe fn new(base: *mut u8, len: usize) -> Self {
        Self { base, len }
    }

    fn check(&self, offset: usize, len: usize) -> Result<(), OutOfBounds> {
        match offset.checked_add(len) {
            Some(end) if end <= self.len => Ok(()),
            _ => Err(OutOfBounds),
        }
    }

    /// Copies `out.len()` bytes starting at `offset` into private memory.
    /// This is the copy-in step: parsers only ever see `out`.
    pub fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), OutOfBounds> {
        self.check(offset, out.len())?;
        for (i, b) in out.iter_mut().enumerate() {
            // SAFETY: offset + i < offset + out.len() <= self.len (checked).
            *b = unsafe { ptr::read_volatile(self.base.add(offset + i)) };
        }
        Ok(())
    }

    pub fn write_from(&self, offset: usize, data: &[u8]) -> Result<(), OutOfBounds> {
        self.check(offset, data.len())?;
        for (i, b) in data.iter().enumerate() {
            // SAFETY: offset + i < offset + data.len() <= self.len (checked).
            unsafe { ptr::write_volatile(self.base.add(offset + i), *b) };
        }
        Ok(())
    }
}
