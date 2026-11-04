//! One value in a mapping the harness owns, so that its bytes can be read
//! back after a call: where the initiator's state, and so its handshake
//! secrets, live. With `stack.rs`, the only module with `unsafe`.

#![allow(unsafe_code)]

use std::mem::{align_of, size_of};

const PAGE: usize = 4096;

pub struct Arena<T> {
    slot: *mut T,
    map: usize,
}

impl<T> Arena<T> {
    pub fn new(value: T) -> Self {
        assert!(align_of::<T>() <= PAGE);
        let map = size_of::<T>().div_ceil(PAGE).max(1) * PAGE;
        // SAFETY: a fresh private anonymous mapping; no existing memory is
        // touched. The result is checked before use.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(base != libc::MAP_FAILED, "mmap");
        let slot = base.cast::<T>();
        // SAFETY: page-aligned (so aligned for `T`), `size_of::<T>() <= map`
        // bytes, unaliased.
        unsafe { slot.write(value) };
        Self { slot, map }
    }

    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: `slot` holds a live `T` for the life of `self`, borrowed
        // exclusively through `&mut self`.
        unsafe { &mut *self.slot }
    }

    /// The value's bytes. Padding is read as whatever the mapping holds
    /// there: the region is scanned, never interpreted.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping is readable for `map >= size_of::<T>()` bytes
        // for the life of `self`, and nothing writes it while `&self` is
        // borrowed.
        unsafe { std::slice::from_raw_parts(self.slot.cast::<u8>(), size_of::<T>()) }
    }
}

impl<T> Drop for Arena<T> {
    fn drop(&mut self) {
        // SAFETY: the live `T` written in `new`, dropped once, then the
        // mapping made there.
        unsafe {
            self.slot.drop_in_place();
            libc::munmap(self.slot.cast(), self.map);
        }
    }
}
