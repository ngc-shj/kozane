//! A thread stack the harness owns, for the residue scan (M4 plan C9).
//! Besides `vg.rs`, this is the only module with `unsafe`: mapping the
//! stack, running a thread on it, and reading it back after the join.
//!
//! The stack is an anonymous `mmap` with a `PROT_NONE` guard page below
//! it, handed to `pthread_create` through `pthread_attr_setstack`. glibc
//! never frees or reuses a stack the caller supplied, so after
//! `pthread_join` the memory is still mapped, no thread runs on it, and
//! its bytes are exactly what the thread left there. `bytes` borrows the
//! stack, so it cannot be read while `run` has a thread on it.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::MaybeUninit;

const PAGE: usize = 4096;

pub struct OwnedStack {
    base: *mut u8,
    len: usize,
}

impl OwnedStack {
    /// `len` bytes of stack (a multiple of the page size), plus a guard
    /// page.
    pub fn new(len: usize) -> Self {
        assert!(len.is_multiple_of(PAGE) && len >= libc::PTHREAD_STACK_MIN);
        // SAFETY: a fresh private anonymous mapping; no existing memory is
        // touched. The result is checked before use.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len + PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(map != libc::MAP_FAILED, "mmap");
        // SAFETY: the first page of the mapping just made.
        assert_eq!(
            unsafe { libc::mprotect(map, PAGE, libc::PROT_NONE) },
            0,
            "mprotect"
        );
        // SAFETY: `PAGE < len + PAGE`, inside the mapping.
        Self {
            base: unsafe { map.cast::<u8>().add(PAGE) },
            len,
        }
    }

    /// The stack, lowest address first.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `base..base+len` is mapped readable and writable for the
        // life of `self`; no thread runs on it outside `run`, which takes
        // `&mut self`.
        unsafe { std::slice::from_raw_parts(self.base, self.len) }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`, exclusively borrowed.
        unsafe { std::slice::from_raw_parts_mut(self.base, self.len) }
    }

    /// Runs `f` on a new thread whose stack is this mapping, and joins it.
    pub fn run<F: FnOnce() + Send>(&mut self, f: F) {
        extern "C" fn start<F: FnOnce()>(arg: *mut c_void) -> *mut c_void {
            // SAFETY: `arg` is the `Box<F>` leaked by `run` for this thread
            // alone.
            let f = unsafe { Box::from_raw(arg.cast::<F>()) };
            f();
            std::ptr::null_mut()
        }

        let arg = Box::into_raw(Box::new(f)).cast::<c_void>();
        let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();
        let mut tid = MaybeUninit::<libc::pthread_t>::uninit();
        // SAFETY: `attr` is initialised before use and destroyed after;
        // the stack is this mapping, unused by any other thread. The thread
        // is joined before `run` returns, so `f`'s borrows (only `Send`
        // ones) outlive it; panics abort, so nothing unwinds past the join.
        unsafe {
            assert_eq!(libc::pthread_attr_init(attr.as_mut_ptr()), 0);
            assert_eq!(
                libc::pthread_attr_setstack(attr.as_mut_ptr(), self.base.cast(), self.len),
                0
            );
            let r = libc::pthread_create(tid.as_mut_ptr(), attr.as_ptr(), start::<F>, arg);
            libc::pthread_attr_destroy(attr.as_mut_ptr());
            if r != 0 {
                drop(Box::from_raw(arg.cast::<F>()));
                panic!("pthread_create: {r}");
            }
            assert_eq!(
                libc::pthread_join(tid.assume_init(), std::ptr::null_mut()),
                0
            );
        }
    }
}

impl Drop for OwnedStack {
    fn drop(&mut self) {
        // SAFETY: the mapping made in `new`, guard page included; no thread
        // runs on it (`run` joins).
        unsafe { libc::munmap(self.base.sub(PAGE).cast(), self.len + PAGE) };
    }
}
