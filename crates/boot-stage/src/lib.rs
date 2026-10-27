//! A PD's boot stage (M7 plan C9, Re-plan R1): init runs inside
//! [`run_init`], which lends an [`Init`] for that one call. A leaf PD that
//! refuses at boot for a deterministic, configuration-shaped cause (no key,
//! no seed, no rng, no clock) takes [`Init::boot_stop`] and returns the
//! [`Dormant`] it gets: the PD stays stopped, ignoring every event, and
//! nothing faults, so the supervisor never resets for it. Every other stop
//! (`halt`, a panic, an abort, an exception) is a fault and resets.
//!
//! Neither `Init` nor `Dormant` can be made outside this crate:
//!
//! ```compile_fail,E0451
//! let _ = boot_stage::Init { _not_send: core::marker::PhantomData };
//! ```
//!
//! ```compile_fail,E0603
//! let _ = boot_stage::Dormant(());
//! ```
//!
//! `Init` cannot outlive the call it was lent to:
//!
//! ```compile_fail,E0521
//! static mut KEPT: Option<&'static boot_stage::Init> = None;
//! boot_stage::run_init(|init| unsafe { KEPT = Some(init) });
//! ```
//!
//! An init that uses it compiles:
//!
//! ```
//! let ready = boot_stage::run_init(|_init| 7);
//! assert_eq!(ready, 7);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Lent to init alone; not `Send`, `Clone`, `Copy` or `Default`.
pub struct Init {
    _not_send: PhantomData<*const ()>,
}

/// A boot stop's handler state: holds nothing (R1 SE-D2), so every local
/// init held has been dropped (and a `Secret` zeroized) by the time a PD
/// returns it.
pub struct Dormant(());

static OPEN: AtomicBool = AtomicBool::new(true);

/// Runs `f`, the PD's init, with the one `Init` there will be. A second call
/// (from a handler, after init) panics, which is a fault and resets: a boot
/// stop cannot be taken at run time.
#[inline(never)]
pub fn run_init<T>(f: impl FnOnce(&Init) -> T) -> T {
    assert!(OPEN.swap(false, Ordering::SeqCst), "run_init after init");
    f(&Init { _not_send: PhantomData })
}

/// Closes the one shot without an init (a PD's first handler entry, in case
/// its init never called `run_init`).
pub fn close() {
    OPEN.store(false, Ordering::SeqCst);
}

impl Init {
    /// The boot stop: the caller has recorded its `Halted` reason; the PD
    /// goes dormant. Leaf PDs only (the `boot-stop` feature).
    #[cfg(feature = "boot-stop")]
    #[inline(never)]
    pub fn boot_stop(&self) -> Dormant {
        Dormant(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
