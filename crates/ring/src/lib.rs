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
//!
//! Verus (M4 plan C6) proves the pure index and ownership logic unbounded,
//! for any admissible `N`/`M`/`BUF`: `slot`, `ring_len`, `Pool::{accept,
//! give, first_mine, mine_count}` and `link::Receiver`'s held-buffer guard.
//! `SharedAccess` and `shmem::Region` stay outside `verus!`, unverified:
//! they are plain Rust traits/raw-pointer code, not pure functions, and
//! Kani keeps exercising them (`proofs.rs`), bounded but wired up end to
//! end.

#![no_std]
#![deny(
    unsafe_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::lemma_fundamental_div_mod;
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::mul::lemma_mul_is_commutative;
use vstd::prelude::*;

pub mod link;
pub mod pass;
pub mod shmem;

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

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Desc {
    pub offset: u32,
    pub len: u32,
}

// `slot`/`ring_len`'s own masking logic (M4 plan C6), proven directly for
// any admissible `N` rather than through `Mask`'s `assert!`-guarded const,
// which Verus's const evaluator cannot translate — the same gap wg-wire's
// `ReplayWindow::WINDOW` hit with `saturating_sub` (M4 plan V1). `Mask`
// itself is unchanged; `Producer::new`/`Consumer::new` now read
// `Mask::<N>::VALUE` to keep its compile-time check of the bound, since
// `slot`/`ring_len` no longer do.

/// The slot a ring index lands in: `idx & (N - 1)`, always inside the
/// region (`< N`). Valid for `N` a power of two in `1..=65536`.
#[inline]
fn slot<const N: usize>(idx: u32) -> (r: usize)
    requires
        0 < N <= 65536,
        N & ((N - 1) as usize) == 0,
    ensures
        r == (idx & ((N - 1) as u32)) as usize,
        r < N,
{
    let mask: u32 = (N as u32).wrapping_sub(1);
    let r = (idx & mask) as usize;
    // AND never exceeds either operand: no fact about `N` enters this
    // check, only the concrete `mask`/`idx` values, so it sidesteps a
    // Verus crash on `N` (a const generic) inside `by (bit_vector)`.
    assert(idx & mask <= mask) by (bit_vector);
    assert(r < N);
    r
}

/// The ring's length, `N` itself. Valid for the same `N` as `slot`.
#[inline]
fn ring_len<const N: usize>() -> (r: u32)
    requires
        0 < N <= 65536,
        N & ((N - 1) as usize) == 0,
    ensures
        r == N as u32,
{
    N as u32
}

} // verus!

pub struct Producer<A, T, const N: usize> {
    acc: A,
    write: u32,
    corrupt: bool,
    _slot: core::marker::PhantomData<T>,
}

impl<T: Copy, A: SharedAccess<T>, const N: usize> Producer<A, T, N> {
    pub fn new(acc: A) -> Self {
        // Compile-time: N must be a power of two <= 65536. `slot`/`ring_len`
        // no longer read `Mask::<N>::VALUE` (Verus proves their masking
        // directly instead), so this is now the trigger site.
        let _ = Mask::<N>::VALUE;
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
        let _ = Mask::<N>::VALUE;
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

verus! {

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

/// The count of `true` entries in `s[0..n]`, used by `mine_count`'s spec.
pub open spec fn count_true(s: Seq<bool>, n: int) -> int
    decreases n,
{
    if n <= 0 {
        0
    } else if s[n - 1] {
        1 + count_true(s, n - 1)
    } else {
        count_true(s, n - 1)
    }
}

} // verus!

impl<const M: usize, const BUF: usize> Pool<M, BUF> {
    /// `initially_mine` decides which side starts owning every buffer.
    pub const fn new(initially_mine: bool) -> Self {
        Self { mine: [initially_mine; M] }
    }

    pub const fn region_len() -> usize {
        M.saturating_mul(BUF)
    }
}

verus! {

impl<const M: usize, const BUF: usize> Pool<M, BUF> {
    /// Whether this side owns buffer `i`: the public, opaque view of the
    /// private `mine` field that contracts use (M4 plan C6; the
    /// `ReplayWindow::has_accepted` pattern).
    pub closed spec fn owns(&self, i: int) -> bool {
        self.mine@[i]
    }

    /// The whole ownership state, as a `Seq`: the opaque view `accept`'s
    /// and `give`'s contracts state their one-slot transition against.
    pub closed spec fn mine_seq(&self) -> Seq<bool> {
        self.mine@
    }

    /// The count of buffers this side owns: the public, opaque view
    /// `mine_count`'s contract states its result against.
    pub closed spec fn owned_count(&self) -> int {
        count_true(self.mine@, M as int)
    }

    /// Validates a descriptor received from the peer and takes ownership.
    /// No buffer is ever owned by both sides (M4 plan C6): `accept` only
    /// ever flips an unowned buffer (`!old(self).owns(i)`) to owned, and
    /// leaves every other buffer's ownership untouched.
    pub fn accept(&mut self, d: Desc) -> (r: Result<usize, DescError>)
        ensures
            r is Ok ==> {
                let i = r->Ok_0;
                &&& i < M
                &&& !old(self).owns(i as int)
                &&& final(self).mine_seq() == old(self).mine_seq().update(i as int, true)
                &&& d.offset as int == i as int * BUF as int
                &&& d.len as int <= BUF as int
            },
            r is Err ==> final(self).mine_seq() == old(self).mine_seq(),
    {
        proof {
            reveal(Pool::owns);
            reveal(Pool::mine_seq);
        }
        let offset = match usize::try_from(d.offset) {
            Ok(v) => v,
            Err(_) => return Err(DescError::OutOfRange),
        };
        let len = match usize::try_from(d.len) {
            Ok(v) => v,
            Err(_) => return Err(DescError::TooLong),
        };
        if BUF == 0 {
            return Err(DescError::Misaligned);
        }
        match offset.checked_rem(BUF) {
            Some(0) => {},
            _ => return Err(DescError::Misaligned),
        }
        let idx = match offset.checked_div(BUF) {
            Some(v) => v,
            None => return Err(DescError::Misaligned),
        };
        if len > BUF {
            return Err(DescError::TooLong);
        }
        let owned = match self.mine.get_mut(idx) {
            Some(v) => v,
            None => return Err(DescError::OutOfRange),
        };
        if *owned {
            return Err(DescError::NotWithPeer);
        }
        proof {
            // `offset % BUF == 0` (checked above) and the fundamental
            // div/mod identity give `offset == BUF * idx`; `d.offset`
            // equals `offset` via the `try_from` just above.
            lemma_fundamental_div_mod(offset as int, BUF as int);
            lemma_mul_is_commutative(BUF as int, idx as int);
        }
        *owned = true;
        Ok(idx)
    }

    /// Hands buffer `idx` to the peer with `len` valid bytes. Returns `None`
    /// if this side does not own it or `len` does not fit. `give` only ever
    /// flips an owned buffer (`old(self).owns(idx)`) to not-owned (M4 plan
    /// C6), leaving every other buffer's ownership untouched.
    pub fn give(&mut self, idx: usize, len: usize) -> (r: Option<Desc>)
        ensures
            r is Some ==> {
                let back = r->Some_0;
                &&& idx < M
                &&& old(self).owns(idx as int)
                &&& final(self).mine_seq() == old(self).mine_seq().update(idx as int, false)
                &&& back.offset as int == idx as int * BUF as int
                &&& back.len as int == len as int
            },
            r is None ==> final(self).mine_seq() == old(self).mine_seq(),
    {
        proof {
            reveal(Pool::owns);
            reveal(Pool::mine_seq);
        }
        if len > BUF {
            return None;
        }
        let owned = self.mine.get_mut(idx)?;
        if !*owned {
            return None;
        }
        let product = idx.checked_mul(BUF)?;
        let offset = match u32::try_from(product) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let len_u32 = match u32::try_from(len) {
            Ok(v) => v,
            Err(_) => return None,
        };
        *owned = false;
        Some(Desc { offset, len: len_u32 })
    }

    /// The first buffer this side owns (for filling), without changing
    /// ownership.
    pub fn first_mine(&self) -> (r: Option<usize>)
        ensures
            r is Some ==> {
                let i = r->Some_0;
                i < M && self.owns(i as int)
            },
            r is None ==> forall|j: int| 0 <= j < M as int ==> !self.owns(j),
    {
        proof {
            reveal(Pool::owns);
        }
        let mut i: usize = 0;
        while i < M
            invariant
                i <= M,
                forall|j: int| 0 <= j < i as int ==> !self.owns(j),
            decreases M - i,
        {
            // Not collapsed into a let-chain: Verus does not yet support it.
            #[allow(clippy::collapsible_if)]
            if let Some(v) = self.mine.get(i) {
                if *v {
                    return Some(i);
                }
            }
            i = i.wrapping_add(1);
        }
        None
    }

    /// Number of buffers this side owns.
    pub fn mine_count(&self) -> (r: usize)
        ensures
            r as int == self.owned_count(),
    {
        proof {
            reveal(Pool::owned_count);
        }
        let mut i: usize = 0;
        let mut count: usize = 0;
        while i < M
            invariant
                i <= M,
                count <= i,
                count as int == count_true(self.mine@, i as int),
            decreases M - i,
        {
            match self.mine.get(i) {
                Some(v) => {
                    if *v {
                        count = count.wrapping_add(1);
                    }
                },
                None => {
                    // `i < M == self.mine@.len()`, so `get` always hits.
                    assert(false);
                },
            }
            // One step of `count_true`'s own recursive definition.
            assert(count as int == count_true(self.mine@, i as int + 1)) by {
                reveal(count_true);
            };
            i = i.wrapping_add(1);
        }
        count
    }
}

} // verus!

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
