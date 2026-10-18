#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]

extern crate std;

use core::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;

/// In-memory ring shared by a test producer and consumer.
#[derive(Default)]
struct Mem {
    write: Cell<u32>,
    read: Cell<u32>,
    slots: RefCell<[Desc; 4]>,
}

struct ProdSide(Rc<Mem>);
struct ConsSide(Rc<Mem>);

impl SharedAccess<Desc> for ProdSide {
    fn load_peer_index(&self) -> u32 {
        self.0.read.get()
    }
    fn store_own_index(&self, v: u32) {
        self.0.write.set(v);
    }
    fn load_slot(&self, i: usize) -> Desc {
        self.0.slots.borrow()[i]
    }
    fn store_slot(&self, i: usize, d: Desc) {
        self.0.slots.borrow_mut()[i] = d;
    }
}

impl SharedAccess<Desc> for ConsSide {
    fn load_peer_index(&self) -> u32 {
        self.0.write.get()
    }
    fn store_own_index(&self, v: u32) {
        self.0.read.set(v);
    }
    fn load_slot(&self, i: usize) -> Desc {
        self.0.slots.borrow()[i]
    }
    fn store_slot(&self, i: usize, d: Desc) {
        self.0.slots.borrow_mut()[i] = d;
    }
}

fn pair() -> (Producer<ProdSide, Desc, 4>, Consumer<ConsSide, Desc, 4>, Rc<Mem>) {
    let m = Rc::new(Mem::default());
    (Producer::new(ProdSide(m.clone())), Consumer::new(ConsSide(m.clone())), m)
}

fn d(n: u32) -> Desc {
    Desc { offset: n, len: n }
}

#[test]
fn empty_ring_pops_none() {
    let (_, mut c, _) = pair();
    assert_eq!(c.pop(), Ok(None));
}

#[test]
fn fifo_order_across_wraparound() {
    let (mut p, mut c, _) = pair();
    for round in 0..10u32 {
        for i in 0..3 {
            p.push(d(round * 3 + i)).unwrap();
        }
        for i in 0..3 {
            assert_eq!(c.pop(), Ok(Some(d(round * 3 + i))));
        }
    }
    assert_eq!(c.pop(), Ok(None));
}

#[test]
fn full_after_n_pushes_then_accepts_after_pop() {
    let (mut p, mut c, _) = pair();
    for i in 0..4 {
        p.push(d(i)).unwrap();
    }
    assert_eq!(p.push(d(9)), Err(RingError::Full));
    c.pop().unwrap();
    assert_eq!(p.push(d(9)), Ok(()));
}

#[test]
fn indices_survive_u32_wrap() {
    let (mut p, mut c, m) = pair();
    p.write = u32::MAX - 1;
    c.read = u32::MAX - 1;
    m.write.set(u32::MAX - 1);
    m.read.set(u32::MAX - 1);
    for i in 0..4 {
        p.push(d(i)).unwrap();
        assert_eq!(c.pop(), Ok(Some(d(i))));
    }
}

#[test]
fn consumer_marks_corrupt_when_peer_claims_more_than_n() {
    let (_, mut c, m) = pair();
    m.write.set(5);
    assert_eq!(c.pop(), Err(RingError::Corrupt));
    // Sticky even after the peer "fixes" its index.
    m.write.set(0);
    assert_eq!(c.pop(), Err(RingError::Corrupt));
    assert!(c.is_corrupt());
}

#[test]
fn producer_marks_corrupt_when_peer_read_runs_ahead() {
    let (mut p, _, m) = pair();
    m.read.set(1); // consumer claims to have read an item never written
    assert_eq!(p.push(d(0)), Err(RingError::Corrupt));
    assert!(p.is_corrupt());
}

#[test]
fn consumer_index_exactly_n_ahead_is_still_valid() {
    let (_, mut c, m) = pair();
    m.write.set(4);
    assert!(matches!(c.pop(), Ok(Some(_))));
}

type P = Pool<4, 2048>;

#[test]
fn pool_round_trip_give_then_accept() {
    let mut mine = P::new(true);
    let desc = mine.give(2, 100).unwrap();
    assert_eq!(desc, Desc { offset: 4096, len: 100 });
    assert_eq!(mine.accept(desc), Ok(2));
}

#[test]
fn pool_rejects_buffer_we_already_own() {
    let mut pool = P::new(true);
    assert_eq!(pool.accept(Desc { offset: 0, len: 1 }), Err(DescError::NotWithPeer));
}

#[test]
fn pool_rejects_double_return() {
    let mut pool = P::new(false);
    let desc = Desc { offset: 2048, len: 10 };
    assert_eq!(pool.accept(desc), Ok(1));
    assert_eq!(pool.accept(desc), Err(DescError::NotWithPeer));
}

#[test]
fn pool_rejects_misaligned_out_of_range_and_too_long() {
    let mut pool = P::new(false);
    assert_eq!(pool.accept(Desc { offset: 1, len: 1 }), Err(DescError::Misaligned));
    assert_eq!(pool.accept(Desc { offset: 4 * 2048, len: 1 }), Err(DescError::OutOfRange));
    // Largest aligned u32 offset: aligned, but far outside the region.
    assert_eq!(pool.accept(Desc { offset: u32::MAX - 2047, len: 1 }), Err(DescError::OutOfRange));
    assert_eq!(pool.accept(Desc { offset: 0, len: 2049 }), Err(DescError::TooLong));
}

#[test]
fn pool_give_refuses_unowned_or_oversized() {
    let mut pool = P::new(false);
    assert_eq!(pool.give(0, 1), None);
    let mut pool = P::new(true);
    assert_eq!(pool.give(0, 2049), None);
    assert_eq!(pool.give(4, 1), None);
}

mod link_tests {
    #![allow(unsafe_code)]

    use super::*;
    use crate::link::{LinkError, Receiver, Sender};
    use crate::shmem::{Region, ShmRing, ring_bytes};
    use std::boxed::Box;
    use std::vec;

    const N: usize = 4;
    const M: usize = 4;
    const BUF: usize = 64;

    /// Shared memory for one direction, leaked so raw pointers stay valid.
    struct Shm {
        used: *mut u8,
        free: *mut u8,
        data: *mut u8,
    }

    fn shm() -> Shm {
        let alloc = |n: usize| Box::leak(vec![0u32; n.div_ceil(4)].into_boxed_slice()).as_mut_ptr().cast::<u8>();
        Shm { used: alloc(ring_bytes::<Desc, N>()), free: alloc(ring_bytes::<Desc, N>()), data: alloc(M * BUF) }
    }

    type Tx = Sender<ShmRing<Desc, N>, ShmRing<Desc, N>, N, M, BUF>;
    type Rx = Receiver<ShmRing<Desc, N>, ShmRing<Desc, N>, N, M, BUF>;

    fn link() -> (Tx, Rx, Shm) {
        let s = shm();
        // SAFETY: each region is leaked, aligned and sized for its use.
        let tx = unsafe {
            Sender::new(ShmRing::producer(s.used), ShmRing::consumer(s.free), Region::new(s.data, M * BUF))
        };
        let rx = unsafe {
            Receiver::new(ShmRing::consumer(s.used), ShmRing::producer(s.free), Region::new(s.data, M * BUF))
        };
        (tx, rx, s)
    }

    fn send(tx: &mut Tx, payload: &[u8]) -> Result<bool, LinkError> {
        let mut scratch = [0u8; BUF];
        tx.send_with(&mut scratch, |b| {
            b[..payload.len()].copy_from_slice(payload);
            Some(payload.len())
        })
    }

    #[test]
    fn payload_round_trips_and_buffer_returns() {
        let (mut tx, mut rx, _s) = link();
        let mut out = [0u8; BUF];
        for i in 0..20u8 {
            tx.reclaim().unwrap();
            assert_eq!(send(&mut tx, &[i, i + 1, i + 2]), Ok(true));
            assert_eq!(rx.recv_into(&mut out), Ok(Some(3)));
            assert_eq!(&out[..3], &[i, i + 1, i + 2]);
        }
    }

    #[test]
    fn sender_runs_out_of_buffers_until_receiver_returns_them() {
        let (mut tx, mut rx, _s) = link();
        for _ in 0..M {
            send(&mut tx, b"x").unwrap();
        }
        assert_eq!(send(&mut tx, b"x"), Err(LinkError::NoBuffer));
        let mut out = [0u8; BUF];
        rx.recv_into(&mut out).unwrap();
        tx.reclaim().unwrap();
        assert_eq!(send(&mut tx, b"x"), Ok(true));
    }

    #[test]
    fn receiver_rejects_forged_descriptor_and_keeps_working() {
        let (_tx, mut rx, s) = link();
        let mut forger: Producer<ShmRing<Desc, N>, Desc, N> =
            Producer::new(unsafe { ShmRing::producer(s.used) });
        forger.push(Desc { offset: 3, len: 1 }).unwrap(); // misaligned
        forger.push(Desc { offset: 0, len: (BUF + 1) as u32 }).unwrap(); // too long
        forger.push(Desc { offset: 0, len: 2 }).unwrap(); // valid
        let mut out = [0u8; BUF];
        assert!(matches!(rx.recv_into(&mut out), Err(LinkError::BadDesc(_))));
        assert!(matches!(rx.recv_into(&mut out), Err(LinkError::BadDesc(_))));
        assert_eq!(rx.recv_into(&mut out), Ok(Some(2)));
    }

    #[test]
    fn sender_rejects_forged_return() {
        let (mut tx, _rx, s) = link();
        let mut forger: Producer<ShmRing<Desc, N>, Desc, N> =
            Producer::new(unsafe { ShmRing::producer(s.free) });
        forger.push(Desc { offset: 0, len: 0 }).unwrap(); // never sent
        assert!(matches!(tx.reclaim(), Err(LinkError::BadDesc(_))));
    }
}
