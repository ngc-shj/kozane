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

    fn region_bytes(s: &Shm) -> std::vec::Vec<u8> {
        // SAFETY: `data` is a leaked allocation of M * BUF bytes.
        unsafe { core::slice::from_raw_parts(s.data, M * BUF) }.to_vec()
    }

    #[test]
    fn scrubbing_sender_zeroes_returned_buffers() {
        let s = shm();
        // Shared pages are not guaranteed to start zeroed on the target.
        // Seed boot-time residue and require the scrubbing constructor to
        // establish the link's clean baseline before its first send.
        // SAFETY: `data` is a leaked allocation of M * BUF bytes.
        unsafe { core::slice::from_raw_parts_mut(s.data, M * BUF) }.fill(0xa5);
        // SAFETY: as in `link`.
        let (mut tx, mut rx): (Tx, Rx) = unsafe {
            (
                Sender::new_scrubbing(ShmRing::producer(s.used), ShmRing::consumer(s.free), Region::new(s.data, M * BUF)),
                Receiver::new(ShmRing::consumer(s.used), ShmRing::producer(s.free), Region::new(s.data, M * BUF)),
            )
        };
        assert!(region_bytes(&s).iter().all(|b| *b == 0));
        assert_eq!(send(&mut tx, b"secret key bytes"), Ok(true));
        assert!(region_bytes(&s).windows(6).any(|w| w == b"secret"));
        let mut out = [0u8; BUF];
        assert_eq!(rx.recv_into(&mut out), Ok(Some(16)));
        tx.reclaim().unwrap();
        assert!(region_bytes(&s).iter().all(|b| *b == 0));
    }

    #[test]
    fn plain_sender_leaves_returned_buffers_alone() {
        let (mut tx, mut rx, s) = link();
        assert_eq!(send(&mut tx, b"payload"), Ok(true));
        rx.recv_into(&mut [0u8; BUF]).unwrap();
        tx.reclaim().unwrap();
        assert!(region_bytes(&s).windows(7).any(|w| w == b"payload"));
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

    // ---- held receive (M3b plan C3, F17) ----

    use crate::link::Taken;

    #[test]
    fn a_taken_message_stays_in_flight_until_release() {
        let (mut tx, mut rx, _s) = link();
        assert_eq!(send(&mut tx, b"held"), Ok(true));
        let mut out = [0u8; BUF];
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Payload(4))));
        assert_eq!(&out[..4], b"held");
        // The sender still counts the message being worked on.
        assert_eq!(tx.in_flight(), Ok(1));
        assert_eq!(rx.release(), Ok(()));
        assert_eq!(tx.in_flight(), Ok(0));
    }

    #[test]
    fn a_second_take_or_receive_before_release_is_refused() {
        let (mut tx, mut rx, _s) = link();
        send(&mut tx, b"a").unwrap();
        send(&mut tx, b"b").unwrap();
        let mut out = [0u8; BUF];
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Payload(1))));
        assert_eq!(rx.take_into(&mut out), Err(LinkError::Held));
        assert_eq!(rx.recv_into(&mut out), Err(LinkError::Held));
        // The refusals took nothing: the second message is still queued.
        rx.release().unwrap();
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Payload(1))));
        assert_eq!(out[0], b'b');
    }

    #[test]
    fn release_with_nothing_held_is_refused() {
        let (_tx, mut rx, _s) = link();
        assert_eq!(rx.release(), Err(LinkError::NoBuffer));
    }

    #[test]
    fn a_take_on_an_empty_link_holds_nothing() {
        let (_tx, mut rx, _s) = link();
        let mut out = [0u8; BUF];
        assert_eq!(rx.take_into(&mut out), Ok(None));
        assert_eq!(rx.release(), Err(LinkError::NoBuffer));
    }

    #[test]
    fn a_bad_descriptor_holds_nothing_and_the_next_take_works() {
        let (_tx, mut rx, s) = link();
        let mut forger: Producer<ShmRing<Desc, N>, Desc, N> =
            Producer::new(unsafe { ShmRing::producer(s.used) });
        forger.push(Desc { offset: 3, len: 1 }).unwrap(); // misaligned
        forger.push(Desc { offset: 0, len: 2 }).unwrap(); // valid
        let mut out = [0u8; BUF];
        assert!(matches!(rx.take_into(&mut out), Err(LinkError::BadDesc(_))));
        assert_eq!(rx.release(), Err(LinkError::NoBuffer));
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Payload(2))));
    }

    #[test]
    fn a_copy_failure_after_accept_is_unreadable_and_stays_held() {
        let s = shm();
        // The receiver's view of the data region covers only buffer 0, so
        // the accepted descriptor for buffer 1 cannot be copied.
        // SAFETY: as in `link`; the receiver's region is a prefix of it.
        let (mut tx, mut rx): (Tx, Rx) = unsafe {
            (
                Sender::new(ShmRing::producer(s.used), ShmRing::consumer(s.free), Region::new(s.data, M * BUF)),
                Receiver::new(ShmRing::consumer(s.used), ShmRing::producer(s.free), Region::new(s.data, BUF)),
            )
        };
        send(&mut tx, b"zero").unwrap();
        send(&mut tx, b"one").unwrap();
        let mut out = [0u8; BUF];
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Payload(4))));
        rx.release().unwrap();
        // Unreadable, not an error, and the buffer has not gone back.
        assert_eq!(rx.take_into(&mut out), Ok(Some(Taken::Unreadable)));
        assert_eq!(tx.in_flight(), Ok(1));
        assert_eq!(rx.take_into(&mut out), Err(LinkError::Held));
        rx.release().unwrap();
        assert_eq!(tx.in_flight(), Ok(0));
    }

    #[test]
    fn a_failed_release_kills_the_link() {
        let (mut tx, mut rx, s) = link();
        send(&mut tx, b"x").unwrap();
        let mut out = [0u8; BUF];
        rx.take_into(&mut out).unwrap();
        // The sender claims to have read a return never written.
        // SAFETY: `read` is the second header field of the leaked, aligned ring.
        unsafe { s.free.cast::<u32>().add(1).write_volatile(1) };
        assert_eq!(rx.release(), Err(LinkError::Corrupt));
        assert_eq!(rx.take_into(&mut out), Err(LinkError::Corrupt));
        assert_eq!(rx.release(), Err(LinkError::Corrupt));
    }

    #[test]
    fn link_is_dead_after_peer_stalls_its_read_index() {
        // A receiver that returns buffers but never advances its read index
        // makes the used ring look full; the sender must stop for good
        // instead of leaking a buffer per call.
        let (mut tx, _rx, s) = link();
        let mut stall: Producer<ShmRing<Desc, N>, Desc, N> =
            Producer::new(unsafe { ShmRing::producer(s.free) });
        for i in 0..M {
            send(&mut tx, b"x").unwrap();
            stall.push(Desc { offset: (i * BUF) as u32, len: 0 }).unwrap();
        }
        tx.reclaim().unwrap();
        assert_eq!(send(&mut tx, b"x"), Err(LinkError::Corrupt));
        assert_eq!(send(&mut tx, b"x"), Err(LinkError::Corrupt));
        assert_eq!(tx.reclaim(), Err(LinkError::Corrupt));
    }

    #[test]
    fn in_flight_and_free_start_with_every_buffer_owned() {
        let (mut tx, _rx, _s) = link();
        assert_eq!(tx.in_flight(), Ok(0));
        assert_eq!(tx.free(), Ok(M));
    }

    #[test]
    fn in_flight_counts_each_send() {
        let (mut tx, _rx, _s) = link();
        send(&mut tx, b"x").unwrap();
        send(&mut tx, b"y").unwrap();
        assert_eq!(tx.in_flight(), Ok(2));
        assert_eq!(tx.free(), Ok(M - 2));
    }

    #[test]
    fn in_flight_is_exact_after_returns_without_an_explicit_reclaim() {
        // The count must include buffers the receiver has returned but the
        // sender has not yet reclaimed, before the next send.
        let (mut tx, mut rx, _s) = link();
        for _ in 0..M {
            send(&mut tx, b"x").unwrap();
        }
        let mut out = [0u8; BUF];
        rx.recv_into(&mut out).unwrap();
        rx.recv_into(&mut out).unwrap();
        assert_eq!(tx.in_flight(), Ok(M - 2));
        rx.recv_into(&mut out).unwrap();
        assert_eq!(tx.free(), Ok(3));
    }

    #[test]
    fn in_flight_and_free_fail_on_a_dead_link() {
        let (mut tx, _rx, s) = link();
        // A free-ring write index more than N ahead marks the link corrupt.
        // SAFETY: `write` is the first header field of the leaked, aligned ring.
        unsafe { s.free.cast::<u32>().write_volatile((N as u32) + 1) };
        assert_eq!(tx.in_flight(), Err(LinkError::Corrupt));
        assert_eq!(tx.free(), Err(LinkError::Corrupt));
    }

    #[test]
    fn in_flight_reports_a_forged_return() {
        let (mut tx, _rx, s) = link();
        let mut forger: Producer<ShmRing<Desc, N>, Desc, N> =
            Producer::new(unsafe { ShmRing::producer(s.free) });
        forger.push(Desc { offset: 0, len: 0 }).unwrap(); // never sent
        assert!(matches!(tx.in_flight(), Err(LinkError::BadDesc(_))));
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

// ---- pass ----

/// A PD stand-in: `full` passes find an input at its cap, then one does not.
struct FakePass {
    full: usize,
    log: std::vec::Vec<&'static str>,
}

impl pass::Pass for FakePass {
    fn serve(&mut self) -> bool {
        self.log.push("serve");
        let more = self.full > 0;
        self.full = self.full.saturating_sub(1);
        more
    }
    fn end_pass(&mut self) {
        self.log.push("end");
    }
}

#[test]
fn every_pass_ends_with_end_pass_and_a_pass_below_the_cap_is_the_last() {
    let mut io = FakePass { full: 3, log: std::vec::Vec::new() };
    pass::run_passes(&mut io);
    assert_eq!(io.log, ["serve", "end"].repeat(4), "each pass must end with end_pass");
}

#[test]
fn an_idle_pass_still_ends_with_end_pass() {
    let mut io = FakePass { full: 0, log: std::vec::Vec::new() };
    pass::run_passes(&mut io);
    assert_eq!(io.log, ["serve", "end"]);
}

const K: usize = 64;

#[test]
fn drain_stops_at_exactly_max_with_input_remaining() {
    let mut waiting = K + 5;
    let mut steps = 0;
    let moved = pass::drain(K, || {
        steps += 1;
        if waiting == 0 {
            return false;
        }
        waiting -= 1;
        true
    });
    assert_eq!((moved, steps), (K, K), "drain must take exactly max and not step again");
    assert_eq!(waiting, 5);
}

#[test]
fn drain_returns_fewer_than_max_when_the_input_runs_dry() {
    let mut waiting = 3;
    let moved = pass::drain(K, || {
        if waiting == 0 {
            return false;
        }
        waiting -= 1;
        true
    });
    assert_eq!(moved, 3);
}

#[test]
fn any_full_continues_when_any_input_moved_the_cap() {
    for moved in [[K, 0, 0], [0, K, 0], [0, 0, K]] {
        assert!(pass::any_full(&moved, K), "{moved:?}");
    }
}

#[test]
fn any_full_breaks_when_every_input_moved_less_than_the_cap() {
    assert!(!pass::any_full(&[K - 1, K - 1, K - 1], K));
    assert!(!pass::any_full(&[0, 0, 0], K));
}
