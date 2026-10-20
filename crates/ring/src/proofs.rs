//! Kani harnesses: the peer controls every shared value and may change it
//! between any two reads.

use core::cell::Cell;

use super::*;

/// Shared state written by an adversarial peer: every load returns a fresh
/// arbitrary value, and loads are counted so the read-once rule is checked.
#[derive(Default)]
struct Adversary<const N: usize> {
    index_loads: Cell<u32>,
    slot_loads: Cell<u32>,
    last_store: Cell<Option<u32>>,
    /// The peer index value most recently handed out.
    last_peer_index: Cell<u32>,
}

impl<const N: usize> SharedAccess<Desc> for &Adversary<N> {
    fn load_peer_index(&self) -> u32 {
        self.index_loads.set(self.index_loads.get().wrapping_add(1));
        let v = kani::any();
        self.last_peer_index.set(v);
        v
    }
    fn store_own_index(&self, v: u32) {
        self.last_store.set(Some(v));
    }
    fn load_slot(&self, i: usize) -> Desc {
        // Same bound as the real ShmRing: slots exist only for i < N.
        assert!(i < N, "slot index out of range");
        self.slot_loads.set(self.slot_loads.get().wrapping_add(1));
        Desc { offset: kani::any(), len: kani::any() }
    }
    fn store_slot(&self, i: usize, _d: Desc) {
        assert!(i < N, "slot index out of range");
    }
}

fn consumer_reads_once<const N: usize>() {
    let adv = Adversary::<N>::default();
    let mut c: Consumer<&Adversary<N>, Desc, N> = Consumer::new(&adv);
    c.read = kani::any();
    let before = c.read;
    let r = c.pop();
    // A peer claiming more than N filled slots must be detected.
    if adv.last_peer_index.get().wrapping_sub(before) as usize > N {
        assert!(r == Err(RingError::Corrupt));
    }
    assert!(adv.index_loads.get() == 1);
    assert!(adv.slot_loads.get() <= 1);
    match r {
        Ok(Some(_)) => {
            assert!(c.read == before.wrapping_add(1));
            assert!(adv.last_store.get() == Some(c.read));
        }
        Ok(None) | Err(RingError::Full) => assert!(c.read == before),
        Err(RingError::Corrupt) => assert!(c.is_corrupt() && c.read == before),
    }
    kani::cover!(matches!(r, Ok(Some(_))));
    kani::cover!(matches!(r, Ok(None)));
    kani::cover!(matches!(r, Err(RingError::Corrupt)));
}

fn producer_reads_once<const N: usize>() {
    let adv = Adversary::<N>::default();
    let mut p: Producer<&Adversary<N>, Desc, N> = Producer::new(&adv);
    p.write = kani::any();
    let before = p.write;
    let r = p.push(Desc { offset: kani::any(), len: kani::any() });
    // A peer read index that implies more than N slots in flight must be detected.
    if before.wrapping_sub(adv.last_peer_index.get()) as usize > N {
        assert!(r == Err(RingError::Corrupt));
    }
    assert!(adv.index_loads.get() == 1);
    assert!(adv.slot_loads.get() == 0);
    match r {
        Ok(()) => assert!(p.write == before.wrapping_add(1)),
        Err(RingError::Full) => assert!(p.write == before),
        Err(RingError::Corrupt) => assert!(p.is_corrupt() && p.write == before),
    }
    kani::cover!(r == Ok(()));
    kani::cover!(r == Err(RingError::Full));
    kani::cover!(r == Err(RingError::Corrupt));
}

#[kani::proof]
fn consumer_n1() {
    consumer_reads_once::<1>();
}
#[kani::proof]
fn consumer_n4() {
    consumer_reads_once::<4>();
}
#[kani::proof]
fn consumer_n256() {
    consumer_reads_once::<256>();
}
#[kani::proof]
fn producer_n1() {
    producer_reads_once::<1>();
}
#[kani::proof]
fn producer_n4() {
    producer_reads_once::<4>();
}
#[kani::proof]
fn producer_n256() {
    producer_reads_once::<256>();
}

/// For any peer-supplied descriptor, `accept` either rejects it or returns a
/// buffer index whose byte range lies inside the region.
#[kani::proof]
fn pool_accept_stays_in_region() {
    let mut pool: Pool<4, 2048> = Pool::new(false);
    // Arbitrary ownership per buffer, not one shared state.
    pool.mine = kani::any();
    let before = pool.mine;
    let d = Desc { offset: kani::any(), len: kani::any() };
    let r = pool.accept(d);
    let in_range = d.offset % 2048 == 0 && (d.offset / 2048) < 4 && d.len <= 2048;
    let idx = (d.offset / 2048) as usize;
    // Accepted exactly when well-formed and currently with the peer.
    assert!(r.is_ok() == (in_range && !before[idx.min(3)]));
    if let Ok(i) = r {
        let start = (i as u64) * 2048;
        assert!(start + u64::from(d.len) <= Pool::<4, 2048>::region_len() as u64);
        assert!(u64::from(d.offset) == start);
        assert!(pool.mine[i]);
        // No other buffer's ownership changes.
        for j in 0..4 {
            if j != i {
                assert!(pool.mine[j] == before[j]);
            }
        }
    } else {
        assert!(pool.mine == before);
    }
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(DescError::NotWithPeer));
}

mod link_proofs {
    #![allow(unsafe_code)]

    use super::Adversary;
    use crate::link::{LinkError, Receiver, Sender, Taken};
    use crate::shmem::Region;

    const M: usize = 2;
    const BUF: usize = 16;

    /// The driver/ingress copy-in path: whatever descriptor and indices the
    /// peer writes, the receiver never reads outside the data region (Kani's
    /// pointer checks) and never reports more than BUF bytes (L7, C5).
    #[kani::proof]
    #[kani::unwind(17)]
    fn receiver_copy_stays_in_region() {
        let mut mem = [0u8; M * BUF];
        // SAFETY: `mem` outlives `rx` and has the stated length.
        let region = unsafe { Region::new(mem.as_mut_ptr(), mem.len()) };
        let used = Adversary::<M>::default();
        let free = Adversary::<M>::default();
        let mut rx: Receiver<&Adversary<M>, &Adversary<M>, M, M, BUF> = Receiver::new(&used, &free, region);
        let mut out = [0u8; BUF];
        let r = rx.recv_into(&mut out);
        if let Ok(Some(n)) = r {
            assert!(n <= BUF);
        }
        // Read-once also holds through the link layer.
        assert!(used.index_loads.get() <= 1 && free.index_loads.get() <= 1);
        kani::cover!(matches!(r, Ok(Some(_))));
        kani::cover!(matches!(r, Err(LinkError::BadDesc(_))));
        kani::cover!(matches!(r, Err(LinkError::Corrupt)));
    }

    /// The held receive (M3b plan C3): whatever descriptor and indices the
    /// peer writes, `take_into` never reads outside the data region, never
    /// reports more than BUF bytes, and holds a buffer exactly when it
    /// reports one; a second take is refused and `release` returns it.
    #[kani::proof]
    #[kani::unwind(17)]
    fn held_receive_stays_in_region_and_holds_what_it_reports() {
        let mut mem = [0u8; M * BUF];
        // SAFETY: `mem` outlives `rx` and has the stated length.
        let region = unsafe { Region::new(mem.as_mut_ptr(), mem.len()) };
        let used = Adversary::<M>::default();
        let free = Adversary::<M>::default();
        let mut rx: Receiver<&Adversary<M>, &Adversary<M>, M, M, BUF> = Receiver::new(&used, &free, region);
        let mut out = [0u8; BUF];
        let r = rx.take_into(&mut out);
        if let Ok(Some(Taken::Payload(n))) = r {
            assert!(n <= BUF);
        }
        if let Ok(Some(_)) = r {
            assert!(rx.take_into(&mut out) == Err(LinkError::Held));
            let rel = rx.release();
            assert!(rel.is_ok() || rel == Err(LinkError::Corrupt));
        } else {
            let rel = rx.release();
            assert!(rel == Err(LinkError::NoBuffer) || rel == Err(LinkError::Corrupt));
        }
        kani::cover!(matches!(r, Ok(Some(Taken::Payload(_)))));
        kani::cover!(matches!(r, Err(LinkError::BadDesc(_))));
    }

    /// The copy-out path: whatever length the fill step reports, the sender
    /// never writes outside the data region.
    #[kani::proof]
    #[kani::unwind(17)]
    fn sender_copy_stays_in_region() {
        let mut mem = [0u8; M * BUF];
        // SAFETY: `mem` outlives `tx` and has the stated length.
        let region = unsafe { Region::new(mem.as_mut_ptr(), mem.len()) };
        let used = Adversary::<M>::default();
        let free = Adversary::<M>::default();
        let mut tx: Sender<&Adversary<M>, &Adversary<M>, M, M, BUF> = Sender::new(&used, &free, region);
        let mut scratch = [0u8; BUF];
        let len: usize = kani::any();
        let r = tx.send_with(&mut scratch, |_| Some(len));
        if r == Ok(true) {
            assert!(len <= BUF);
        }
        assert!(used.index_loads.get() <= 1 && free.index_loads.get() == 0);
        kani::cover!(r == Ok(true));
        kani::cover!(matches!(r, Err(LinkError::BadDesc(_))));
    }

    /// The backlog read by `ingress`: whatever the peer returns, the count
    /// never exceeds what was sent, and a buffer returned before the call is
    /// already counted as back.
    #[kani::proof]
    #[kani::unwind(17)]
    fn sender_in_flight_stays_within_pool() {
        let mut mem = [0u8; M * BUF];
        // SAFETY: `mem` outlives `tx` and has the stated length.
        let region = unsafe { Region::new(mem.as_mut_ptr(), mem.len()) };
        let used = Adversary::<M>::default();
        let free = Adversary::<M>::default();
        let mut tx: Sender<&Adversary<M>, &Adversary<M>, M, M, BUF> = Sender::new(&used, &free, region);
        let mut scratch = [0u8; BUF];
        let sent = tx.send_with(&mut scratch, |_| Some(1));
        let r = tx.in_flight();
        if let Ok(n) = r {
            assert!(n <= usize::from(sent == Ok(true)));
        }
        kani::cover!(sent == Ok(true) && r == Ok(0));
        kani::cover!(sent == Ok(true) && r == Ok(1));
    }
}
