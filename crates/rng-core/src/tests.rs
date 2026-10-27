#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

struct Fake {
    blocks: [[u8; SEED_LEN]; 4],
    lens: [usize; 4],
    fail: [bool; 4],
    at: usize,
    calls: usize,
}

impl Fake {
    fn good() -> Self {
        Fake { blocks: [[1; 32], [2; 32], [3; 32], [4; 32]], lens: [32; 4], fail: [false; 4], at: 0, calls: 0 }
    }
}

impl Device for Fake {
    fn draw(&mut self, out: &mut [u8; SEED_LEN]) -> Result<usize, DeviceError> {
        self.calls += 1;
        let i = self.at;
        self.at += 1;
        if self.fail[i] {
            return Err(DeviceError);
        }
        *out = self.blocks[i];
        Ok(self.lens[i])
    }
}

fn seed(s: &mut Server, c: Caller, now: u64, d: &mut Fake) -> (Result<(), Unavailable>, [u8; 32]) {
    let mut out = Secret::<SEED_LEN>::from_bytes([0xEE; 32]);
    let r = s.seed(c, now, d, &mut out);
    (r, *out.as_bytes())
}

#[test]
fn a_full_block_is_served() {
    let (r, out) = seed(&mut Server::new(), Caller::Hs, 0, &mut Fake::good());
    assert_eq!(r, Ok(()));
    assert_eq!(out, [1; 32]);
}

#[test]
fn a_short_completion_is_unavailable_and_leaves_no_bytes() {
    let mut d = Fake::good();
    d.lens[0] = 31;
    let (r, out) = seed(&mut Server::new(), Caller::Hs, 0, &mut d);
    assert_eq!(r, Err(Unavailable::Short));
    assert_eq!(out, [0; 32]);
}

#[test]
fn a_device_failure_or_deadline_is_unavailable() {
    let mut d = Fake::good();
    d.fail[0] = true;
    let (r, out) = seed(&mut Server::new(), Caller::Key, 0, &mut d);
    assert_eq!(r, Err(Unavailable::Device));
    assert_eq!(out, [0; 32]);
}

#[test]
fn an_all_zero_block_is_unavailable() {
    let mut d = Fake::good();
    d.blocks[0] = [0; 32];
    assert_eq!(seed(&mut Server::new(), Caller::Hs, 0, &mut d).0, Err(Unavailable::Zero));
}

#[test]
fn a_repeated_block_is_unavailable_and_the_next_fresh_one_served() {
    let mut s = Server::new();
    let mut d = Fake::good();
    d.blocks[1] = d.blocks[0];
    assert_eq!(seed(&mut s, Caller::Hs, 0, &mut d).0, Ok(()));
    assert_eq!(seed(&mut s, Caller::Pq, 0, &mut d).0, Err(Unavailable::Stuck), "a stuck device across callers");
    assert_eq!(seed(&mut s, Caller::Pq, 0, &mut d), (Ok(()), [3; 32]));
}

#[test]
fn a_caller_at_its_quota_is_served_and_the_next_request_is_not() {
    let mut s = Server::new();
    let mut d = Fake { blocks: [[9; 32]; 4], ..Fake::good() };
    for (i, b) in d.blocks.iter_mut().enumerate() {
        b[0] = i as u8 + 10;
    }
    for i in 0..SEED_BURST {
        assert_eq!(seed(&mut s, Caller::Tls, 0, &mut d).0, Ok(()), "request {i} within the burst");
    }
    let calls = d.calls;
    assert_eq!(seed(&mut s, Caller::Tls, 0, &mut d).0, Err(Unavailable::Quota));
    assert_eq!(d.calls, calls, "the quota is charged before the device is touched");
}

#[test]
fn a_drained_tainted_caller_never_starves_a_key_caller() {
    let mut s = Server::new();
    let mut d = Fake::good();
    for _ in 0..SEED_BURST {
        s.buckets[Caller::Hs.index()].take(0);
    }
    assert_eq!(seed(&mut s, Caller::Hs, 0, &mut d).0, Err(Unavailable::Quota));
    assert_eq!(seed(&mut s, Caller::Key, 0, &mut d).0, Ok(()));
}

#[test]
fn the_bucket_refills_at_one_seed_an_interval() {
    let mut s = Server::new();
    for _ in 0..SEED_BURST {
        assert!(s.buckets[0].take(0));
    }
    assert!(!s.buckets[0].take(SEED_INTERVAL_NS - 1));
    assert!(s.buckets[0].take(SEED_INTERVAL_NS));
}
