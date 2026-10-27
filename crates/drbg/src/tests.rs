#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::panic)]

use super::*;

fn seed(b: u8) -> Secret<SEED_LEN> {
    Secret::from_bytes([b; SEED_LEN])
}

fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    libcrux_hmac::hmac_sha2_256_slices(&mut out, key, parts).unwrap();
    out
}

#[test]
fn the_construction_is_the_one_the_plan_locks() {
    let hedge = seed(0x11);
    let rng = seed(0x22);
    let mut d = Drbg::<HmacSha256>::instantiate(&hedge, &rng).unwrap();
    let k0 = hmac(&[0x11; 32], &[INIT, &[0x22; 32]]);
    assert_eq!(d.key.as_bytes(), &k0);
    let mut out = [0u8; 40];
    d.fill(&mut out, 7).unwrap();
    let b0 = hmac(&k0, &[OUT, &0u64.to_le_bytes(), &7u64.to_le_bytes()]);
    let k1 = hmac(&k0, &[NEXT, &0u64.to_le_bytes()]);
    let b1 = hmac(&k1, &[OUT, &1u64.to_le_bytes(), &7u64.to_le_bytes()]);
    let k2 = hmac(&k1, &[NEXT, &1u64.to_le_bytes()]);
    assert_eq!(&out[..32], &b0);
    assert_eq!(&out[32..], &b1[..8]);
    assert_eq!(d.key.as_bytes(), &k2);
    d.reseed(&seed(0x33)).unwrap();
    assert_eq!(d.key.as_bytes(), &hmac(&k2, &[RESEED, &[0x33; 32]]));
}

#[test]
fn the_key_is_replaced_by_every_block() {
    let mut d = Drbg::<HmacSha256>::instantiate(&seed(1), &seed(2)).unwrap();
    let mut seen = [[0u8; 32]; 4];
    for (i, k) in seen.iter_mut().enumerate() {
        *k = *d.key.as_bytes();
        let mut out = [0u8; 16];
        d.fill(&mut out, i as u64).unwrap();
        assert_ne!(d.key.as_bytes(), k, "draw {i} left K in place");
        assert_ne!(&out[..], &k[..16], "draw {i} output the key");
    }
}

#[test]
fn a_reseed_combines_the_old_state_and_the_seed() {
    let mk = |h: u8| Drbg::<HmacSha256>::instantiate(&seed(h), &seed(9)).unwrap();
    let (mut a, mut b, mut c) = (mk(1), mk(1), mk(2));
    a.reseed(&seed(5)).unwrap();
    b.reseed(&seed(6)).unwrap();
    c.reseed(&seed(5)).unwrap();
    assert_ne!(a.key.as_bytes(), b.key.as_bytes(), "the seed is not mixed in");
    assert_ne!(a.key.as_bytes(), c.key.as_bytes(), "the old state is not mixed in (an assignment)");
}

#[test]
fn the_same_rng_seed_under_different_hedges_gives_different_output() {
    let mut a = Drbg::<HmacSha256>::instantiate(&seed(1), &seed(7)).unwrap();
    let mut b = Drbg::<HmacSha256>::instantiate(&seed(2), &seed(7)).unwrap();
    let mut b2 = Drbg::<HmacSha256>::instantiate(&seed(2), &seed(7)).unwrap();
    let (mut x, mut y, mut z) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    a.fill(&mut x, 0).unwrap();
    b.fill(&mut y, 0).unwrap();
    b2.fill(&mut z, 0).unwrap();
    assert_ne!(x, y);
    // Allow side: the same pair gives the same output.
    assert_eq!(y, z);
}

#[test]
fn fill_number_reseed_draws_needs_a_reseed_first() {
    let mut d = Drbg::<HmacSha256>::instantiate(&seed(1), &seed(2)).unwrap();
    d.since_seed = RESEED_DRAWS - 1;
    let mut out = [0xAAu8; 8];
    assert_eq!(d.fill(&mut out, 0), Ok(()), "the last fill before the bound");
    assert!(d.reseed_due());
    let mut out = [0xAAu8; 8];
    assert_eq!(d.fill(&mut out, 0), Err(DrbgError::ReseedDue));
    assert_eq!(out, [0; 8], "a refused fill leaves no bytes");
    d.reseed(&seed(3)).unwrap();
    assert!(!d.reseed_due());
    assert_eq!(d.fill(&mut out, 0), Ok(()));
}

#[test]
fn a_counter_that_would_wrap_fails_the_draw() {
    let mut d = Drbg::<HmacSha256>::instantiate(&seed(1), &seed(2)).unwrap();
    d.ctr = u64::MAX;
    let mut out = [0xAAu8; 8];
    assert_eq!(d.fill(&mut out, 0), Err(DrbgError::Exhausted));
    assert_eq!(out, [0; 8]);
    d.ctr = u64::MAX - 1;
    assert_eq!(d.fill(&mut out, 0), Ok(()), "the last counter value still draws");
}
