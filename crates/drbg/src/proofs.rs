#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! The state machine over a model PRF (M7 plan C7): the real PRF is
//! HMAC-SHA256, which the unit tests check against known answers. The model
//! maps (key, parts) to key with byte 0 moved by the parts' first byte and
//! one, so a replaced key always differs and a reseed depends on its seed.

use super::*;

struct Model;

impl Prf for Model {
    fn prf(key: &[u8; KEY_LEN], parts: &[&[u8]], out: &mut [u8; KEY_LEN]) -> Result<(), DrbgError> {
        *out = *key;
        let last = parts.last().and_then(|p| p.first()).copied().unwrap_or(0);
        out[0] = key[0].wrapping_add(1).wrapping_add(last.wrapping_mul(2));
        Ok(())
    }
}

fn any_drbg() -> Drbg<Model> {
    Drbg { key: Secret::from_bytes(kani::any()), ctr: kani::any(), since_seed: kani::any(), _prf: core::marker::PhantomData }
}

#[kani::proof]
fn fill_refuses_exactly_at_and_past_the_reseed_bound() {
    let mut d = any_drbg();
    kani::assume(d.ctr < u64::MAX);
    let before = d.since_seed;
    let mut out: [u8; 4] = kani::any();
    let r = d.fill(&mut out, kani::any());
    if before >= RESEED_DRAWS {
        assert!(r == Err(DrbgError::ReseedDue));
        assert!(out == [0; 4]);
    } else {
        assert!(r.is_ok());
    }
    kani::cover!(r.is_ok());
    kani::cover!(r == Err(DrbgError::ReseedDue));
}

#[kani::proof]
fn a_wrapping_counter_fails_and_leaves_no_bytes() {
    let mut d = any_drbg();
    kani::assume(d.since_seed < RESEED_DRAWS);
    let ctr = d.ctr;
    let mut out: [u8; 4] = kani::any();
    let r = d.fill(&mut out, kani::any());
    if ctr == u64::MAX {
        assert!(r == Err(DrbgError::Exhausted));
        assert!(out == [0; 4]);
    } else {
        assert!(r.is_ok());
    }
    kani::cover!(r == Err(DrbgError::Exhausted));
}

#[kani::proof]
fn a_draw_replaces_the_key_and_a_reseed_resets_the_bound() {
    let mut d = any_drbg();
    kani::assume(d.since_seed < RESEED_DRAWS && d.ctr < u64::MAX);
    let before = *d.key.as_bytes();
    let mut out = [0u8; 4];
    assert!(d.fill(&mut out, kani::any()).is_ok());
    assert!(*d.key.as_bytes() != before);
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    kani::assume(a.wrapping_mul(2) != b.wrapping_mul(2));
    let mut da = Drbg::<Model> { key: Secret::from_bytes(*d.key.as_bytes()), ctr: d.ctr, since_seed: d.since_seed, _prf: core::marker::PhantomData };
    let mut db = Drbg::<Model> { key: Secret::from_bytes(*d.key.as_bytes()), ctr: d.ctr, since_seed: d.since_seed, _prf: core::marker::PhantomData };
    assert!(da.reseed(&Secret::from_bytes([a; SEED_LEN])).is_ok());
    assert!(db.reseed(&Secret::from_bytes([b; SEED_LEN])).is_ok());
    assert!(da.since_seed == 0);
    assert!(da.key.as_bytes() != db.key.as_bytes());
}
