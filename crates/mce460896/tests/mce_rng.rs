//! The RNG contract: I6 (a failed draw is an `RngError`, no output claimed)
//! and I8 (one fresh full-length draw per attempt, wiped, never reused).

mod common;

use common::{SplitMix, boxed};
use mce460896::{CT_LEN, ENCAPS_RAND_LEN, PK_LEN, RngError, SK_LEN, SS_LEN, encaps, encaps_attempt, keypair};

/// Every candidate is `0x1fff >= SYS_N`: too few in range.
const SHORT: [u8; ENCAPS_RAND_LEN] = [0xff; ENCAPS_RAND_LEN];
/// Every candidate is 0: in range, but repeated.
const REPEATED: [u8; ENCAPS_RAND_LEN] = [0; ENCAPS_RAND_LEN];

fn some_pk() -> Box<[u8; PK_LEN]> {
    let mut pk = boxed::<PK_LEN>();
    SplitMix::new(7).fill(&mut pk[..]).expect("fill");
    pk
}

#[test]
fn rejected_attempts_return_zero_and_zero_their_outputs() {
    let pk = some_pk();
    for rand in [SHORT, REPEATED] {
        let (mut ct, mut ss) = ([0xaa; CT_LEN], [0xaa; SS_LEN]);
        assert_eq!(encaps_attempt(&pk, &rand, &mut ct, &mut ss), 0);
        assert_eq!((ct, ss), ([0; CT_LEN], [0; SS_LEN]));
    }
}

#[test]
fn encaps_returns_rng_error_on_a_failed_first_draw_and_claims_no_output() {
    let pk = some_pk();
    let (mut ct, mut ss) = ([0xaa; CT_LEN], [0xaa; SS_LEN]);
    let mut calls = 0;
    let r = encaps(
        &pk,
        &mut |_: &mut [u8]| {
            calls += 1;
            Err(RngError)
        },
        &mut ct,
        &mut ss,
    );
    assert_eq!(r, Err(RngError));
    assert_eq!(calls, 1);
    assert_eq!((ct, ss), ([0; CT_LEN], [0; SS_LEN]));
}

#[test]
fn encaps_returns_rng_error_on_a_failed_draw_after_a_rejection() {
    let pk = some_pk();
    let (mut ct, mut ss) = ([0xaa; CT_LEN], [0xaa; SS_LEN]);
    let mut calls = 0;
    let r = encaps(
        &pk,
        &mut |b: &mut [u8]| {
            calls += 1;
            if calls == 1 {
                b.copy_from_slice(&SHORT);
                Ok(())
            } else {
                Err(RngError)
            }
        },
        &mut ct,
        &mut ss,
    );
    assert_eq!(r, Err(RngError));
    assert_eq!(calls, 2);
    assert_eq!((ct, ss), ([0; CT_LEN], [0; SS_LEN]));
}

#[test]
fn keypair_returns_rng_error_and_claims_no_output() {
    let mut pk = boxed::<PK_LEN>();
    let mut sk = boxed::<SK_LEN>();
    pk.fill(0xaa);
    sk.fill(0xaa);
    let mut calls = 0;
    let r = keypair(
        &mut |_: &mut [u8]| {
            calls += 1;
            Err(RngError)
        },
        &mut pk,
        &mut sk,
    );
    assert_eq!(r, Err(RngError));
    assert_eq!(calls, 1);
    assert!(pk.iter().chain(sk.iter()).all(|&b| b == 0));
}

/// I8: a recording RNG. Two forced rejections, then the SplitMix stream
/// until the shim accepts. Each request must be exactly one attempt's
/// length and arrive wiped; the attempts the shim made must be exactly the
/// recorded draws, verbatim, which `encaps_attempt` replays.
#[test]
fn encaps_draws_fresh_full_length_bytes_per_attempt() {
    let pk = some_pk();
    let mut stream = SplitMix::new(0x18);
    let mut draws: Vec<Vec<u8>> = Vec::new();
    let (mut ct, mut ss) = ([0u8; CT_LEN], [0u8; SS_LEN]);

    encaps(
        &pk,
        &mut |b: &mut [u8]| {
            assert_eq!(b.len(), ENCAPS_RAND_LEN, "one attempt's length per request");
            assert!(b.iter().all(|&x| x == 0), "the previous draw was wiped");
            match draws.len() {
                0 => b.copy_from_slice(&SHORT),
                1 => b.copy_from_slice(&REPEATED),
                _ => stream.fill(b)?,
            }
            draws.push(b.to_vec());
            Ok(())
        },
        &mut ct,
        &mut ss,
    )
    .expect("encaps");

    assert!(draws.len() >= 3);
    let (last, rejected) = draws.split_last().expect("draws");
    for d in rejected {
        let (mut c, mut s) = ([0u8; CT_LEN], [0u8; SS_LEN]);
        assert_eq!(encaps_attempt(&pk, d.as_slice().try_into().expect("len"), &mut c, &mut s), 0);
    }
    let (mut c, mut s) = ([0u8; CT_LEN], [0u8; SS_LEN]);
    assert_eq!(encaps_attempt(&pk, last.as_slice().try_into().expect("len"), &mut c, &mut s), 1);
    assert_eq!((c, s), (ct, ss), "the accepted attempt used the last draw verbatim");
}
