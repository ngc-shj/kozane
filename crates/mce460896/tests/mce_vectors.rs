//! M4 plan C8: functional equivalence with the peers' liboqs 0.8 (round 3
//! framing) and with the frozen classic-mceliece-rust 2.0.2 bridge.

mod common;

use common::{SplitMix, big_stack, boxed, cmr, liboqs, sk_from_liboqs};
use mce460896::{CT_LEN, ENCAPS_RAND_LEN, PK_LEN, SK_LEN, SS_LEN, decaps, encaps, keypair, pk_from_sk, stages};
use sha3::{Digest, Sha3_256};

const CLASSES: [&str; 4] = ["valid", "c0", "c1", "both"];

/// liboqs.txt stores only a hash of each public key: rebuild the key from
/// the secret key, check the hash, then encapsulate under liboqs's stream.
fn check_liboqs_encaps(i: usize) {
    let v = liboqs();
    let sk = sk_from_liboqs(v.get(&format!("mce.{i}.sk_oqs")));
    let mut pk = boxed::<PK_LEN>();
    assert!(pk_from_sk(&sk, &mut pk), "mce.{i} pk_from_sk");
    assert_eq!(Sha3_256::digest(&pk[..]).as_slice(), v.get(&format!("mce.{i}.pk_sha3")), "mce.{i} pk");

    let (mut ct, mut ss) = ([0u8; CT_LEN], [0u8; SS_LEN]);
    let mut stream = SplitMix::new(v.seed(&format!("mce.{i}.enc_seed")));
    encaps(&pk, &mut |b: &mut [u8]| stream.fill(b), &mut ct, &mut ss).expect("encaps");
    assert_eq!(&ct[..], v.get(&format!("mce.{i}.ct")), "mce.{i} ct");
    assert_eq!(&ss[..], v.get(&format!("mce.{i}.ss")), "mce.{i} ss");
}

#[test]
fn liboqs_encaps_matches_for_every_entry() {
    let ids = liboqs().indices("mce");
    assert_eq!(ids, [0, 1, 2]);
    let runs: Vec<_> = ids.into_iter().map(|i| std::thread::spawn(move || big_stack(move || check_liboqs_encaps(i)))).collect();
    for r in runs {
        r.join().expect("entry");
    }
}

/// Key generation against cmr 2.0.2: the same seed stream gives the same
/// key pair, the secret key byte for byte in the spec layout.
fn check_cmr_keypair(i: usize) {
    let v = cmr();
    let mut pk = boxed::<PK_LEN>();
    let mut sk = boxed::<SK_LEN>();
    let mut stream = SplitMix::new(v.seed(&format!("cmr.{i}.kp_seed")));
    keypair(&mut |b: &mut [u8]| stream.fill(b), &mut pk, &mut sk).expect("keypair");

    assert_eq!(Sha3_256::digest(&pk[..]).as_slice(), v.get(&format!("cmr.{i}.pk_sha3")), "cmr.{i} pk");
    assert_eq!(&sk[..], v.get(&format!("cmr.{i}.sk")), "cmr.{i} sk");

    let mut rebuilt = boxed::<PK_LEN>();
    assert!(pk_from_sk(&sk, &mut rebuilt));
    assert!(rebuilt[..] == pk[..], "cmr.{i} pk_from_sk");

    let (mut ct, mut ss) = ([0u8; CT_LEN], [0u8; SS_LEN]);
    let mut stream = SplitMix::new(v.seed(&format!("cmr.{i}.enc_seed")));
    encaps(&pk, &mut |b: &mut [u8]| stream.fill(b), &mut ct, &mut ss).expect("encaps");
    let mut back = [0u8; SS_LEN];
    decaps(&sk, &ct, &mut back);
    assert_eq!(back, ss, "cmr.{i} round trip");
}

#[test]
fn cmr_keypair_matches_for_every_entry() {
    let ids = cmr().indices("cmr");
    assert_eq!(ids, [0, 1, 2]);
    let runs: Vec<_> = ids.into_iter().map(|i| std::thread::spawn(move || big_stack(move || check_cmr_keypair(i)))).collect();
    for r in runs {
        r.join().expect("entry");
    }
}

#[test]
fn liboqs_decaps_matches_in_every_class() {
    let v = liboqs();
    for i in v.indices("mce") {
        let sk = sk_from_liboqs(v.get(&format!("mce.{i}.sk_oqs")));
        for class in CLASSES {
            let ct: [u8; CT_LEN] = v.array(&format!("mce.{i}.dec.{class}.ct"));
            let mut ss = [0u8; SS_LEN];
            decaps(&sk, &ct, &mut ss);
            assert_eq!(&ss[..], v.get(&format!("mce.{i}.dec.{class}.ss")), "mce.{i} {class}");
        }
        assert_eq!(v.get(&format!("mce.{i}.dec.valid.ss")), v.get(&format!("mce.{i}.ss")));
    }
}

#[test]
fn cmr_decaps_matches_in_every_class() {
    let v = cmr();
    let ids = v.indices("cmr");
    assert_eq!(ids, [0, 1, 2]);
    for i in ids {
        let sk: Box<[u8; SK_LEN]> = Box::new(v.array(&format!("cmr.{i}.sk")));
        for class in CLASSES {
            let ct: [u8; CT_LEN] = v.array(&format!("cmr.{i}.dec.{class}.ct"));
            let mut ss = [0u8; SS_LEN];
            decaps(&sk, &ct, &mut ss);
            assert_eq!(&ss[..], v.get(&format!("cmr.{i}.dec.{class}.ss")), "cmr.{i} {class}");
        }
        let ct: [u8; CT_LEN] = v.array(&format!("cmr.{i}.ct"));
        let mut ss = [0u8; SS_LEN];
        decaps(&sk, &ct, &mut ss);
        assert_eq!(&ss[..], v.get(&format!("cmr.{i}.ss")), "cmr.{i} encapsulation");
    }
}

/// The encapsulation streams exercise rejections, so the vectors also pin
/// that `encaps` consumes a rejected attempt's bytes as liboqs does.
#[test]
fn liboqs_encaps_streams_include_rejected_attempts() {
    let v = liboqs();
    let attempts: Vec<usize> = v
        .indices("mce")
        .into_iter()
        .map(|i| {
            let mut stream = SplitMix::new(v.seed(&format!("mce.{i}.enc_seed")));
            (1..)
                .find(|_| {
                    let mut rand = [0u8; ENCAPS_RAND_LEN];
                    stream.fill(&mut rand).expect("fill");
                    stages::sample(&rand).accept == 0xffff
                })
                .expect("accepts")
        })
        .collect();
    eprintln!("attempts per liboqs entry: {attempts:?}");
    assert!(attempts.iter().any(|&n| n > 1), "{attempts:?}");
}
