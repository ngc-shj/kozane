//! CT mode (M4 plan C9): runs under memcheck with every secret input marked
//! undefined. Any branch or address that depends on a marked byte is a
//! memcheck error; the only errors allowed are the canary's.

use std::hint::black_box;

use mce460896::{CT_LEN, ENCAPS_RAND_LEN, PK_LEN, SK_LEN, SS_LEN, decaps, encaps_attempt};

use crate::vectors::{self, CLASSES, ENTRIES, Vectors, boxed};
use crate::{fail, vg};

/// Decapsulations: the four C8 classes per entry, plus the boundary
/// weights on entry 0. Encapsulation attempts: every draw of each entry's
/// stream (1, 3 and 4 attempts), plus the two crafted rejections.
const CASES: usize = ENTRIES * CLASSES.len() + 6 + (1 + 3 + 4) + 2;

/// Branches on a marked byte: memcheck must report exactly this, once, at
/// this symbol, or the run proves nothing about the KEM.
#[inline(never)]
fn canary(secret: &[u8; 1]) -> u32 {
    if black_box(secret[0]) & 1 == 1 {
        black_box(1)
    } else {
        black_box(2)
    }
}

struct Run {
    cases: usize,
    marked: usize,
}

impl Run {
    /// Marks `buf` secret, then counts the bytes memcheck confirms
    /// undefined on that exact buffer, before the KEM receives it.
    fn mark(&mut self, name: &str, buf: &mut [u8]) {
        vg::mark_secret(buf);
        self.confirm(name, buf);
    }

    fn confirm(&mut self, name: &str, buf: &[u8]) {
        match vg::undefined_bytes(buf) {
            Some(n) if n == buf.len() => self.marked += n,
            Some(n) => fail(&format!("{name}: {n} of {} bytes undefined", buf.len())),
            None => fail(&format!("{name}: VALGRIND_GET_VBITS failed")),
        }
    }

    fn decaps(&mut self, name: &str, sk: &[u8; SK_LEN], ct: &[u8; CT_LEN], want: &[u8]) {
        self.confirm(name, &sk[..]);
        let mut ss = boxed::<SS_LEN>();
        decaps(sk, ct, &mut ss);
        vg::declassify("ss-out", &mut ss[..]);
        if ss[..] != *want {
            fail(&format!(
                "{name}: shared secret differs from the expected value"
            ));
        }
        self.cases += 1;
    }

    fn attempt(
        &mut self,
        name: &str,
        pk: &[u8; PK_LEN],
        rand: &mut [u8; ENCAPS_RAND_LEN],
        want: Option<(&[u8], &[u8])>,
    ) {
        self.mark(name, &mut rand[..]);
        let (mut ct, mut ss) = (boxed::<CT_LEN>(), boxed::<SS_LEN>());
        let mut accept = [encaps_attempt(pk, rand, &mut ct, &mut ss)];
        vg::declassify("encaps-accept", &mut accept);
        vg::declassify("ct-out", &mut ct[..]);
        vg::declassify("ss-out", &mut ss[..]);
        let ok = match want {
            Some((c, s)) => accept[0] == 1 && ct[..] == *c && ss[..] == *s,
            None => accept[0] == 0 && ct.iter().chain(ss.iter()).all(|&b| b == 0),
        };
        if !ok {
            fail(&format!(
                "{name}: accept bit {} or outputs differ from the expected values",
                accept[0]
            ));
        }
        self.cases += 1;
    }
}

pub fn run() -> ! {
    if !vg::running_on_valgrind() {
        println!("CT-NOT-VALGRIND CT mode must run under valgrind --tool=memcheck");
        std::process::exit(3);
    }
    println!("CT-CASES {CASES}");

    let mut run = Run {
        cases: 0,
        marked: 0,
    };

    let mut secret = [0x5au8];
    run.mark("canary", &mut secret);
    black_box(canary(&secret));
    println!("CT-CANARY done");

    let v = Vectors::load();
    for i in 0..ENTRIES {
        // Public derivations happen before the key is marked.
        let mut sk = v.sk(i);
        let pk = v.pk(&sk);
        let boundary = if i == 0 {
            vectors::boundary_cases(&pk, &sk)
        } else {
            Vec::new()
        };
        let attempts = v.attempts(i);

        run.mark(&format!("mce.{i}.sk"), &mut sk[..]);
        for class in CLASSES {
            let ct: Box<[u8; CT_LEN]> = Box::new(v.array(&format!("mce.{i}.dec.{class}.ct")));
            run.decaps(
                &format!("decaps.{i}.{class}"),
                &sk,
                &ct,
                v.get(&format!("mce.{i}.dec.{class}.ss")),
            );
        }
        for b in &boundary {
            run.decaps(&b.name, &sk, &b.ct, &b.ss);
        }

        let last = attempts.len() - 1;
        for (n, mut rand) in attempts.into_iter().enumerate() {
            let want =
                (n == last).then(|| (v.get(&format!("mce.{i}.ct")), v.get(&format!("mce.{i}.ss"))));
            run.attempt(&format!("encaps.{i}.attempt{n}"), &pk, &mut rand, want);
        }
        if i == 0 {
            for (name, bytes) in [("short", vectors::SHORT), ("repeated", vectors::REPEATED)] {
                let mut rand = Box::new(bytes);
                run.attempt(&format!("encaps.{name}"), &pk, &mut rand, None);
            }
        }
    }

    let used = vg::used_sites();
    for (id, calls) in &used {
        println!("CT-DECLASSIFY-SITE {id} {calls}");
    }
    println!("CT-MARKED-BYTES {}", run.marked);
    println!("CT-DECLASSIFY {}", used.len());
    println!("CT-DONE {}", run.cases);
    std::process::exit(0);
}
