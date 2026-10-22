//! The C8 liboqs vectors and the inputs both modes build from them.

use std::collections::BTreeMap;

use mce460896::{CT_LEN, ENCAPS_RAND_LEN, PK_LEN, SK_LEN, SS_LEN};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub const SYS_N: usize = 4608;
pub const SYS_T: usize = 96;
pub const SYND_BYTES: usize = CT_LEN - 32;
pub const CLASSES: [&str; 4] = ["valid", "c0", "c1", "both"];

/// The liboqs entries (`mce.<i>.`) the harness requires.
pub const ENTRIES: usize = 3;

const LIBOQS: &str = include_str!("../../../crates/mce460896/tests/vectors/liboqs.txt");

/// SplitMix64 as a byte stream, as `tools/rp-vectors` feeds liboqs.
pub struct SplitMix {
    state: u64,
    buf: [u8; 8],
    used: usize,
}

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed,
            buf: [0; 8],
            used: 8,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            if self.used == 8 {
                self.buf = self.next_u64().to_le_bytes();
                self.used = 0;
            }
            *b = self.buf[self.used];
            self.used += 1;
        }
    }
}

pub struct Vectors(BTreeMap<String, Vec<u8>>);

impl Vectors {
    pub fn load() -> Self {
        let mut map = BTreeMap::new();
        for line in LIBOQS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let (k, v) = line.split_once(' ').expect("name hex");
            assert!(v.len() % 2 == 0, "{k}: odd hex length");
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).expect("hex"))
                .collect();
            assert!(map.insert(k.to_owned(), bytes).is_none(), "{k} twice");
        }
        Self(map)
    }

    pub fn get(&self, name: &str) -> &[u8] {
        self.0
            .get(name)
            .unwrap_or_else(|| panic!("vector {name} missing"))
    }

    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.get(name)
            .try_into()
            .unwrap_or_else(|_| panic!("vector {name} is not {N} bytes"))
    }

    pub fn seed(&self, name: &str) -> u64 {
        u64::from_le_bytes(self.array(name))
    }

    /// liboqs's secret key in the round-3 spec layout
    /// (`cmr = [0; 40] ‖ oqs[576..] ‖ oqs[..576]`, `secret_blob::pq`).
    pub fn sk(&self, i: usize) -> Box<[u8; SK_LEN]> {
        let oqs = self.get(&format!("mce.{i}.sk_oqs"));
        assert_eq!(oqs.len(), 13_568);
        let mut sk = boxed::<SK_LEN>();
        sk[40..40 + 13_568 - 576].copy_from_slice(&oqs[576..]);
        sk[SK_LEN - 576..].copy_from_slice(&oqs[..576]);
        sk
    }

    /// The public key, rebuilt from the secret key (liboqs.txt stores only
    /// a hash of it, which `crates/mce460896/tests/mce_vectors.rs` checks).
    pub fn pk(&self, sk: &[u8; SK_LEN]) -> Box<[u8; PK_LEN]> {
        let mut pk = boxed::<PK_LEN>();
        assert!(mce460896::pk_from_sk(sk, &mut pk), "pk_from_sk");
        pk
    }

    /// The entry's encapsulation stream, one `ENCAPS_RAND_LEN` draw per
    /// attempt, up to and including the first accepted one. Each draw is
    /// its own heap buffer, so that moving it never copies it to a stack.
    #[allow(clippy::vec_box)]
    pub fn attempts(&self, i: usize) -> Vec<Box<[u8; ENCAPS_RAND_LEN]>> {
        let mut stream = SplitMix::new(self.seed(&format!("mce.{i}.enc_seed")));
        let mut out = Vec::new();
        loop {
            let mut rand = boxed::<ENCAPS_RAND_LEN>();
            stream.fill(&mut rand[..]);
            let accept = mce460896::stages::sample(&rand).accept == 0xffff;
            out.push(rand);
            if accept {
                return out;
            }
        }
    }
}

/// A zeroed boxed array.
pub fn boxed<const N: usize>() -> Box<[u8; N]> {
    vec![0u8; N].into_boxed_slice().try_into().expect("length")
}

/// SHAKE256 of the concatenation of `parts`, 32 bytes.
pub fn h32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Every candidate is `0x1fff >= SYS_N`: too few in range.
pub const SHORT: [u8; ENCAPS_RAND_LEN] = [0xff; ENCAPS_RAND_LEN];
/// Every candidate is 0: in range, but repeated.
pub const REPEATED: [u8; ENCAPS_RAND_LEN] = [0; ENCAPS_RAND_LEN];

/// A boundary-weight decapsulation input: an error vector of weight
/// `positions.len()` encrypted under `pk` with its `C1`, and the shared
/// secret decapsulation must give (the implicit rejection unless the
/// weight is `SYS_T`).
pub struct Boundary {
    pub name: String,
    pub ct: Box<[u8; CT_LEN]>,
    pub ss: [u8; SS_LEN],
}

pub fn boundary_cases(pk: &[u8; PK_LEN], sk: &[u8; SK_LEN]) -> Vec<Boundary> {
    let mut rng = SplitMix::new(0xc9);
    let mut sets: Vec<(String, Vec<usize>)> = Vec::new();
    for w in [0, 1, SYS_T - 1, SYS_T, SYS_T + 1] {
        let mut pos: Vec<usize> = Vec::new();
        while pos.len() < w {
            let p = (rng.next_u64() % SYS_N as u64) as usize;
            if !pos.contains(&p) {
                pos.push(p);
            }
        }
        sets.push((format!("w{w}"), pos));
    }
    // Weight SYS_T touching both ends of the code.
    let mut edges: Vec<usize> = vec![0, SYS_N - 1];
    while edges.len() < SYS_T {
        let p = (rng.next_u64() % SYS_N as u64) as usize;
        if !edges.contains(&p) {
            edges.push(p);
        }
    }
    sets.push(("w96-edges".into(), edges));

    let s = &sk[SK_LEN - SYS_N / 8..];
    sets.into_iter()
        .map(|(name, pos)| {
            let mut e = [0u8; SYS_N / 8];
            for p in &pos {
                e[p / 8] |= 1 << (p % 8);
            }
            let c0 = mce460896::stages::encrypt_syndrome(pk, &e);
            let mut ct = boxed::<CT_LEN>();
            ct[..SYND_BYTES].copy_from_slice(&c0);
            ct[SYND_BYTES..].copy_from_slice(&h32(&[&[2], &e]));
            let ss = if pos.len() == SYS_T {
                h32(&[&[1], &e, &ct[..]])
            } else {
                h32(&[&[0], s, &ct[..]])
            };
            Boundary {
                name: format!("decaps.boundary.{name}"),
                ct,
                ss,
            }
        })
        .collect()
}
