//! Shared test support: the SplitMix64 byte stream and the vector files.

#![allow(dead_code)]

use std::collections::BTreeMap;

use mce460896::RngError;

/// SplitMix64 as a byte stream, 8 bytes little-endian per step: the stream
/// `tools/rp-vectors` feeds liboqs (and cmr) through `randombytes`, so any
/// chunking of the requests sees the same bytes.
pub struct SplitMix {
    state: u64,
    buf: [u8; 8],
    used: usize,
}

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self { state: seed, buf: [0; 8], used: 8 }
    }

    pub fn byte(&mut self) -> u8 {
        if self.used == 8 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            self.buf = (z ^ (z >> 31)).to_le_bytes();
            self.used = 0;
        }
        let b = self.buf[self.used];
        self.used += 1;
        b
    }

    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        out.iter_mut().for_each(|b| *b = self.byte());
        Ok(())
    }
}

/// A vector file: `name hex` lines, `#` comments.
pub struct Vectors(BTreeMap<String, Vec<u8>>);

impl Vectors {
    pub fn parse(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
            let (k, v) = line.split_once(' ').expect("name hex");
            assert!(v.len() % 2 == 0, "{k}: odd hex length");
            let bytes = (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i + 2], 16).expect("hex")).collect();
            assert!(map.insert(k.to_owned(), bytes).is_none(), "{k} twice");
        }
        Self(map)
    }

    pub fn get(&self, name: &str) -> &[u8] {
        self.0.get(name).unwrap_or_else(|| panic!("vector {name} missing"))
    }

    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.get(name).try_into().unwrap_or_else(|_| panic!("vector {name} is not {N} bytes"))
    }

    pub fn seed(&self, name: &str) -> u64 {
        u64::from_le_bytes(self.array(name))
    }

    /// The entry indices `prefix.<i>.` present in the file.
    pub fn indices(&self, prefix: &str) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .0
            .keys()
            .filter_map(|k| k.strip_prefix(prefix)?.strip_prefix('.')?.split('.').next()?.parse().ok())
            .collect();
        out.dedup();
        out
    }
}

pub fn liboqs() -> Vectors {
    Vectors::parse(include_str!("../vectors/liboqs.txt"))
}

pub fn cmr() -> Vectors {
    Vectors::parse(include_str!("../vectors/cmr-2.0.2.txt"))
}

/// A zeroed boxed array (public keys do not fit a test thread's stack).
pub fn boxed<const N: usize>() -> Box<[u8; N]> {
    vec![0u8; N].into_boxed_slice().try_into().expect("length")
}

/// Runs `f` on a thread with a 64 MB stack (key generation needs ~1.1 MB).
pub fn big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new().stack_size(64 << 20).spawn(f).expect("spawn").join().expect("join")
}

/// liboqs's 13568-byte secret key to the round-3 spec (cmr) layout:
/// `cmr = [0; 40] ‖ oqs[576..] ‖ oqs[..576]` (`secret_blob::pq`).
pub fn sk_from_liboqs(oqs: &[u8]) -> Box<[u8; mce460896::SK_LEN]> {
    assert_eq!(oqs.len(), 13_568);
    let mut sk = boxed::<{ mce460896::SK_LEN }>();
    sk[40..40 + 13_568 - 576].copy_from_slice(&oqs[576..]);
    sk[mce460896::SK_LEN - 576..].copy_from_slice(&oqs[..576]);
    sk
}
