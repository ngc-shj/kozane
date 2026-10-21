//! Test support (M4 plan C9 residue mode): the stages and stored forms of
//! the secrets, computed by the same internal functions `decaps` and
//! `encaps_attempt` run, so the residue scan derives its needles from the
//! port's own code. Nothing in the KEM calls this module.
//!
//! Every returned value is secret; callers own wiping it.

use crate::decrypt::{self, Work};
use crate::encrypt::{self, Sample};
use crate::params::{GFBITS, SYND_BYTES, SYS_N, SYS_T};
use crate::{CT_LEN, ENCAPS_RAND_LEN, PK_LEN, SK_LEN};

pub use crate::transpose::transpose_64x64;

/// 64 bitsliced field elements.
pub type Vec13 = [u64; GFBITS];

/// The sampler's forms of one attempt.
pub struct SampleForms {
    /// All ones iff the attempt accepts.
    pub accept: u16,
    /// The error positions (`ind[]`), in draw order.
    pub ind: [u16; SYS_T],
    /// `e` as bytes.
    pub e: [u8; SYS_N / 8],
    /// `e` as 64-bit words (`e_int`).
    pub e_words: [u64; SYS_N / 64],
}

/// The sampler on `rand`.
pub fn sample(rand: &[u8; ENCAPS_RAND_LEN]) -> SampleForms {
    let mut st = Sample::new();
    let mut e = [0u8; SYS_N / 8];
    let accept = encrypt::gen_e(&mut st, &mut e, rand);
    SampleForms { accept, ind: st.ind, e, e_words: st.e_int }
}

/// `ind[]` as stored: little-endian `u16`s.
pub fn pack_ind(ind: &[u16; SYS_T]) -> [u8; SYS_T * 2] {
    let mut out = [0u8; SYS_T * 2];
    for (c, v) in out.as_chunks_mut::<2>().0.iter_mut().zip(ind) {
        c.copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// The encapsulation syndrome `C0 = H e`.
pub fn encrypt_syndrome(pk: &[u8; PK_LEN], e: &[u8; SYS_N / 8]) -> [u8; SYND_BYTES] {
    let mut s = [0u8; SYND_BYTES];
    encrypt::syndrome(&mut s, pk, e);
    s
}

/// The Goppa polynomial `g`, bitsliced (`irr_load`).
pub fn g_bitsliced(sk: &[u8; SK_LEN]) -> [Vec13; 2] {
    let mut out = [[0; GFBITS]; 2];
    crate::util::irr_load(&mut out, crate::sk_parts(sk).0);
    out
}

/// The decoder's forms for `ct` under `sk`.
pub struct DecodeForms {
    /// The received word after the inverse network (the support applied).
    pub recv: [u64; 128],
    /// `1 / g(a)^2` for every field element (the support's scaling).
    pub inv: [Vec13; 128],
    /// The doubled syndrome (`s_priv`).
    pub syndrome: [Vec13; 4],
    /// The error locator, Berlekamp-Massey's output.
    pub locator: [Vec13; 2],
    /// `e` as bytes.
    pub e: [u8; SYS_N / 8],
    /// The decode failure bit.
    pub fail: u8,
}

/// The `syndrome` stage: network, scaling, transposed FFT.
pub fn syndrome(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN]) -> [Vec13; 4] {
    let mut w = Work::new();
    decrypt::syndrome(&mut w, crate::sk_parts(sk).0, ct.split_at(SYND_BYTES).0);
    w.s_priv
}

/// The `bm` stage on a syndrome.
pub fn bm(syndrome: &[Vec13; 4]) -> [Vec13; 2] {
    let mut out = [[0; GFBITS]; 2];
    crate::bm::bm(&mut out, syndrome);
    out
}

/// Every decoder stage on `ct`.
pub fn decode(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN]) -> DecodeForms {
    let mut w = Work::new();
    let (g_alpha, _) = crate::sk_parts(sk);
    let c0 = ct.split_at(SYND_BYTES).0;
    decrypt::syndrome(&mut w, g_alpha, c0);
    let locator = bm(&w.s_priv);
    let mut e = [0u8; SYS_N / 8];
    let fail = decrypt::decrypt(&mut e, g_alpha, c0);
    DecodeForms { recv: w.recv, inv: w.inv, syndrome: w.s_priv, locator, e, fail }
}
