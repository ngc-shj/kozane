//! Kani harnesses for the record header, the inner plaintext, the
//! extension walker, the ClientHello and the DER encoder (M6 plan C6, T15).
//! Run with `cargo kani -p tls-wire`. Messages are at most 96 bytes, so a
//! ClientHello (with its 1216-byte share) is never accepted here: its
//! accepting side is the unit tests' and bolero's, and its harness covers
//! the walker accepting the other extensions (T-N9).

use super::der::{MAX_SIG_LEN, MIN_SIG_LEN, SCALAR_LEN, ecdsa_sig_value};
use super::hello::{client_hello, walk};
use super::record::{header, inner_plaintext};
use super::*;

const MAX_LEN: usize = 96;

fn any_bytes(buf: &[u8; MAX_LEN]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= MAX_LEN);
    buf.get(..len).unwrap_or(&[])
}

fn inside(outer: &[u8], inner: &[u8]) -> bool {
    let (o, i) = (outer.as_ptr_range(), inner.as_ptr_range());
    inner.is_empty() || (o.start <= i.start && i.end <= o.end)
}

/// An accepted header has a known type, version 0x0303 (0x0301 only on the
/// first record) and a length within its type's bound.
#[kani::proof]
fn record_header_accepts_only_bounded_known_records() {
    let bytes: [u8; RECORD_HEADER_LEN] = kani::any();
    let first: bool = kani::any();
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if let Ok(h) = header(&bytes, first) {
        assert!(ContentType::from_u8(bytes[0]) == Some(h.content_type));
        assert!(version == TLS12 || (first && version == TLS10));
        if h.content_type == ContentType::ApplicationData {
            assert!(h.len <= MAX_CIPHERTEXT);
        } else {
            assert!(h.len >= 1 && h.len <= MAX_PLAINTEXT);
        }
        kani::cover!(h.content_type == ContentType::ApplicationData && h.len == MAX_CIPHERTEXT);
        kani::cover!(h.content_type == ContentType::Handshake && first && version == TLS10);
    }
}

/// The inner plaintext's content lies in the input, before its type byte,
/// and the type is never change_cipher_spec.
#[kani::proof]
#[kani::unwind(98)]
fn inner_plaintext_is_total_and_in_bounds() {
    let buf: [u8; MAX_LEN] = kani::any();
    let bytes = any_bytes(&buf);
    if let Ok((ty, content)) = inner_plaintext(bytes) {
        assert!(inside(bytes, content) && content.len() < bytes.len());
        assert!(ty != ContentType::ChangeCipherSpec);
        kani::cover!(ty == ContentType::ApplicationData && bytes.len() > content.len() + 1);
    }
}

/// Every extension the walker returns lies inside the block.
#[kani::proof]
#[kani::unwind(26)]
fn extension_walker_stays_inside_the_block() {
    let buf: [u8; MAX_LEN] = kani::any();
    let block = any_bytes(&buf);
    if let Ok(e) = walk(block) {
        for s in [
            e.supported_versions,
            e.supported_groups,
            e.key_share,
            e.signature_algorithms,
            e.alpn,
            e.server_name,
            e.psk_modes,
            e.pre_shared_key,
        ]
        .into_iter()
        .flatten()
        {
            assert!(inside(block, s));
        }
        kani::cover!(e.supported_versions.is_some() && e.supported_groups.is_some() && e.key_share.is_some());
    }
}

/// Two extensions of one type are never accepted, whatever the type and
/// their contents.
#[kani::proof]
#[kani::unwind(10)]
fn extension_walker_refuses_a_repeated_type() {
    const DATA: usize = 8;
    let ty: u16 = kani::any();
    let (a, b): (usize, usize) = (kani::any(), kani::any());
    kani::assume(a <= DATA && b <= DATA);
    let data: [u8; 2 * DATA] = kani::any();
    let mut block = [0u8; 2 * (4 + DATA)];
    let [t0, t1] = ty.to_be_bytes();
    let mut at = 0;
    for (len, from) in [(a, 0), (b, DATA)] {
        block[at] = t0;
        block[at + 1] = t1;
        block[at + 2] = 0;
        block[at + 3] = len as u8;
        block[at + 4..at + 4 + len].copy_from_slice(&data[from..from + len]);
        at += 4 + len;
    }
    assert!(walk(&block[..at]).is_err());
    // The allow side: one extension of the type alone is accepted.
    kani::cover!(walk(&block[..4 + a]).is_ok());
}

/// No ClientHello of at most 64 bytes is accepted (its share alone is
/// 1216), and parsing one never panics. 64 bytes reach past the fixed
/// fields (2 + 32 + 1 + suites + compression) into the extension block, so
/// the cover shows a refusal decided there. The walker on its own is
/// `extension_walker_stays_inside_the_block`: one harness walking 96
/// symbolic bytes twice ran cbmc past 32 GiB.
#[kani::proof]
#[kani::unwind(34)]
fn client_hello_is_total_and_refused_within_64_bytes() {
    const HELLO_LEN: usize = 64;
    let buf: [u8; HELLO_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= HELLO_LEN);
    let bytes = buf.get(..len).unwrap_or(&[]);
    let r = client_hello(bytes);
    assert!(r.is_err());
    kani::cover!(matches!(r, Err(Refusal::NoTls13 | Refusal::NoChaCha | Refusal::NoPqGroup)));
}

/// The DER signature is 8..=72 bytes, a SEQUENCE of two minimal positive
/// INTEGERs; only a zero r or s is refused.
#[kani::proof]
#[kani::unwind(34)]
fn der_encoder_is_minimal_and_bounded() {
    let rs: [u8; 2 * SCALAR_LEN] = kani::any();
    let mut out = [0u8; MAX_SIG_LEN];
    let r_zero = rs[..SCALAR_LEN].iter().all(|&b| b == 0);
    let s_zero = rs[SCALAR_LEN..].iter().all(|&b| b == 0);
    match ecdsa_sig_value(&rs, &mut out) {
        Ok(n) => {
            assert!(!r_zero && !s_zero);
            assert!((MIN_SIG_LEN..=MAX_SIG_LEN).contains(&n));
            assert!(out[0] == 0x30 && usize::from(out[1]) == n - 2);
            let mut at = 2;
            for _ in 0..2 {
                assert!(out[at] == 2);
                let len = usize::from(out[at + 1]);
                assert!((1..=33).contains(&len));
                let (first, second) = (out[at + 2], out[at + 3]);
                // Minimal: a leading 0x00 only before a high bit; positive.
                assert!(first & 0x80 == 0);
                assert!(first != 0 || (len > 1 && second & 0x80 != 0));
                at += 2 + len;
            }
            assert!(at == n);
            kani::cover!(n == MIN_SIG_LEN);
            kani::cover!(n == MAX_SIG_LEN);
        }
        Err(e) => assert!(e == Refusal::Internal && (r_zero || s_zero)),
    }
}
