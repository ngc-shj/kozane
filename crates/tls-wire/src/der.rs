//! The DER `ECDSA-Sig-Value` (RFC 3279 section 2.2.3) a P-256
//! CertificateVerify carries (RFC 8446 section 4.2.3), from `key`'s r ‖ s
//! (M6 plan C5, F8). Minimal INTEGERs: no leading zero byte except the one
//! that keeps a high bit positive; zero is not a valid r or s.

use crate::Refusal;

/// SEQUENCE of two one-byte INTEGERs.
pub const MIN_SIG_LEN: usize = 8;
/// SEQUENCE of two 33-byte INTEGERs (a 32-byte value with its high bit
/// set, after a 0x00).
pub const MAX_SIG_LEN: usize = 72;
/// r and s, 32 bytes big-endian each.
pub const SCALAR_LEN: usize = 32;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;

/// Writes the signature into `out` and returns its length, within
/// [`MIN_SIG_LEN`]..=[`MAX_SIG_LEN`]. Every length fits DER's short form.
pub fn ecdsa_sig_value(r_s: &[u8; 2 * SCALAR_LEN], out: &mut [u8; MAX_SIG_LEN]) -> Result<usize, Refusal> {
    let (r, s) = r_s.split_at(SCALAR_LEN);
    let (r_pad, r) = minimal(r)?;
    let (s_pad, s) = minimal(s)?;
    // Each INTEGER is 2 + pad + len <= 35 bytes; the SEQUENCE at most 72.
    let r_len = r.len().checked_add(usize::from(r_pad)).ok_or(Refusal::Internal)?;
    let s_len = s.len().checked_add(usize::from(s_pad)).ok_or(Refusal::Internal)?;
    let body = r_len.checked_add(s_len).and_then(|n| n.checked_add(4)).ok_or(Refusal::Internal)?;
    let total = body.checked_add(2).filter(|&t| t <= MAX_SIG_LEN).ok_or(Refusal::Internal)?;
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| -> Result<(), Refusal> {
        let end = at.checked_add(bytes.len()).ok_or(Refusal::Internal)?;
        out.get_mut(at..end).ok_or(Refusal::Internal)?.copy_from_slice(bytes);
        at = end;
        Ok(())
    };
    put(&[SEQUENCE, short_len(body)?])?;
    for (pad, int, len) in [(r_pad, r, r_len), (s_pad, s, s_len)] {
        put(&[INTEGER, short_len(len)?])?;
        if pad {
            put(&[0])?;
        }
        put(int)?;
    }
    Ok(total)
}

/// The value without leading zero bytes, and whether it needs a 0x00 in
/// front to stay positive. A zero value is refused.
fn minimal(v: &[u8]) -> Result<(bool, &[u8]), Refusal> {
    let first = v.iter().position(|&b| b != 0).ok_or(Refusal::Internal)?;
    let rest = v.get(first..).ok_or(Refusal::Internal)?;
    let pad = rest.first().is_some_and(|&b| b & 0x80 != 0);
    Ok((pad, rest))
}

fn short_len(n: usize) -> Result<u8, Refusal> {
    u8::try_from(n).ok().filter(|&b| b < 0x80).ok_or(Refusal::Internal)
}
