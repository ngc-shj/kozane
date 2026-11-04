//! RFC 4648 base64 with padding, for WireGuard keys as `peers.toml` and
//! `wg` write them. Decoding is strict: one canonical text per key.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4u32 {
            if usize::try_from(i).is_ok_and(|i| i <= chunk.len()) {
                let shift = 18u32.saturating_sub(i.saturating_mul(6));
                s.push(char::from(ALPHABET.get(((n >> shift) & 63) as usize).copied().unwrap_or(b'=')));
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).and_then(|p| u32::try_from(p).ok())
}

/// A 32-byte key: exactly 44 characters, one `=`, canonical last digit.
pub fn decode32(text: &str) -> Option<[u8; 32]> {
    let t = text.as_bytes();
    if t.len() != 44 || t.get(43) != Some(&b'=') {
        return None;
    }
    let mut out = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut at = 0usize;
    for &c in t.get(..43)? {
        acc = (acc << 6) | value(c)?;
        bits = bits.checked_add(6)?;
        if bits >= 8 {
            bits = bits.checked_sub(8)?;
            *out.get_mut(at)? = ((acc >> bits) & 0xff) as u8;
            at = at.checked_add(1)?;
            acc &= 1u32.checked_shl(bits).unwrap_or(0).wrapping_sub(1);
        }
    }
    // 43 digits carry 258 bits: the last 2 must be zero.
    (at == 32 && acc == 0).then_some(out)
}
