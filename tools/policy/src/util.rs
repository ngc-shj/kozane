//! Small shared helpers: hex decoding of the fixed-size fields the various
//! TOML files carry (fleet IDs, digests, public keys).

use crate::sig;

pub fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let b = sig::unhex(s).filter(|b| b.len() == N).ok_or_else(|| format!("{what} is not {} lowercase hex digits", N * 2))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&b);
    Ok(out)
}
