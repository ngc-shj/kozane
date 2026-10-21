//! Beneš control bits from a permutation: libmceliece `controlbits.c`
//! (Nassimi-Sahni, `cbrecursion`), the algorithm cmr 2.0.2 also runs.
//!
//! `crypto_sort_int32` is replaced by the Batcher network of `sort.rs`:
//! every value sorted here is non-negative and below 2^30, so the order,
//! and hence the output, is the same. The C code keeps `q` inside its
//! `temp` area; here each level's `q` has its own slot in a chain, which
//! changes no value.

// Indices are public positions in the network (I4).
#![allow(clippy::indexing_slicing)]
// Every `+`/`-`/`*` on a `usize` here is a public network position; the
// values use `wrapping_*`.
#![allow(clippy::arithmetic_side_effects)]

use zeroize::Zeroize;

use super::sort::sort;
use crate::barrier;
use crate::params::{COND_BYTES, GFBITS};

pub(crate) const N: usize = 1 << GFBITS;

fn put_bit(out: &mut [u8], pos: usize, bit: u32) {
    out[pos >> 3] ^= (bit << (pos & 7)) as u8;
}

/// `cbrecursion(out, pos, step, pi, w, n, temp)`. `temp` holds `2n`
/// words; `qs` the sub-permutations of this level and the levels below.
#[allow(clippy::too_many_arguments)] // the C recursion's parameters, plus the q chain
fn cbrecursion(out: &mut [u8], pos: usize, step: usize, pi: &[u16], w: usize, n: usize, temp: &mut [u32], qs: &mut [u16]) {
    if w == 1 {
        put_bit(out, pos, u32::from(pi[0]));
        return;
    }

    let mut pos = pos;
    {
        let (a, rest) = temp.split_at_mut(n);
        let b = &mut rest[..n];

        for x in 0..n {
            a[x] = (u32::from(pi[x] ^ 1) << 16) | u32::from(pi[x ^ 1]);
        }
        sort(a); // A = (id<<16)+pibar

        for x in 0..n {
            let px = a[x] & 0xffff;
            let cx = barrier::u32_min(px, x as u32);
            b[x] = (px << 16) | cx;
        }
        // B = (p<<16)+c

        for x in 0..n {
            a[x] = a[x].wrapping_shl(16) | x as u32; // A = (pibar<<16)+id
        }
        sort(a); // A = (id<<16)+pibar^-1

        for x in 0..n {
            a[x] = a[x].wrapping_shl(16).wrapping_add(b[x] >> 16); // A = (pibar^(-1)<<16)+pibar
        }
        sort(a); // A = (id<<16)+pibar^2

        if w <= 10 {
            for x in 0..n {
                b[x] = ((a[x] & 0xffff) << 10) | (b[x] & 0x3ff);
            }

            for _ in 1..w - 1 {
                // B = (p<<10)+c
                for x in 0..n {
                    a[x] = ((b[x] & !0x3ff) << 6) | x as u32; // A = (p<<16)+id
                }
                sort(a); // A = (id<<16)+p^{-1}

                for x in 0..n {
                    a[x] = a[x].wrapping_shl(20) | b[x]; // A = (p^{-1}<<20)+(p<<10)+c
                }
                sort(a); // A = (id<<20)+(pp<<10)+cp

                for x in 0..n {
                    let ppcpx = a[x] & 0xfffff;
                    let ppcx = (a[x] & 0xffc00) | (b[x] & 0x3ff);
                    b[x] = barrier::u32_min(ppcx, ppcpx);
                }
            }
            for x in 0..n {
                b[x] &= 0x3ff;
            }
        } else {
            for x in 0..n {
                b[x] = a[x].wrapping_shl(16) | (b[x] & 0xffff);
            }

            for i in 1..w - 1 {
                // B = (p<<16)+c
                for x in 0..n {
                    a[x] = (b[x] & !0xffff) | x as u32;
                }
                sort(a); // A = (id<<16)+p^(-1)

                for x in 0..n {
                    a[x] = a[x].wrapping_shl(16) | (b[x] & 0xffff); // A = p^(-1)<<16+c
                }

                if i < w - 2 {
                    for x in 0..n {
                        b[x] = (a[x] & !0xffff) | (b[x] >> 16); // B = (p^(-1)<<16)+p
                    }
                    sort(b); // B = (id<<16)+p^(-2)
                    for x in 0..n {
                        b[x] = b[x].wrapping_shl(16) | (a[x] & 0xffff); // B = (p^(-2)<<16)+c
                    }
                }

                sort(a); // A = id<<16+cp
                for x in 0..n {
                    let cpx = (b[x] & !0xffff) | (a[x] & 0xffff);
                    b[x] = barrier::u32_min(b[x], cpx);
                }
            }
            for x in 0..n {
                b[x] &= 0xffff;
            }
        }

        for x in 0..n {
            a[x] = (u32::from(pi[x]) << 16).wrapping_add(x as u32);
        }
        sort(a); // A = (id<<16)+pi^(-1)

        for j in 0..n / 2 {
            let z = 2 * j;
            let fj = barrier::u32_bottombit_01(b[z]); // f[j]
            let fz = (z as u32).wrapping_add(fj); // F[z]
            let fz1 = fz ^ 1; // F[z+1]

            put_bit(out, pos, fj);
            pos += step;

            b[z] = a[z].wrapping_shl(16) | fz;
            b[z + 1] = a[z + 1].wrapping_shl(16) | fz1;
        }
        // B = (pi^(-1)<<16)+F

        sort(b); // B = (id<<16)+F(pi)

        pos += (2 * w - 3) * step * (n / 2);

        for k in 0..n / 2 {
            let y = 2 * k;
            let lk = barrier::u32_bottombit_01(b[y]); // l[k]
            let ly = (y as u32).wrapping_add(lk); // L[y]
            let ly1 = ly ^ 1; // L[y+1]

            put_bit(out, pos, lk);
            pos += step;

            a[y] = (ly << 16) | (b[y] & 0xffff);
            a[y + 1] = (ly1 << 16) | (b[y + 1] & 0xffff);
        }
        // A = (L<<16)+F(pi)

        sort(a); // A = (id<<16)+F(pi(L)) = (id<<16)+M

        pos -= (2 * w - 2) * step * (n / 2);

        for j in 0..n / 2 {
            qs[j] = ((a[2 * j] & 0xffff) >> 1) as u16;
            qs[j + n / 2] = ((a[2 * j + 1] & 0xffff) >> 1) as u16;
        }
    }

    let (q, below) = qs.split_at_mut(n);
    cbrecursion(out, pos, step * 2, &q[..n / 2], w - 1, n / 2, temp, below);
    cbrecursion(out, pos + step, step * 2, &q[n / 2..], w - 1, n / 2, temp, below);
}

/// `layer`: applies the stride-`2^s` swaps of one network layer to `p`.
fn layer(p: &mut [u16; N], cb: &[u8], s: usize) {
    let stride = 1 << s;
    let mut index = 0;
    for i in (0..N).step_by(stride * 2) {
        for j in 0..stride {
            let d = (p[i + j] ^ p[i + j + stride]) & barrier::u8_bitmod_mask(cb[index >> 3], index);
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index += 1;
        }
    }
}

/// The permutation a network applies to the identity: the layers in the
/// order `controlbitsfrompermutation`'s check applies them.
pub(crate) fn apply_network(pi: &mut [u16; N], cb: &[u8; COND_BYTES]) {
    for (i, p) in pi.iter_mut().enumerate() {
        *p = i as u16;
    }
    let mut at = 0;
    for i in (0..GFBITS).chain((0..GFBITS - 1).rev()) {
        layer(pi, &cb[at..], i);
        at += N >> 4;
    }
}

/// `controlbitsfrompermutation(out, pi, w = GFBITS, n = N)`.
#[inline(never)]
pub(crate) fn controlbits(out: &mut [u8; COND_BYTES], pi: &[u16; N]) {
    let mut temp = [0u32; 2 * N];
    let mut qs = [0u16; 2 * N];
    let mut pi_test = [0u16; N];

    loop {
        *out = [0; COND_BYTES];
        cbrecursion(out, 0, 1, pi, GFBITS, N, &mut temp, &mut qs);

        // Check for correctness.
        apply_network(&mut pi_test, out);
        let mut diff = 0u16;
        for (a, b) in pi.iter().zip(&pi_test) {
            diff |= a ^ b;
        }
        if barrier::u16_nonzero_mask(diff) == 0 {
            break;
        }
    }

    temp.zeroize();
    qs.zeroize();
    pi_test.zeroize();
}
