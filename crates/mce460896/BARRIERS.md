# mce460896 barrier map (M4 plan C7, invariant I3)

Every mask or 1-bit operation on a secret goes through exactly one call into
`src/barrier.rs`. This table is the member set: each source call site, and
the port call site that replaces it. Line numbers are those of the port at
the commit that adds or changes this file.

Sources:

- **libmceliece** 20260622, `crypto_kem/460896pc/vec` (its symlinks
  resolved into `460896/vec`, `460896/avx`, `348864/vec`, `348864/avx`,
  `348864pc/avx`): every `crypto_int*_*` / `crypto_uint*_*` call in the
  ported files.
- **Round 3**: the reference liboqs 0.8 vendors (oqs-sys 0.8.0,
  `src/kem/classic_mceliece/pqclean_mceliece460896_vec`), pinned by
  `tools/rp-vectors`' lock: every mask site of its KEM framing
  (`operations.c`) and of its sampler (`encrypt.c` `gen_e`).

## libmceliece cryptoint call sites

| # | Source (file:function) | Call | Port site | Barrier call |
|---|---|---|---|---|
| L1 | `bm.c:update` | `crypto_int64_bitmod_01(e, i)` | `bm.rs:update` (72) | `u64_bitmod_01` |
| L2 | `bm.c:vec_reduce` | `crypto_int64_bottombit_01(tmp)` | `bm.rs:vec_reduce` (91) | `u64_bottombit_01` |
| L3 | `bm.c:bm` | `crypto_uint64_nonzero_mask(d)` | `bm.rs:bm` (127) | `u64_nonzero_mask` |
| L4 | `bm.c:bm` | `crypto_uint64_leq_mask(L*2, N)` | `bm.rs:bm` (128) | `u64_leq_mask` |
| L5 | `bm.c:bm` | `crypto_int64_bitmod_01(d, i)` | `bm.rs:bm` (131) | `u64_bitmod_01` |
| L6 | `bm.c:bm` | `crypto_int64_bitmod_01(b, i)` | `bm.rs:bm` (134) | `u64_bitmod_01` |
| L7 | `decrypt.c:weight_check` | `crypto_int64_bitmod_01(error[i/64], i)` | `decrypt.rs:weight_check` (93) | `u64_bitmod_01` |
| L8 | `decrypt.c:weight_check` | `crypto_int8_bitmod_01(e[i/8], i)` | `decrypt.rs:weight_check` (96) | `u8_bitmod_01` |
| L9 | `decrypt.c:weight_check` | `-crypto_int16_zero_mask(check)` | `decrypt.rs:weight_check` (100) | `u16_zero_01` |
| L10 | `encrypt.c:syndrome` | `crypto_uint64_bottombit_01(b)` | `encrypt.rs:syndrome` (125) | `u64_bottombit_01` |
| L11 | `fft.c:butterflies` | `crypto_int64_bitmod_mask(beta[i], j)` | `fft.rs:butterflies` (69) | `u64_bitmod_mask` |
| L12 | `fft_tr.c:butterflies_tr` | `crypto_int64_bitmod_01(beta[0], j)` | `fft_tr.rs:butterflies_tr` (240) | `u64_bitmod_01` |
| L13 | `fft_tr.c:butterflies_tr` | `crypto_int64_bitmod_01(beta[i], j)` | `fft_tr.rs:butterflies_tr` (248) | `u64_bitmod_01` |
| L14 | `gf.c:gf_iszero` | `crypto_int32_zero_mask(a)` | `gf.rs:iszero` (13) | `u32_zero_mask` |
| L15 | `gf.c:gf_sq` | `crypto_int32_shlmod(x,8)` | `gf.rs:sq` (43) | `u32_shlmod` |
| L16 | `gf.c:gf_sq` | `crypto_int32_shlmod(x,4)` | `gf.rs:sq` (44) | `u32_shlmod` |
| L17 | `gf.c:gf_sq` | `crypto_int32_shlmod(x,2)` | `gf.rs:sq` (45) | `u32_shlmod` |
| L18 | `gf.c:gf_sq` | `crypto_int32_shlmod(x,1)` | `gf.rs:sq` (46) | `u32_shlmod` |
| L19 | `gf.c:gf_sq2` | `crypto_int64_shlmod(x,24)` | `gf.rs:sq2` (63) | `u64_shlmod` |
| L20 | `gf.c:gf_sq2` | `crypto_int64_shlmod(x,12)` | `gf.rs:sq2` (64) | `u64_shlmod` |
| L21 | `gf.c:gf_sq2` | `crypto_int64_shlmod(x,6)` | `gf.rs:sq2` (65) | `u64_shlmod` |
| L22 | `gf.c:gf_sq2` | `crypto_int64_shlmod(x,3)` | `gf.rs:sq2` (66) | `u64_shlmod` |
| L23 | `gf_2m_mul.c:gf_mul` | `crypto_int32_bottombit_mask(t1)` (before the loop) | `gf.rs:mul` (22) | `u32_bottombit_mask` |
| L24 | `gf_2m_mul.c:gf_mul` | `crypto_int32_bottombit_mask(t1)` (in the loop) | `gf.rs:mul` (26) | `u32_bottombit_mask` |
| L25 | `kem_dec.c:operation_dec` | `crypto_uint8_zero_mask(fail)` | `lib.rs:decaps_core` (127) | `u8_zero_mask` |
| L26 | `kem_dec.c:operation_dec` | `crypto_uint8_bottombit_01(m)` | `lib.rs:decaps_core` (130) | `u8_bottombit_01` |
| L27 | `util.h:irr_load` | `crypto_int64_bitmod_01(irr[j], i)` (low half) | `util.rs:irr_load` (58) | `u64_bitmod_01` |
| L28 | `util.h:irr_load` | `crypto_int64_bitmod_01(irr[j], i)` (high half) | `util.rs:irr_load` (63) | `u64_bitmod_01` |
| L29 | `vec.h:vec_set1_16b` | `crypto_int64_shlmod(ret,16)` | `vec.rs:set1_16b` (29) | `u64_shlmod` |
| L30 | `vec.h:vec_set1_16b` | `crypto_int64_shlmod(ret,32)` | `vec.rs:set1_16b` (30) | `u64_shlmod` |
| L31 | `vec.h:vec_testz` | `crypto_int64_bottombit_01(a)` | `vec.rs:testz` (54) | `u64_bottombit_01` |

The remaining cryptoint calls in those files are not mask operations, or
belong to code the port replaces; none has a barrier site:

| Source | Call | Port |
|---|---|---|
| `encrypt.c:syndrome` | `crypto_uint64_load` (2 sites), `crypto_uint32_load` (2) | plain little-endian `load8` / `load4` (`util.rs`) |
| `encrypt.c:uint16_is_smaller_declassify` | `crypto_uint16_smaller_mask` | not ported: libmceliece's `gen_e` declassifies and branches; replaced by the round-3 sampler (R5–R11) |
| `encrypt.c:gen_e` | `crypto_int16_negative_mask`, `crypto_uint16_store` | not ported, as above (also `crypto_sort_int16`, `crypto_xof_bitwrite16`) |

`gf_2m_mul2.c` (`gf_mul2`) is not ported (nothing calls it).
`gf_2mt_mul.c` (`GF_mul`) and `kem_keypair.c` have no cryptoint calls.

## Round-3 framing and sampler mask sites

| # | Source (file:function) | Site | Port site | Barrier call |
|---|---|---|---|---|
| R1 | `operations.c:crypto_kem_dec` | C1 compare, `ret_confirm \|= conf[i] ^ c[SYND_BYTES + i]` | `lib.rs:decaps_core` (123), accumulated into the decode failure | `u8_or` |
| R2 | `operations.c:crypto_kem_dec` | failure merge, `m = ret_decrypt \| ret_confirm; m -= 1; m >>= 8` | `lib.rs:decaps_core` (127), shared with L25 | `u8_zero_mask` |
| R3 | `operations.c:crypto_kem_dec` | `*x++ = (~m & 0) \| (m & 1)` | `lib.rs:decaps_core` (130), shared with L26 | `u8_bottombit_01` |
| R4 | `operations.c:crypto_kem_dec` | `e`/`s` select, `(~m & sk[i]) \| (m & e[i])` | `lib.rs:decaps_core` (132) | `u8_select` |
| R5 | `encrypt.c:gen_e` | filter, `if (ind[i] < SYS_N)` | `encrypt.rs:gen_e` (66) | `u16_smaller_mask` |
| R6 | `encrypt.c:gen_e` | compaction, `ind32[count++] = ind[i]` | `encrypt.rs:gen_e` (68): slot `k` masked by `count == k` | `u16_equal_mask` |
| R7 | `encrypt.c:gen_e` | `if (count < SYS_T) continue` | `encrypt.rs:gen_e` (72) | `u16_smaller_mask` |
| R8 | `encrypt.c:gen_e` | duplicate check, `if (ind32[i] == ind32[j]) eq = 1` | `encrypt.rs:gen_e` (77), OR-accumulated | `u16_or_equal_mask` |
| R9 | `encrypt.c:gen_e` | accept, `if (eq == 0) break` (with R7) | `encrypt.rs:gen_e` (92) | `u16_equal_mask` |
| R10 | `encrypt.c:gen_e` | `val[j] = one << (ind32[j] & 63)` | `encrypt.rs:gen_e` (84) | `u64_shlmod` |
| R11 | `encrypt.c:gen_e` | `mask = i ^ (ind32[j] >> 6); mask -= 1; mask >>= 63; mask = -mask` | `encrypt.rs:gen_e` (85) | `u64_equal_mask` |
| R12 | `encrypt.c:syndrome` | `b &= 1` | `encrypt.rs:syndrome` (125), shared with L10 | `u64_bottombit_01` |

## Key generation (host only; out of the C9/C10 identity set)

`src/keygen/` ports libmceliece `sk_gen.c`, `pk_gen.c`, `controlbits.c`
and `kem_keypair.c`. It runs only in `tools/mksecrets` and is not in the
identity set (map-out), but its cryptoint calls go through the barrier all
the same. Where libmceliece declassifies a rejection
(`*_is_*_declassify`) the port branches on the barrier's mask, as the C
code branches on the declassified one: the rejection is public.

| # | Source (file:function) | Call | Port site | Barrier call |
|---|---|---|---|---|
| K1 | `sk_gen.c:gf_is_zero_declassify` | `crypto_uint16_zero_mask(t)` | `keygen/sk_gen.rs:genpoly_gen` (60) | `u16_zero_mask` |
| K2 | `pk_gen.c:uint64_is_equal_declassify` | `crypto_uint64_equal_mask(t,u)` | `keygen/pk_gen.rs:pk_gen` (109) | `u64_equal_mask` |
| K3 | `pk_gen.c:uint64_is_zero_declassify` | `crypto_uint64_zero_mask(t)` | `keygen/pk_gen.rs:pk_gen` (153) | `u64_zero_mask` |
| K4 | `pk_gen.c:de_bitslicing` | `crypto_int64_bitmod_01(in[i][j], r)` | `keygen/pk_gen.rs:de_bitslicing` (32) | `u64_bitmod_01` |
| K5 | `pk_gen.c:to_bitslicing_2x` | `crypto_int64_bitmod_01(in[i*64 + r], j + GFBITS)` | `keygen/pk_gen.rs:to_bitslicing_2x` (45) | `u64_bitmod_01` |
| K6 | `pk_gen.c:to_bitslicing_2x` | `crypto_int64_bitmod_01(in[i*64 + r], j)` | `keygen/pk_gen.rs:to_bitslicing_2x` (51) | `u64_bitmod_01` |
| K7 | `pk_gen.c:pk_gen` | `~crypto_uint64_bitmod_mask(mat[row][i], j)` (pivot search) | `keygen/pk_gen.rs:bit_mask` (61), called at 145 | `u64_bitmod_mask` |
| K8 | `pk_gen.c:pk_gen` | `crypto_uint64_bitmod_mask(mat[row][i], j)` (systematic check, with K3) | `keygen/pk_gen.rs:bit_mask` (61), called at 153 | `u64_bitmod_mask` |
| K9 | `pk_gen.c:pk_gen` | `crypto_uint64_bitmod_mask(mat[k][i], j)` (elimination) | `keygen/pk_gen.rs:bit_mask` (61), called at 158 | `u64_bitmod_mask` |
| K10 | `pk_gen.c:pk_gen` | `crypto_uint64_bitmod_mask(mat[k][row/64], row)` (back substitution) | `keygen/pk_gen.rs:bit_mask` (61), called at 169 | `u64_bitmod_mask` |
| K11 | `pk_gen.c:pk_gen` | `crypto_uint64_bitmod_mask(ops[row][c >> 6], c)` (row output) | `keygen/pk_gen.rs:bit_mask` (61), called at 197 | `u64_bitmod_mask` |
| K12 | `controlbits.c:cbrecursion` | `int32_min(px, x)` | `keygen/controlbits.rs:cbrecursion` (49) | `u32_min` |
| K13 | `controlbits.c:cbrecursion` | `int32_min(ppcx, ppcpx)` | `keygen/controlbits.rs:cbrecursion` (84) | `u32_min` |
| K14 | `controlbits.c:cbrecursion` | `int32_min(B[x], cpx)` | `keygen/controlbits.rs:cbrecursion` (119) | `u32_min` |
| K15 | `controlbits.c:cbrecursion` | `crypto_int32_bottombit_01(B[z])` | `keygen/controlbits.rs:cbrecursion` (134) | `u32_bottombit_01` |
| K16 | `controlbits.c:cbrecursion` | `crypto_int32_bottombit_01(B[y])` | `keygen/controlbits.rs:cbrecursion` (152) | `u32_bottombit_01` |
| K17 | `controlbits.c:layer` | `crypto_int8_bitmod_mask(cb[index >> 3], index)` | `keygen/controlbits.rs:layer` (185) | `u8_bitmod_mask` |
| K18 | `controlbits.c:controlbitsfrompermutation` | `crypto_int16_nonzero_mask(diff)` | `keygen/controlbits.rs:controlbits` (223) | `u16_nonzero_mask` |

Not barrier sites: `crypto_sort_int32` / `crypto_sort_int64` (replaced by
the Batcher networks of `keygen/sort.rs`, whose compare-exchange masks are
plain `wrapping_*` arithmetic), `crypto_declassify` (see above), and the
reference's own `-` / `&` masks in `genpoly_gen` (`gf_iszero`, L14).

## Port-only sites

| # | Port site | Purpose | Barrier call |
|---|---|---|---|
| P1 | `lib.rs:encaps_attempt_core` (192) | the returned accept bit (outputs are masked by the R9 mask) | `u8_bottombit_01` |

## Count

- Source sites: 31 libmceliece decode and framing (L1–L31), 12 round-3
  (R1–R12) and 18 libmceliece key generation (K1–K18), 61 in all. R2, R3
  and R12 share their port site with L25, L26 and L10; K7–K11 share the
  one call in `keygen/pk_gen.rs:bit_mask`.
- Port barrier call sites outside `barrier.rs`: **55**
  (`grep -rn 'barrier::' src` without the `use` lines and `barrier.rs`):
  31 for L1–L31, 9 for the unshared R1, R4–R11, 1 port-only (P1) and 14
  for key generation (K1–K6, K7–K11 as one, K12–K18).
- In the C9/C10 identity set (decaps, encaps_attempt): 30, that is all
  but the key-generation sites and `gf.rs` (L14–L24), which only key
  generation calls.
