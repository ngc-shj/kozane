# Coding Deviation Log: secureos-m4-verus-mceliece

## V0b — Verus in the dev image, first annotation in wg-wire

### Result

All five V0b steps pass with `vstd` in `wg-wire` and one annotated
function. `below_window` is the replay window's lower-bound compare,
factored out of `check_and_update`:

| Step | Result |
|---|---|
| 1. `make pds lint-pds` | rc 0 (build-std, `clippy -D warnings`) |
| 2. Kani `proofs::replay_window_rejects_second_use`, alone | SUCCESSFUL |
| 3. bolero target `wg-wire` | rc 0, seed corpus loaded |
| 4. `make unit` | rc 0 |
| 5. `cargo verus verify -p wg-wire` | `1 verified, 0 errors` |

The `cargo verus` invocation was:

```
PATH=/opt/verus:$PATH RUSTUP_TOOLCHAIN=1.98.1 VERUS_Z3_PATH=/opt/verus/z3 \
cargo verus verify -p wg-wire --locked --offline --target-dir build/target-verus
```

**Red-proof (on a scratch copy):** `<` changed to `<=` in `below_window`
fails with `postcondition not satisfied`, `0 verified, 1 errors`.

**vstd pairing:** crates.io `vstd 0.0.0-2026-10-04-0306` resolves
`verus_builtin 0.0.0-2026-09-16-0054` and `verus_builtin_macros
0.0.0-2026-09-20-0158`. These are the same versions the Verus source tree
at the pinned commit carries (V0 probe), so the pairing is confirmed.

**Verus source tarball:** sha256
`40be6fb66e457ca71210cb85b3febf3f43fce106df8db3caf3c18df349ab0b93`.

### Deviations

- **The Verus build needs a git repository.** `rust_verify/build.rs` and
  vargo read `git rev-parse HEAD` and `git show` and panic without them.
  - The stage therefore commits the sha256-checked tarball tree into a
    throwaway repository.
  - vargo overrides `VARGO_BUILD_VERSION`/`VARGO_BUILD_SHA` from that
    repository, so `verus --version` reports `0.2026.10.21.8c07505`: the
    throwaway commit's date and hash.
  - The real pin is in `/opt/verus/SOURCE` (`426d8b0…`). The reported
    string identifies nothing and is not used by any gate.
- **The `.text` comparison must use the same checkout path.** A git
  worktree at another path changed every PD's `.text`, including PDs that
  do not link wg-wire. This was address layout, not code.
  - The comparison is therefore done in `/work`: the slice's changes are
    stashed, the PDs are built and saved, the changes are restored, and the
    PDs are rebuilt.
  - The comparison uses `objdump -d`, normalised for addresses, symbol
    hashes, `anon.*`/`.llvm.*` suffixes and immediates.
  - `tools/pd-text-hashes` prints raw `.text` sha256s as the first signal.
- **The `.text` record for V0b:**
  - **Unchanged:** the PDs that do not link wg-wire (audit, eth-in,
    eth-out, inner, timer).
  - **Changed:** data, hs, ingress, key, pq and pqkey.
  - **Normalised, as first annotated:** `verus!` left `below_window` out of
    line, a `bl` from `check_and_update` in pd-data.
  - **After `#[inline]` on `below_window`:** the only differences are
    `adrp` targets that objdump labels with neighbouring data symbols
    (layout), or reordered functions. The sorted multisets differ by 18
    lines in data and in hs, all of them data-page references. ingress
    differs by 0. The instruction streams are otherwise identical.
  - **Rule kept for later slices:** a function inside `verus!` that was
    inlined before is marked `#[inline]`, so its code shape is unchanged.

## V1 — the Verus gate (C1) and wg-wire (C2)

### Result

- **`make verus`:** `VERUS-WG-WIRE 62`, `VERUS-ENSURES-WG-WIRE 47`,
  `VERUS-FUNCTIONS 62`, `VERUS-TRUSTED-CHECKED 1`. The second run is a
  cached pass.
- **Trusted constructs:** none in wg-wire. `policy/verus-trusted.toml` is
  empty.
- **check-selftest:** all five cases fail for their named reason:

  | Case | Needle |
  |---|---|
  | `verus-cache` | both sides checked |
  | `verus-trusted` | the cfg_attr spelling |
  | `verus-required` | — |
  | `verus-wg-wire-window` | `r == (c + window < top)` |
  | `verus-wg-wire-roundtrip` | `r is Ok <==> (bytes@.len() == INITIATION_LEN as int` |

- **Other checks:**
  - unit 716 (wg-wire 13), unchanged;
  - Kani wg-wire 5/5;
  - bolero wg-wire;
  - `cargo clippy -p wg-wire -D warnings`.

### Deviations

- **Codec refactor (C2, plan: refactor to forms vstd specifies).**
  - `Reader`/`Writer` used `split_first_chunk`, `split_at_mut_checked` and
    `core::mem::take`, and vstd has no specs for them. They are replaced by
    `read_array::<N>` and `write_at`, using `get`/`get_mut` over literal
    ranges and `checked_add`, plus shift/mask LE conversions.
  - Array-pattern destructuring is not supported by Verus, so literal
    indexing into fixed arrays is used instead. Clippy's `indexing_slicing`
    does not flag that.
  - Behaviour is unchanged. The unit tests, Kani and bolero pass
    unmodified.
- **The round trip is a pair of spec lemmas per type.** For each type,
  `lemma_spec_emit_*_parses` and `lemma_spec_emit_*_inverse` relate a
  field-level `spec_emit_*` to `parse`'s field formulas. Each emitter's
  `ensures` is `final(out)@.subrange(0, LEN) == spec_emit_*(…)`.
  - The lemmas take field values, not a struct, because spec code cannot
    construct `[u8; N]` from a `Seq`.
  - The LE lemmas extract bytes before `by (bit_vector)`, which rejects
    `Seq` indexing.
- **ReplayWindow:**
  - It gains a `Ghost<Set<int>>` field `accepted`, of zero size.
  - `WINDOW` is computed without `saturating_sub`, which Verus cannot call
    in a const; the value is unchanged.
  - `new()` is no longer a `const fn`, because a ghost field cannot be
    initialised in one. No const caller exists: wg-core calls it from
    `Session::new`.
  - `well_formed`, `top_value` and `has_accepted` are `closed` spec fns,
    because the fields are private.
  - The invariant adds `(BITS as u64) < u64::MAX`, so that the clearing
    loop's step counter cannot wrap.
- **The `.text` record for V1:**
  - **Unchanged (normalised):** key, pq, pqkey and audit.
  - **Changed:** data, hs and ingress, the users of the wg-wire codecs.
    Their instruction counts went 10601→10605, 19471→19598 and
    22683→22812: per-field bounds checks.
  - **Panic paths:** the count of `core::panicking`/`slice::index` call
    sites is unchanged in all three (124, 210, 163). The refactor added no
    panic path.
  - This is a reviewed code-shape change, as the plan allows.

## M-1 — identity probe (C10, before the port)

### Result: identity is reachable

The probe compared `keccak` (which `pd-pq` already ships) and a probe
function between a harness build and the PD build.

| Harness build | `keccak::keccak_p::<u64>` normalised diff |
|---|---|
| `aarch64-unknown-linux-gnu`, PD flags (`opt-level s`, overflow checks, panic=abort, static relocation, `+v8a,+strict-align,+neon`) | 387 lines |
| … plus `-C force-frame-pointers=no` | 387 lines: the linux target's `frame-pointer: non-leaf` overrides the flag |
| `aarch64-ct-harness.json` (below), `-Z build-std=std,panic_abort`, linked by cc | 12 lines: `adrp+add` against lld's relaxed `nop; adr` |
| … linked by rust-lld (`-Clinker-flavor=gnu-lld-cc -Clink-self-contained=+linker`) | **0 lines** |

The harness target, `aarch64-ct-harness.json`, is the linux-gnu spec with
the codegen-relevant fields of `support/targets/aarch64-sel4-microkit.json`:

- `frame-pointer` removed;
- `disable-redzone: true`;
- `features: +v8a,+strict-align,+neon`;
- `panic-strategy: abort`;
- `relocation-model: static`;
- `position-independent-executables: false` and
  `static-position-independent-executables: false`;
- `stack-probes: inline`;
- `default-uwtable: true`.

It keeps `llvm-target` `aarch64-unknown-linux-gnu`, so it links against
glibc for valgrind.

**The probe function** (`copy_from_slice`, a bounds-checked index and an
overflow-checked add) was compiled for both targets as a `no_std`
staticlib. With build-std `core` on both, the pre-link disassembly
matches except for `core`'s v0-mangling crate hash (`Cs<hash>_`), which
differs per build. The C10 normaliser must mask that hash.

### Consequences for C9/C10 (recorded before M2)

- **Harness build:** the harness is built for `aarch64-ct-harness.json`
  with `-Zjson-target-spec -Z build-std=std,panic_abort`, linked by
  rust-lld. That replaces C9's `-C relocation-model=static` and
  frame-pointer flags. The JSON is committed under `support/targets/` in
  M2.
- **Generic instantiations:** `core::slice::copy_from_slice_impl` is called
  out of line, as a `core` generic. The C10 closure follows it, and it
  matches across builds because both build `core` from the same source with
  the same flags. Whether `-Z share-generics=no` is still needed is decided
  in M2, on the real closure.

## M1 — port source

- **Source: libmceliece 20260622 `crypto_kem/460896pc/vec`.** The tarball's
  sha256 is `a30b93fcc51281881a31007c0b82cdfaff532a9d2dba87c7f99760f1f83266b7`.
  - The `pc` ("plaintext confirmation") variant is libmceliece's round-3
    framing: `C1 = H(2,e)`, `K = H(1, e, C0‖C1)`, a 188-byte ciphertext
    (`348864pc/avx/kem_enc.c`).
  - The plan's round-1 refinement had combined libmceliece's core with a
    round-3 framing source from elsewhere. Since libmceliece itself ships
    the round-3 framing, the core and the framing both come from it, as
    the owner originally decided. The I3 mapping table maps libmceliece's
    `crypto_int*`/`crypto_uint*` sites throughout.
- **Reference and oracle:** PQClean's round-3 `mceliece460896_vec`, as
  vendored by liboqs 0.8 (`oqs-sys-0.8.0/liboqs/src/kem/classic_mceliece/pqclean_mceliece460896_vec`).
  The C8 vectors come from it. Where libmceliece's encaps sampler consumes
  the stream differently, the port follows liboqs, as C8 requires, and
  the difference is recorded below.

- **liboqs 0.8's keygen is round 2.** The port found this; the
  orchestrator decided the response.
  - **What liboqs does:** oqs-sys 0.8.0's `pqclean_mceliece460896_vec` is
    byte-identical (md5) to the PQClean source. Its keygen is round 2:
    - AES-256-CTR seed expansion;
    - the round-2 field polynomial `y^96+714y^11+5296y^5+728y^4+5881`;
    - a 13568-byte sk with round-2 control bits.
    
    Its KEM framing is round 3, and the peers' decapsulation interoperates
    with round-3/4 keys (the C8 decaps classes all match).
  - **Decision:** the gateway generates its own static key (`mksecrets`),
    so its keygen need not match the peers'. The port uses libmceliece's
    own round-3/4 keygen: SHAKE-based, δ stored, no AES in the crate. That
    is the plan's "round 3 keygen", and it matches the deployed cmr keys.
  - **Vector roles:**
    - keygen is checked against the frozen cmr bridge (`cmr.i.kp_seed` →
      `pk_sha3`, `sk`);
    - encaps and decaps are checked against liboqs. liboqs's pk is
      rebuilt from `sk_oqs` and checked against `pk_sha3`.
- **Encaps sampling follows liboqs's round-3 `gen_e`.** libmceliece's
  sampler (filter, sort, declassify branch) consumes the stream
  differently. The port implements liboqs's semantics without branches or
  secret addresses, and it matches all three liboqs entries, including
  their 1, 3 and 4 attempts.

### M1 result (C7, C8)

- **`crates/mce460896`:** libmceliece 20260622 `460896pc/vec`, ported to
  no_std Rust.
  - Dependencies: `sha3 =0.10.9` and `zeroize =1.8.1` only.
  - `unsafe` appears only in `barrier.rs`.
  - Unit tests: 5 unit, 5 rng, 2 stack and 5 vectors, in dev and in
    `--release`; `clippy --all-targets -D warnings` is clean.
- **Equivalence:**
  - Keygen matches cmr 2.0.2 byte for byte (pk SHA3-256 and the 13608-byte
    sk, for all three bridge seeds). Both draw one 32-byte δ, expand it
    with SHAKE256(64‖δ), and use the field polynomial
    `y^96+y^10+y^9+y^6+1`.
  - Encaps matches liboqs (ct and ss) for all three entries, with 1, 3 and
    4 sampling attempts.
  - Decaps matches liboqs and cmr in all four classes.
  - The liboqs pk is rebuilt from `sk_oqs` by `pk_from_sk` and checked
    against `pk_sha3`.
- **Red check (orchestrator, scratch copy):** one flipped nibble in
  `mce.1.dec.c1.ss` fails `liboqs_decaps_matches_in_every_class`.
- **Constants:**
  - `ENCAPS_RAND_LEN` is 384.
  - `SCRUB_DEPTH` is 96 KiB. The measured peaks, by stack-exhaustion
    bisection, are: `decaps_core` 64 KiB; `encaps_attempt_core` 20 KiB in
    dev and 4 KiB in release. A unit test asserts depth ≥ peak + 16 KiB.
  - decaps' root therefore uses about 96 KiB of pqkey's 128 KiB stack.
- **`BARRIERS.md`:** 55 port-side barrier calls for 61 source sites
  (L 31, R 12, K 18). 30 of them are in the C9/C10 identity set; keygen and
  the keygen-only `gf.rs` sites are mapped out.

### M1 deviations

- **No-std check:** `cargo build --target aarch64-unknown-none` needs
  `-Zbuild-std=core,compiler_builtins`, because the image does not install
  that target's std. The PD build uses build-std anyway.
- **Lints:**
  - `clippy::indexing_slicing` is allowed per module in the core and
    keygen, because every index is a public loop variable over a
    fixed-size array (I4, adjudicated by C9 and C10).
  - `arithmetic_side_effects` is allowed only in the modules whose `+ - *`
    touch public indices: vec, transpose, util, benes, fft, fft_tr and
    keygen. lib, bm, decrypt, encrypt, gf, stages and barrier stay `deny`
    and use `wrapping_*` (I7).
- **Visibility:** `decaps_core`, `encaps_attempt_core` and `pk_from_sk` are
  `#[doc(hidden)] pub`, for the stack and vector tests.
- **The shim's other branch:** besides the accept bit, the shim branches on
  the RNG's `Err`, which is public.
- **Keygen** is host-only. It needs about 1.1 MB of stack for pk_gen's
  matrix, and its rejection branches on public data, as libmceliece does.
- **C8's NIST round-3 KAT is not added (R-M8).** The round-3 submission
  (`mceliece-20201010.tar.gz`, sha256
  `1b8aca59430ca7a0569e4e918e1c0c165f67dd0ccde44760f314eaa40f75dafe`)
  contains no `kat_kem.rsp` and no hash of one, only the generator
  `nist/kat_kem.c` and the reference implementation. Its DRBG needs
  OpenSSL's AES. Producing the file would mean building the C reference
  as a third oracle.
  - **What covers the KAT's purpose:** keygen is byte-identical to cmr
    2.0.2, a port of that same round-3 reference whose upstream tests check
    the NIST KAT. Encaps and decaps match liboqs, which the peers run.
  - **Residual:** no direct comparison with the NIST reference's own
    output. Recorded as R-M8.

## V2 — msgs (C3) and rosenpass-wire (C4)

### Result

- **`make verus`** over wg-wire, rosenpass-wire and msgs:

  | Key | Value |
  |---|---|
  | `VERUS-MSGS` | 70 |
  | `VERUS-ENSURES-MSGS` | 43 |
  | `VERUS-ROSENPASS-WIRE` | 49 |
  | `VERUS-ENSURES-ROSENPASS-WIRE` | 23 |
  | `VERUS-FUNCTIONS` | 181 |
  | `VERUS-TRUSTED-CHECKED` | 3 |

- **Coverage:** all 8 `pub fn decode` sites of msgs are verified, as are all
  4 parse/emit pairs of rosenpass-wire, `peek_type`, and the round-trip
  lemmas.
- **check-selftest:** `verus-msgs-exact` (needle
  `r is Ok <==> b@.len() == INITIATION_MSG_LEN as int`) and
  `verus-rp-wire-roundtrip` (needle `=~= spec_emit_init_conf(`) are red
  under their mutations.

### Deviations

- **msgs chunk_ref: the one trusted construct (owner-approved,
  2026-10-22).**
  - **Why it exists:** `Initiation`, `Response`, `Install` and `PskInstall`
    borrow `&'a [u8; N]` from the middle of the input on purpose. Zero copy
    means no secret copy (`send`, `recv`, `osk`). vstd has no spec for
    `TryFrom<&[u8]> for &[u8; N]`, and its error type would need
    `external_type_specification`.
  - **Who added it:** the sub-agent's attempt to add an `external_body`
    was denied by the permission system ("Security Weaken"). The owner then
    chose option 1, a single Kani-checked trusted helper, and the
    orchestrator added it.
  - **What it is:** `chunk_ref::<N>(b, at) -> Option<&[u8; N]>` is
    `#[verifier::external_body]`. Its ensures says it returns `Some` iff
    `at + N <= len`, and that the bytes are `b@.subrange(at, at + N)`. It
    is listed in `policy/verus-trusted.toml` and in msgs' required list.
  - **How the contract is checked:** Kani harnesses `chunk_ref_initiation`
    (148), `chunk_ref_response` (92) and `chunk_ref_key` (32) check it for
    every `N` the decoders borrow, over any input up to `N + 8` bytes and
    any offset. They check that it is `Some` exactly when in range, and
    that the result points at `b[at]`. The content equality follows from
    the aliasing. An explicit byte compare made cbmc unroll `memcmp` per
    byte, past the unwind bound.
- **Refactors:**
  - **Both crates:** like wg-wire, they use local `read_array`/`write_at`
    and LE helpers instead of `split_first_chunk`, `split_at_mut_checked`,
    `mem::take`, `from_le_bytes` and array patterns.
  - **rosenpass-wire:** `(r0 | r1 | r2) != 0` became `r0 != 0 || r1 != 0 ||
    r2 != 0`, because Verus's integer theory does not relate a byte OR to
    "not all zero". `peek_type` reads through `read_array::<1>`.
  - **msgs:** `EP_LEN` and the four tag constants became `pub`, because a
    public spec cannot name a private const. The legacy
    `put`/`take`/`put_ep`/`take_ep` are removed. The whole crate is one
    `verus!` block.
- **The `.text` record for V2:**
  - **Method:** normalised and sorted disassembly against a V1 worktree
    (`317cda7`). The control PDs audit, timer, eth-in and inner differ by
    0 lines, so the path-independent comparison is valid.
  - **Changed:** the users of msgs and rosenpass-wire. Instruction counts
    went from V1 to V2 as follows:

    | PD | Instructions |
    |---|---|
    | data | 10605→10613 |
    | hs | 19598→19595 |
    | ingress | 22812→22881 |
    | pq | 28484→28843 |
    | pqkey | 6 lines reordered |

  - **Panic paths:** the `core::panicking`/`slice::index` call-site counts
    are unchanged in all five PDs (124, 210, 163, 237, 116).
- **Kani:**
  - msgs now has 7 harnesses (4 + the 3 `chunk_ref` contracts) and
    rosenpass-wire has 10, all passing.
  - Selftest `kani-chunk-ref` (a body that borrows one byte late) fails at
    the pointer assertion.

## V4 — ring, pure logic (C6)

### Result

- **Verus:** `VERUS-RING 15`, `VERUS-ENSURES-RING 12`, with no trusted
  construct. Kani ring 11/11 still passes, and so do the 37 unit tests.
- **Selftest:** `verus-ring-mask` (mask with N) is red. Needle:
  `r == (idx & ((N - 1) as u32)) as usize`.
- **Coverage:**
  - `slot` and `ring_len` hold for any `0 < N <= 65536`.
  - `Pool::{accept, give, first_mine, mine_count}` hold for any `M`/`BUF`.
    `accept` flips only an unowned slot and `give` only an owned one; every
    other slot is unchanged.
  - The held receive goes through the verified `begin_take`/`end_release`.
    A second take is refused while one is held, and the release succeeds
    exactly once per hold.

### Deviations

- **Without a trusted model of SharedAccess/Region.**
  - The plan modelled both as spec-only traits on the allowlist. Adding any
    trusted construct needs the owner, so C6 was done without one instead.
  - The pure logic is factored into functions that take the values read
    from shared memory as parameters. The `SharedAccess`/`shmem` calls
    stay outside `verus!`, unchanged.
- **"No buffer owned by both sides" is proved per Pool only.**
  - What is proved: an accept never takes an owned slot, and a give never
    gives an unowned one.
  - What is not: the two-sided invariant would need the Sender's and the
    Receiver's Pools modelled jointly, which is a larger proof. The Kani
    harness `pool_accept_stays_in_region` and the link tests keep covering
    it end to end. It is recorded under SC30.
- **Refactors (behaviour unchanged; tests.rs unedited):**
  - **The compile-time check of `N`:** `Mask::<N>::VALUE` is now read in
    `Producer::new`/`Consumer::new`; `slot`/`ring_len` compute the mask
    themselves. Verus cannot evaluate the `assert!`-guarded const. Every
    instantiated N is still checked at compile time, because the fields are
    private and `new` is the only constructor.
  - **Moved inside `verus!`:** `Desc` and `LinkError`, because verified
    ensures name them.
  - **Rewritten loops:** `first_mine` and `mine_count` are indexed loops,
    replacing `iter().position`/`filter().count()`.
  - **Rewritten error handling:** `accept`'s `map_err`/`ok_or` chains are
    now `match`.
  - **One un-collapsed `if let`:** Verus rejects let-chains, so it is kept
    with `#[allow(clippy::collapsible_if)]`.
- **The `.text` record** for V4 is taken together with V3, after the wire
  slice.

## V3 — wire (C5), and the `.text` record for V3 + V4

### Result

- **Verus:** `VERUS-WIRE 82`, `VERUS-ENSURES-WIRE 53`, with no trusted
  construct.
- **Other checks:** Kani wire 5/5, bolero wire, 32 unit tests and
  `clippy -D warnings` all pass.
- **Selftest:** `verus-wire-ipv4` (the TTL ≤ 1 refusal removed) is red.
  Needle: `r is Ok <==> (ipv4_header_ok(packet@) && packet@[8] > 1`.
- **Proved, for any frame up to the MTU:**
  - `parse_frame`, `parse_frame_ip` and `parse_ipv4_packet` accept exactly
    their predicates: version 4, no options, no fragments, a checksum that
    folds to 0, a valid source, and `IPV4_HDR <= total_len <= len`.
  - `forward_ipv4` refuses TTL ≤ 1, and its output is the specified
    decremented packet with a recomputed checksum.
  - `emit` produces the specified bytes for each body, including the UDP
    pseudo-header checksum with RFC 768's 0 → 0xffff.
  - The Internet checksum equals its spec. A number-theory proof shows
    that embedding it validates.

### Deviations

- **`check_into` and `check_ip_into` are not Verus-checked.** Both are
  `#[cfg(any(test, kani))]` test helpers that ship in no PD. Verus's pass
  does not compile them, so an `ensures` on them would never be checked.
  With `verus_keep_ghost` forced on, their internal `assert!`/`panic!`
  needed runtime `PartialEq` on `Option<Result<Frame, _>>` related to spec
  equality, which did not close. The helpers are unchanged, and unit and
  bolero tests exercise them. The plan's C5 entry-point list is narrowed to
  the five that ship.
- **Refactors (behaviour unchanged; tests.rs and proofs.rs unedited):**
  - `csum_add`/`csum_fold` use a `read_array` loop and two unrolled folds,
    which are always sufficient for a `u32`.
  - `Writer` is replaced by fixed-offset `write_at`.
  - The `drop_reasons!` macro is a hand-written enum, with `ALL` kept
    outside `verus!`.
  - Three constants are now `pub`.
  - `emit`'s `Body::Ipv4` precondition compares field by field.
  - A few `saturating_*` replace `+`/`-` for `arithmetic_side_effects`.
- **The `.text` record for V3 + V4**, normalised and sorted, against
  `851dbdd`:
  - **Unchanged:** audit, timer and key (ring's index code inlines as
    before).
  - **Changed** (the users of wire's parsers and checksum):
    - inner: 7022→7238
    - ingress: 22881→23104
    - data: 10613→10730
  - **Layout-level only:** eth-in, eth-out, hs, pq and pqkey differ by
    9–18 lines.
  - **Panic paths:** no PD gained a `core::panicking`/`slice::index` call
    site; ingress went from 163 to 161.

## M2a — the constant-time gate (C9)

### Result

- **`make ct`** passes in about 3.5 s:

  | Key | Value |
  |---|---|
  | `CT-CASES` | 28 |
  | `CT-MARKED-BYTES` | 289609, confirmed undefined by `VALGRIND_GET_VBITS` |
  | `CT-DECLASSIFY` | 3 |
  | `RESIDUE-CASES` | 25 |
  | `UNIT-CT-HARNESS` | 11 |

  Memcheck reports only the canary's error. **mce460896 shows no
  constant-time violation on the executed paths.**
- **CT cases:**
  - decaps in four classes for 3 keys, plus 6 boundary weights;
  - encaps_attempt on every draw of the vector streams, plus a short and a
    repeated draw.
- **Residue cases:** 12 decaps, 10 attempts, and 3 runs of the real generic
  `encaps` shim, some with rejections. The painted depth is about 98 KB.
- **The F1 record (the one-time red-proof against cmr 2.0.2).** A scratch
  harness ran cmr's `decapsulate` under the same profile:

  ```
  Use of uninitialised value of size 8
     at classic_mceliece_rust::bm::bm (bm.rs:58)   <- b[i] = (b[i] & !mle) | (t[i] & mle)
     by classic_mceliece_rust::decrypt::decrypt (decrypt.rs:49)
  Conditional jump or move depends on uninitialised value(s)
     at classic_mceliece_rust::bm::bm (bm.rs:55)   <- the overflow check on secret l
  Conditional jump or move depends on uninitialised value(s)
     at classic_mceliece_rust::decrypt::decrypt (decrypt.rs:59)
  ERROR SUMMARY: 421615 errors from 4 contexts (one is the canary)
  ```

  This reproduces the C8 spike's F1 dynamically, and adds the
  overflow-check branch the spike rated benign.
- **check-selftest `ct` cases**, each red for its named reason:
  - `ct-barrier`: BM's two `vec_cmov`s made a branch. The report kind
    names `bm.rs`.
  - `ct-canary`, `ct-early-exit`.
  - `ct-declassify`: an unlisted site.
  - `ct-declassify-width`: `rand` declassified as the accept predicate.
  - `ct-not-valgrind` (exit 3) and `residue-under-valgrind` (exit 4).
  - `mce-residue-rand` and `mce-residue-scrub`.

### Deviations

- **Harness build:** `tools/ct-harness` is its own workspace with its own
  lock. Its dependencies are mce460896 (path), sha3, keccak and libc; all
  versions equal the root lock's.
  - Its unit tests run inside `make ct` and are counted as
    `UNIT-CT-HARNESS`, because `make unit`/`make lint` do not see it.
  - It holds two `unsafe` modules: `vg.rs` for the client requests, and
    `stack.rs` for an mmap'd stack with a guard page via
    `pthread_attr_setstack`.
- **The verdict:** it lives in the harness (`--verdict-ct`,
  `--verdict-residue`), so that its parser has unit tests. Under memcheck a
  harness failure is masked to exit 97, so the verdict also requires
  `CT-DONE` as the last line and no `CT-FAIL` line.
- **Residue red-proofs:**
  - `scrub_stack` covers a removed local wipe, so a per-form mutation needs
    the wipe and the scrub both removed.
  - Red-proved forms:
    - `rand` (the shim's wipe);
    - keccak, ss, support and syndrome (scrub removed);
    - e-bytes (wipe and scrub removed).
  - Not red-proved individually: g, bm, ind and e-bitsliced. Their needles
    are derived from pub stage outputs, and the scrub covers them.
- **One mask computation stayed branch-free when written as a branch.**
  The mask in L3 (`u64_nonzero_mask`), rewritten as `if`, stayed green: LLVM
  lowered it branch-free. `ct-barrier` therefore mutates the cmov site.
- **Painted-depth floors:** decaps 32 KiB and encaps 2 KiB, asserted ≤
  `SCRUB_DEPTH`. The floors themselves are not red-proved.
- **Record key:** computed by `tools/ct_record.py` over the harness, the
  policy, `crates/mce460896/tests/vectors/*.txt` and `valgrind --version`.
  Its six fixtures run in `make pins`.

## M3a — cut-over (C11, part 1)

- **What switched:** pqkey-core, rosenpass-core and mksecrets use
  mce460896. `classic-mceliece-rust`, `rand 0.8.8` and `rand_core 0.6.4`
  are gone from the root lock and from rp-vectors' lock. The rp-vectors
  `--cmr` mode is deleted; the frozen bridge file stays.
- **Tests:** unit counts are unchanged (pqkey-core 20, rosenpass-core 39,
  mksecrets 22, secret-blob 13). rosenpass-core's liboqs KAT and its
  fails-closed-without-randomness test pass unchanged against mce460896.
- **RNG failure handling:** the filler-RNG workarounds (`CmrRng`, and
  mksecrets' `failed` flag) are gone, because mce460896 fails the draw
  directly.
- **mksecrets' shared-key buffer:** its KAT path no longer gets cmr's
  automatic zeroize of the shared-key buffer it hashes and drops. This is a
  host-only, short-lived CLI that zeroes none of its other buffers either;
  recorded, not changed.
- **P13 is enforced.** The P6 fixtures inject a locked cmr (`lock_cmr`),
  because the live tree no longer has one. They expect P13 alongside P6,
  and three P13 fixtures are added: `CHECK-PINS-FIXTURES` 90 and
  `CHECK-PINS-RULES` 16.
- **Still to do:** C10, the package binding and SC23's close.

## M2b — identity and shape (C10), the package binding and SC23 (C11, part 2)

### Result

- **`make ct-shape`:**
  - **Identity holds with no codegen flag change.** `-Z share-generics=no`
    is not needed: both builds call the same crate's copy of each shared
    generic. The normaliser keeps the instantiating crate (` @crate`), so a
    future shift would show as an identity diff.
  - **Closures:** `mce460896::decaps` in pd-pqkey has 39 functions and 12
    stops; `mce460896::encaps_attempt` in pd-pq has 20 functions and 10
    stops. `CT-SHAPE-SYMBOLS` is 59.
  - **The shape baseline:** `policy/ct-shape.toml` holds 60 `[[function]]`
    entries, each justified.
  - **Erasure:** no PD carries a `vstd::`/`verus_builtin` symbol. The
    positive control finds each PD's entry symbol.
  - **Tests:** 30 normaliser and gate fixtures (`CT-SHAPE-FIXTURES`), run in
    `make pins`.
- **check-selftest `ct-shape` cases,** each red for its named reason:

  | Case | Mutation | Needle |
  |---|---|---|
  | `ct-shape` | the ct-barrier mutation | `ct-shape: pd-pqkey.elf: shape: mce460896::bm::bm:` |
  | `ct-identity` | pd-pq alone at `-Copt-level=3` | `ct-shape: pd-pq.elf: identity: mce460896::` |
  | `verus-erasure` | wire's `parse_frame` takes a fn pointer to a vstd exec function, kept in the eth PDs | `erasure: vstd::` |

- **The package binding:**
  - `make package` depends on `ct-harness`.
  - For every kernel config, `tools/package` runs ct-shape's identity and
    forbidden checks, and refuses if the harness is missing.
  - For non-debug configs it also requires the C9 pass record.
  - `test_package.py` gains 8 fixtures (`PACKAGE-FIXTURES` 103). One of
    them runs the real ct-shape on a mutated ELF.
- **SC23 is closed** in `policy/waivers.toml`, with `tools/waivers.py` and
  the file's comments stating the new binding. **L2 is amended**: the
  architecture plan's L2 row names `pqkey`'s basis, and the M3 plan's
  waiver row records the M4 amendment.

### Deviations

- **C10 (b) has four owner-approved `udiv` exceptions (R-M9).** The
  `[[divide]]` entries in `policy/ct-shape.toml` are pinned to the function
  and instruction. An entry that matches nothing fails. br/blr,
  memcmp/bcmp and the client-request preamble can have no exception.
- **The client-request preamble** is matched as the four-`ror` sequence.
  A lone `ror x12, x12, #3` occurs legitimately in keccak at opt-level 3.
- **The encaps shim** has no symbol in pd-pq; it is inlined into
  `<rosenpass_core::kem::McEliece460896 as Encaps>::encaps::<Hedged<..>>`,
  which carries its shape baseline.
- **Unresolved `adr` targets:** an `adr` to a rodata address that no symbol
  covers (a merged string) is masked as `<addr>`.
- **No separate allow case for package-waiver.** The planned
  `package-waiver-closed` selftest would need real secrets blobs and a full
  package build. The allow side is covered by `test_package.py`'s
  "everything green → allow" fixture and by the integration suite's three
  `make package` runs.
- **package-waiver** now opens a waiver (`SC99`) in its own copy, because
  none is open in the tree.
- **The check-pins P6 fixtures** are re-based on SC23 closed.

## C11 member set

The member set was derived by `git grep -n -E 'SC23|classic.mceliece|\bcmr\b|CmrRng|rand_core|constant.time|\bL2\b|waiver' -- ':!docs/archive'`,
run at `cec0ce2`.

- **Updated:**
  - `policy/waivers.toml` (SC23 closed, comments);
  - `tools/waivers.py` (docstring);
  - `tools/check-pins` (P6 and P13);
  - `tools/package` (the ct binding);
  - `tests/tools/test_check_pins.py` and `test_package.py` (re-based);
  - `tools/check-selftest` (`package-waiver`);
  - pqkey-core, rosenpass-core, mksecrets and rp-vectors (the cut-over);
  - the L2 rows of the architecture plan and the M3 plan.
- **Historical or provenance, kept:**
  - the cmr references in mce460896's doc comments, `BARRIERS.md` and the
    frozen bridge vectors;
  - secret-blob's `cmr_sk_from_liboqs`/`liboqs_sk_from_cmr`. The names are
    kept to avoid an API ripple, and the docs now say "round-3 spec
    layout".
  - pqkey-core's test comment;
  - rp-vectors' README note on the removed mode;
  - liboqs's own `OQS_KEM_classic_mceliece_*` symbol names.
- **Unrelated to SC23, matching only `\bL2\b`, `constant.time` or
  `rand_core`:**
  - the laws checker's L2 (`tools/laws`, `policy/laws.toml`,
    `system/secureos.system`);
  - key-core's constant-time notes;
  - other crates' `rand_core` lock entries.

## Phase 2 self-check (step 2-5)

Three experts checked `be5d54a..d1a93cb` against R1–R57, RS1–RS6 and
RT1–RT11. The first solo `make check` at `d1a93cb` also failed, in `test`.

- **`make check` failure:** `run.py`'s reason-list check looked for the
  `drop_reasons!` macro, which C5 replaced with a plain enum. The macro had
  also made "every variant is in `DropReason::ALL`" true by construction.
  The check now parses the enum and `ALL`, and requires both to equal its
  list. The `ALL` comparison was red-proved by dropping one entry.
- **P9/P10 (Major):** plan C11 adds mce460896 to the secret-crate lists; it
  had not been added. It is now in `SECRET_CRATES`, so P10 covers it too,
  with one deny fixture each.
- **P16 (Major):** P16 compared the key names of `[dependencies]`, so a
  `package =` rename, a `[patch]`, or a change below sha3 passed. It now
  judges the resolved set. Each dependency must name sha3 or zeroize by
  `package`, as a registry version only. The workspace may have no
  `[patch]`/`[replace]`, and the lock's closure of the two must be exactly
  `MCE_CLOSURE` (11 name@version pairs), all from crates.io.
  - **Deviation from the plan:** P16 reads Cargo.lock instead of running
    `cargo metadata`. The check-pins fixtures run on partial trees that
    cargo cannot resolve, and every gate builds `--locked`, so the lock is
    the resolution. The lock does not record edge kinds, so `MCE_CLOSURE`
    also holds generic-array's build dependency and cpufeatures' libc.
  - Every refusal branch has its own fixture (8 cases).
- **P12 (Major):** P12 now fails when the Makefile has no `verus_crates :=`
  list, and when a listed crate exists without `src/`. Following P11's
  precedent, a tree without the crate at all is skipped; the Verus gate
  fails on a listed crate that is gone.
- **Verus scanner (Major):** `tools/verus_trusted.py` missed these, and now
  catches each, all inside `verus!`:
  - `assume_specification`, which is item syntax (vstd itself writes
    `pub assume_specification<T>[ .. ]`), not an attribute;
  - path-qualified `admit(` and `assume(`, and the expanded `assume_(`;
  - trusted constructs hidden behind a char literal `'"'` or a raw string,
    which desynced the comment and string stripper.

  Five P12 fixtures cover these. Each is red under the previous scanner
  and green under the new one.
- **ct-shape containment (Major):** the identity check now also fails in
  two cases.
  - Any `mce460896::` function in a PD lies outside the root's closure
    (other than the shim or its carrier). This covers `keypair`,
    `stages::*` and `pk_from_sk`.
  - A function outside the closure branches to an mce460896 function inside
    it other than the root. An example is a direct `decaps_core` call, which
    skips the scrub.

  Branches into the closure's shared core helpers are allowed: they have
  callers of their own (`copy_from_slice`, from msgs and the TLS setup).
  The synthetic ELFs now link only their own root. Four fixtures cover the
  check, and the live PDs pass.
- **`mce-fresh-draw` (Major):** the selftest case required by plan C7 was
  missing; it is added.
  - The mutated shim reuses the first half of the first rejected draw for
    one attempt.
  - The first version reused the half for good. In mksecrets' tests that
    never accepted, and the run hung; the selftest has no timeout.
- **mce460896 tests never ran (Critical; found by the `mce-fresh-draw`
  red-proof, missed by all three experts):** the plan's `host_crates gains
  mce460896 and ct-harness` was not done. So `make unit` and `make lint`
  never ran mce460896's 17 tests, including the liboqs and cmr equivalence
  vectors and I8. The first `mce-fresh-draw` run stayed green for that
  reason.
  - mce460896 is now in `host_crates`. Its tests pass, and clippy is clean.
  - ct-harness is its own workspace and cannot join `host_crates`, so `ct`
    now runs its clippy next to its unit tests.
  - The manifest gains `UNIT-MCE460896 5`, plus `UNIT-RNG 5`,
    `UNIT-STACK 2` and `UNIT-VECTORS 5` (integration-test binaries are
    counted by name). `UNIT-TESTS` is 733 and `LINT-CRATES` 21.
  - The M4 equivalence claims (sections M1 result and M3a) rest on manual
    runs of these tests, not on `make check`, until this commit.
- **`verus-required` (Major, R29):** the old mutant (removing `verus! {`)
  did not compile, contrary to its comment. It now moves `below_window`
  below the block as plain Rust without its ensures.
- **test_package (Major, RT11):** the scratch dir and the `ct_stubs`
  globals are now released in `finally` even when the setup raises, and
  `ct_stubs` undoes a partial setup.
- **Accepted (Minor, R39):** mksecrets' KAT shared key is not zeroised.
  mksecrets wipes none of its secrets, including the long-term McEliece
  secret key it writes, so wiping only the KAT key would add nothing. This
  is a residual of the host tool.

## Phase 3 round 1 fixes

The findings are in `secureos-m4-verus-mceliece-code-review.md`. These
record what changed in the plan's mechanisms.

- **Verus scanner (F1/F2, S1–S6, T4):**
  - **Required functions:** named `Type::fn`, or `*::fn` for every fn of
    that name in the crate (`*::decode`, `*::parse`, `*::emit`). Each
    definition must be inside `verus!` with an ensures, and a definition
    outside fails.
  - **Ensures count:** `VERUS-ENSURES-<CRATE>` now counts every definition.
    The old count took the max per name. wg-wire goes from 47 to 57, msgs
    from 43 to 67 and rosenpass-wire from 23 to 35.
  - **Trusted constructs:** each is bound to its item and compared as a
    multiset by one function, which P12 and the gate share. The scan covers
    the whole file and treats every `verus!` delimiter the same.
  - **What counts as trusted:** the scan now also flags:
    - `cfg`/`cfg!` naming a `verus_*` cfg, except on a `use` item;
    - `#[path]` and `include!`;
    - `assume_new(`/`assume_new_fallback(`;
    - `verus::internal`;
    - `external_trait_specification`, `external_trait_extension` and
      `assume_termination`.

    The last three come from enumerating `verifier::` attributes in the
    pinned vstd and verus_builtin sources (S6).
  - **Empty crates:** a crate with no `verus!` block fails.
- **C10 (S4):** ct-shape's identity check refuses McEliece symbols in any
  `pd-*.elf` other than the two roots'. It reads the search path, so
  package gets it too.
- **C8 stack measurement (F5, S10):**
  - **The probe:** `cpu::StackProbe` paints pq's and pqkey's free stack at
    init and prints the high-water mark whenever it deepens. The
    integration case `stack headroom (C8)` requires 16 KiB free at the
    system file's `stack_size`.
  - **First measurement:** pqkey peaked at 113,760 B and pq at 119,152 B of
    131,072. pq had only 11.9 KB free: `encaps_attempt` scrubbed decaps'
    96 KiB.
  - **The fix:** `SCRUB_DEPTH_ENCAPS` is 40 KiB (host peak 20 KiB plus the
    16 KiB margin, asserted by `mce_stack.rs`), with its own
    `scrub_stack_encaps`. pqkey-core no longer copies the 13.6 KB secret key
    onto the stack (F6/S9).
  - **Second measurement:** with these, after the full rp gate boot, pq
    peaks at 61,808 B (69,264 B free) and pqkey at 100,096 B (30,976 B
    free). The `.system` comments carry these figures.
  - **Probe cost:** the first probe scanned the stack byte by byte after
    every pq pass. Under load that cost pq the budget it needed, and
    `rp spoof` failed. The probe now scans a word at a time, and pq reports
    only on its 1 Hz timer.
- **Residue forms (F4/T2):** the plan's per-form cases are consolidated
  into one, `mce-residue-forms`. It strips every local wipe, both scrubs and
  the shim's `Zeroizing`, and requires a `RESIDUE-HIT` for all ten forms.
  This proves eight needle derivations can match in one valgrind run
  instead of ten. Which wipe protects which form stays covered by the scrub
  and by `mce-residue-rand`/`-scrub`.
  - **bm and g never hit, even with every wipe and both scrubs removed**
    (measured). The fft right after BM converts the locator in place and
    reuses BM's frame. A copy for the fft made `g` vanish too: the layout
    moved, and LLVM elided the copy. So no mutation exposes them.
  - **Their needles are the implementation's own outputs:**
    `stages::bm`'s, asserted equal to the decoder's locator, and the sk's g
    bytes. They stay in the scan as tripwires, without a red-proof
    (residual).
- **Selftest:**
  - **`ct-c1-barrier`:** added (F3/T1).
  - **`ct-harness-unit`:** added (T12).
  - **Kani needles:** failure-only (T3).
  - **Regex needles:** a needle may now be a regex; `ct-barrier` and
    `ct-c1-barrier` name the file (T7).
  - **Timeout:** each case's make runs in its own process group, killed
    with SIGKILL after 4 h (T11).
- **check-pins:**
  - **P13:** fixtures reach `tools/` (T5).
  - **P16:**
    - refuses features and default features on sha3 and zeroize;
    - refuses `.cargo/config.toml` `[patch]`/`[source]` (S7).
  - **P9:** in mce460896, P9 covers every type but `RngError` (F10).
- **C9 record:** the record's counts must equal `tests/manifest.txt`'s
  (T13).
  - The record fixtures list their keys explicitly (T6).
  - `make ct` runs the harness's clippy and tests before ct-gate, so a
    failure there cannot leave a fresh record (F7).
- **package (S8):** package binds the shape baseline as well.
- **Unit keys (F11/T9):** the mce460896 integration tests are
  `mce_{rng,stack,vectors}.rs`. The stack probe's child is `#[ignore]`d, so
  UNIT-MCE-STACK is 1.
- **Accepted, with residuals:**
  - **T8 (ct-identity has no allow-side run):** the allow side is the
    gate's own green run in `make check`. Cost to add: a second full PD
    build per selftest. The worst case is a case that is red for a reason
    other than the opt-level change; the needle names the identity diff,
    which bounds this.
  - **T10 (verus-gate's own-summary clause is not red-proved):** no
    mutation outside the gate makes Verus exit 0 without the crate's
    summary. The VERUS-<CRATE> manifest count is the backstop.
  - **S11 (macro pairing by version only):** comparing the crates.io
    `verus_builtin_macros`/`vstd` sources with the tarball's needs an image
    rebuild. It is recorded for M5's reproducible-build work, where the
    image is rebuilt anyway; R-M3 already accepts unaudited macro output.
- **Selftest speed:** every case used to copy the repo, without `build/`
  or `target/`, into a fresh temp dir and build cold. The cases now share
  one warm tree at `build/selftest-work/tree`. `sync_tree` restores each
  file by content: a file the previous case mutated is rewritten with a
  fresh mtime, so cargo rebuilds it, and unchanged files keep theirs. Only
  `build/target*` and `build/ct/target*` survive between cases. A lock
  keeps two selftests off the tree. A unit case now takes 26–33 s.

## Phase 3 round 2 fixes

- **Verus scanner (S2/N1, S3, S6, S12/N3, S13/N2):**
  - **cfg predicates:** a predicate in a verified crate may name only
    `test` and `kani` (with `not`/`all`/`any`). The one exemption is an
    outer `#[cfg(verus_keep_ghost)]` directly on a `use vstd::`,
    `verus_builtin::` or `verus_builtin_macros::` item. Inner attributes are
    never exempt. `cfg!` is read with any delimiter.
  - **Builtins that assume:** `admit`, `assume_`, `assume_new` and
    `assume_new_fallback` are flagged as identifiers wherever they occur,
    so aliases and macro-ident passing count. `assume(` is flagged
    everywhere, except Kani's `kani::assume(` outside verus!, which
    restores round 1's boundary. A `mod kani`/`as kani` is flagged.
  - **Attributes:** a TRUSTED name anywhere in an attribute that names
    `verifier` or `verus_verify` counts. The pinned
    `verus_builtin_macros` has `#[verus_verify(external_body)]`, which was
    checked in the registry. So does a `verifier::$meta` in a macro, and
    a `path =` anywhere in an attribute (`cfg_attr` included).
  - **What cargo compiles:** a verified crate may not have `[lib] path`,
    a build script, or a target path outside its source dirs.
  - **Counting:** constructs count per occurrence, so two on one line are
    two. They bind to the item they decorate (`impl <Type>` for an impl,
    through `const fn`), or to the fn whose body encloses the call.
  - **Fixtures:** 16 new P12 deny fixtures and one allow fixture. Each
    deny fixture is red under the round 1 scanner.
- **C8 (T15, T16, S14):** the probe reports to the word, not the byte (S14).
  - **Two new refusals in `stack_headroom_case`:**
    - a mark shallower than the PD's own scrub (the probe is not
      measuring);
    - a garbled high-water line.
  - **Fixtures:** `tests/tools/test_stack_headroom.py` (8 fixtures, in
    `make pins`) checks each clause, the boundary (16,384 B free passes,
    16,383 B fails) and the measured figures.
- **C10 (S16/N5, T20, T21):**
  - **Which PDs are checked:** ct-shape takes them from the system file's
    `program_image` list, not a glob, and refuses a listed image missing
    from the search path. package passes its `--system`.
  - **Fixtures:** the CLI is shown refusing a third PD with McEliece
    symbols, and an aliased memcpy is shown to be a stop.
  - **Residual:** McEliece code inlined into another PD carries no
    `mce460896::` symbol, and stays outside this check.
- **P16 (S7/N6/T25):** P16 now also reads the legacy `.cargo/config`, and
  refuses mce460896's own `[features]`. Every root workspace member's
  sha3/zeroize must be featureless, since features unify (the tool
  workspaces build on their own). Every closure package needs a checksum.
- **Selftest:**
  - **Proof lock (T26):** the Kani/Verus lock is one file per container
    (`/tmp/secureos-proof.lock`, the container's own `/tmp`), not one per
    checkout. A second container would take its own lock (T32: only one
    container runs proofs on a host). kani-gate.sh's comment still says
    "machine"; it is corrected together with moving the lock out of the
    hashed script, since any edit there invalidates every Kani cache. Before, the warm
    tree and the real tree would each take their own.
  - **Timeouts (T19):** a timed-out case fails whatever its output held.
  - **The warm tree (T17):** it now lives outside the checkout (no parent
    `.cargo/config.toml`), and bolero's `crashes/` dirs are cleared each
    case. What survives between cases: every SKIP-named dir (`target/`
    at any depth, `build/target*`, `build/ct/target*`).
  - **`sync_tree` fixtures (T18):** six fixtures, in
    `test_check_selftest.py`. A restored file is newer than the sync start
    (red with `copy2`), an unchanged one keeps its mtime, and adds,
    deletes, modes and type changes are synced.
  - **New cases:**
    - `mce-residue-encaps-scrub` and `mce-residue-encaps-depth` (S15) show
      the encaps scrub and its depth matter on their own;
    - `mce-residue-bm` (T14) keeps BM's output alive with `black_box`
      against the fft's in-place rewrite;
    - `ct-harness-lint` (T12).
- **Fixtures (T22, T23, T24, F11):**
  - **P9:** a P9 case shows the `RngError` exception is by exact name.
  - **C9 record:** a case for a manifest missing a key the record needs.
  - **P15:** a deny fixture in another tool.
  - **Unit keys:** two crates' test binaries with one stem now report
    `UNIT-KEY-COLLISION-<stem>`, which the manifest refuses.
- **Integration (`rp conf share`):** the second test-timing failure of the
  same class. Its 2/s InitHello flood had not sent anything when the faster
  exchange ended, so both floods are now waited for before the client
  starts.
- **Residual:** `g`'s needle stays without a red-proof. Its stored forms
  live in `syndrome`'s frame and in the caller's sk, and nothing short of
  planting the sk bytes, which would only be circular, exposes them.
- **Selftest: one boot per test-layer case.** Every test-layer case used
  to run all seven integration boots, about 35 minutes each.
  - **The filter:** `SECUREOS_IT_BOOTS` (`make test it_boots=<boot>`) runs
    only the named boots. A filtered run prints
    `INTEGRATION-CASES-PARTIAL`, which `make test`'s grep does not take,
    so it can never pass the manifest.
  - **The assignments:** each case gets the boot whose function raises its
    needle (traced in run.py): wireguard for seven cases, cookie boot a for
    two, rp gate boot for one. `integration-count` stays unfiltered,
    because it needs the full count.
  - **Unknown names:** an unknown boot name fails the run.
- **The first full selftest on the warm tree** (code at `e2d7c97`) took
  8,631 s for 100 cases. 90 passed and 8 failed, each for a reason in the
  selftest or the gate rather than in the property it proves:
  - **`verus-trusted`:** the needle predated round 1's per-item message.
  - **`ct-canary`, `ct-early-exit` and `ct-declassify-width`:** these mutate
    the harness, and round 1 (F7) had moved the harness clippy before
    ct-gate, so clippy refused them first.
    - ct-gate runs first again. A clippy or test failure after it removes
      the pass record it wrote, which keeps F7's guarantee, and says so.
    - `ct-harness-lint`'s needle is that message, its echo split so that
      make's printed recipe cannot match it.
  - **`c2-hello-burst` (stale since M3b):** M3b shrank `RP_IN_FLIGHT`, so
    the mutated burst (15) no longer broke the C2 assertion. It went
    unseen because an earlier crate's test failure stopped `cargo test`
    before pqkey-core. Two fixes:
    - `make unit` runs `--no-fail-fast`;
    - the mutation sits at the boundary (21: 31 > 21 + 10 is false). Much
      above that, ingress-core's arrays stop compiling.
  - **`integration-residue`, `integration-expiry-residue` and
    `integration-count`:** on `ff55c04` they pass. Re-run alone, with the
    boot filter, `integration-residue` took 137 s.

## Phase 3 round 3 fixes

Round 3 re-found the class the scanner kept growing for (S2/N1, S3/S6/N3,
then S19): every fix to the source-text scan met a new spelling. The class
is closed at its primitive instead, per the R42 convergence rule.

- **Verus refuses what it trusted (S2, S3, S6, S19 for four crates):**
  - **The flag:** a crate with no entry in `policy/verus-trusted.toml`
    (wg-wire, rosenpass-wire, ring, wire) is verified with
    `--fwd-verus-args-to roots -- --no-cheating`. Verus itself then refuses
    assume, admit, external_body and assume_specification in what it
    compiled, whatever cfg, macro or literal spelled them. vstd is not a
    root, since it assumes internally.
  - **Order in the gate:** the gate runs Verus and the source checks both,
    and fails if either fails, so each has its own red-proof
    (`verus-no-cheating`, needle "external_body/assume_specification not
    allowed with --no-cheating"; `verus-trusted` and the required-function
    cases for the scan).
  - **Pinned:** `VERUS-NO-CHEATING-CRATES 4`.
  - **msgs:** it keeps its one allowlisted external_body (`chunk_ref`,
    Kani-checked), so it is verified without the flag and relies on the
    scan. That is the residual.
- **The scan, hardened for msgs and for P12 (S2/N1, S3/N3, S19, S20,
  S21, S26, T31):**
  - **cfg:** every `cfg`/`cfg_attr` predicate in an attribute is checked
    at any depth (cfg_attr can produce a cfg), and an unbalanced one is
    refused.
  - **Attributes:** a macro-metavariable attribute (`#[$a]`) is flagged.
  - **TRUSTED names:** every TRUSTED name but `external` is flagged as an
    identifier anywhere (macro arguments, `use` aliases); `external`
    inside any attribute. `verus_verify` outside an attribute is flagged.
  - **The lexer:**
    - nests block comments and reads `c`/`cr` strings;
    - marks an unterminated literal or comment, which is refused (rustc
      refuses it too, so it can only be there to hide code);
    - matches `verus !` with a space.
  - **The exempt `#[cfg(verus_keep_ghost)] use`:** it must import only
    vstd `lemma_*`/`group_*` names, with no `as` and no glob.
  - **Item binding:** an attribute's item skips later attributes and
    qualifies methods.
  - **Target paths:** they are resolved before the source-dir check.
  - **Verus crates as dependencies:** only verus_crates may depend on
    Verus's crates (lock).
  - **Fixtures:** 15 new P12 deny fixtures (+1 allow). Each is red under
    `32a016c`, except the `verus !` allow case, which `32a016c` wrongly
    refused.
- **The same lexer everywhere (R48, the owner's "横展開"):** P9, P10, P11,
  P13 and P14 used two weaker comment strippers. In both, a `"//"` inside a
  string cut the rest of the line, so a derive, a `from_bytes(*`, a cookie
  compare, a cmr `use` or an `unsafe` after a URL string was hidden. They
  now use the scanner's lexer and report unterminated literals. P7, P8 and
  P15 read raw lines (comments included, and asm strings for P15) and
  were left so. Six fixtures, red under `32a016c`.
- **C10 (S22/F-R3-2, F-R3-3, T30):**
  - **Parsing:** ct-shape and run.py read the system file as XML (any
    quoting or spacing), as microkit and laws do.
  - **The Makefile:** the ct-shape target passes `--system $(system)`.
  - **Fixtures:** single quotes, an unreadable file, no program_image, and
    a missing root.
- **C9 record (T27, S23, F-R3-1):** ct-gate writes `pending-<key>`, and
  `make ct`'s last line promotes it to `pass-<key>`, the only name package
  accepts, after the harness clippy and tests. A failed or interrupted
  `make ct` leaves no pass record. Promotion needs exactly one pending
  record (three fixtures).
- **C8 (T28, S25):**
  - every high-water line must be attributed to pq or pqkey (a garbled
    prefix is refused);
  - pq's floor and the floor tie are fixtured, and the unused parameters
    are gone.
- **P16 (T25, N6, S24):**
  - **Member tables:** every dependency table of every member is read
    (target, dev and build included), along with `[features]` values that
    enable sha3/zeroize features.
  - **Config:** `rustflags` in the cargo config is refused.
  - **Missing members:** a member without a Cargo.toml is refused.
  - **Fixtures:** the bare-version, target-table, features, workspace-table
    and rustflags paths. The ones that did not change behaviour are
    red-proved by removing their branch.
- **Selftest and counts:**
  - **T19:** the timeout rule and the crashes clearing have fixtures, each
    red when removed.
  - **F11/T29:** the unit counts moved from the Makefile awk to
    `tools/unit-counts`. It produces the same output on the real log, and
    an unreadable owner is refused (4 fixtures).
  - **T24:** P15 has a deny fixture in a second tool.
- **The C8 probe broke the integration run (found by the round 3 make
  check):**
  - **Cause:** pq printed its high-water line on the console while `audit`
    printed. PD debug output goes out a character per syscall, so the two
    interleaved, and the awaited `audit: src=pq RpPskExported` line no
    longer matched (the wireguard prelude timed out). The two
    `prelude: timed out` failures of the first warm-tree selftest had the
    same cause.
  - **pq:** it now reports through audit: a new value-carrying event,
    `StackHighWater { bytes }` (code 0x0052, never coalesced), printed by
    `audit` alone.
  - **pqkey:** it has no audit ring, so it prints its mark once, after the
    boot KAT, as it already printed "secrets valid".
  - **The size check:** the probe's size is checked by the PDs'
    `STACK_SIZE` constants against the system file.
  - **Measured:** pq 61,696 B (69,376 B free); pqkey at boot 99,408 B
    (31,664 B free).
  - **Residual:** pqkey's later decapsulations, on pq's calls, ran 688 B
    deeper in the previous measurement (100,096 B). The integration check
    reads the boot mark, and the 16 KiB minimum covers that margin.

## Phase 3 round 4 fixes, and where the source scan stops

- **The scan (F-R4-1, N1, N2, N3, N4):**
  - **Spaced tokens:** `#`, `!` and `[` may be spaced or comment-separated
    (`# [`, `#/**/[`, `cfg ! (..)`, `include ! (..)`).
  - **`cfg`, `cfg_attr` and `include` outside an attribute:** flagged as
    identifiers (aliases, macro idents), except an allowed `cfg!(..)`.
  - **Build-environment reads:** `option_env!`/`env!` are refused outside
    test-only files (a file a crate root declares only as
    `#[cfg(test)] mod x;`; an inline test module is still refused). Cargo sets `CARGO_PRIMARY_PACKAGE` under `-p`, not
    for a PD's dependency, so such a read splits the builds as a cfg does.
  - **The lexer:** it takes `_` in `\u{..}` and drops a shebang line as
    rustc does.
  - **Macro definitions:** a trusted construct inside one is refused, since
    it is counted once but expands per invocation.
  - **Allowlist counts:** an entry's count must be an integer >= 1.
  - **The `--no-cheating` decision:** the gate takes it from
    `verus_trusted.py allowed`, the same parse.
  - **Fixtures:** 14: 13 deny fixtures, each red under `0f8f0b7`, and 1
    allow fixture, red with the cfg! exclusion removed. Round 5 adds a
    spaced `cfg ! (test)` allow case, which pins the spaced macro form.
- **P16 (T34, F-R4-3, N5, T35):** a `workspace = true` sha3/zeroize that
  adds features is refused. `[features]` values are matched against the
  member's keys that resolve to sha3/zeroize (renamed ones included).
  Fixtures for target rustflags and a missing member are added.
- **C8 (F-R4-2, T36, T39):** a StackHighWater mark is counted reported
  only once audit delivered it, as `CostHighWater` does; a lost one is
  offered again (`StackProbe::offer`, host-tested). The event is fixtured
  through the Coalescer, and so is the STACK_SIZE mismatch.
- **Tests (T37, T38, T41):**
  - **promote:** its fixtures check the refusal message, the absence of a
    pass record, and that the promoted record is one `check_record`
    accepts. A fixture pins promote as `make ct`'s last line.
  - **run_make:** its timeout conversion is fixtured with a stub make.
  - **ct-shape:** a malformed system file and a path-less program_image
    are fixtured.
- **Where the source scan stops (accepted, R42 convergence):**
  - **What the mechanical gate guarantees:**
    - For the four `--no-cheating` crates, Verus refuses
      assume/admit/external_body/assume_specification in what it
      compiled.
    - For all five crates, the scan refuses every trusted construct,
      cfg split and build-environment read in each spelling the five
      review rounds found: aliases of `cfg`/`include`/`env`/`option_env`
      included, and a trusted construct inside a macro definition or a
      macro's arguments.
  - **What it does not claim:** completeness against source deliberately
    written to evade a text scan. Each round found a new spelling (13 by
    round 4: cfg_attr nesting, macro idents, five lexer desyncs, spaced
    tokens, env reads, macro-body expansion, ...). Rust's macros, cfgs and
    build environment make that class open-ended. A committer able to write
    such code can equally edit `tools/verus_trusted.py`, the policies or
    the manifest, which the gate cannot defend against either.
  - **Who covers it:** review of every diff to a verified crate. That
    diff is small and named by `verus_crates`.
  - **Worst case:**
    - In msgs, the decoders' proofs could rest on an unproved
      `ensures`.
    - In any crate, an evading cfg or env split could ship a body
      Verus never saw.
    - For a cfg split, Kani, unit and bolero build the same side Verus
      saw. For a split on `CARGO_PRIMARY_PACKAGE`, they build it as the
      primary package too, so only the PD build, and with it the
      integration run, exercises the shipped side.
  - **Likelihood:** low for honest or careless edits, which the scan
    catches. The rest needs intent.
  - **Cost to close:** compare the compiled MIR of the verified build
    with the shipped one. That is a project of its own; it is recorded for
    M5's reproducible-build work, which builds both.
- **Round 5 (T34 continuing, T42–T45):**
  - **P16:** it resolves an inherited `workspace = true` key to the package
    its workspace declaration names, so a renamed inherited sha3 that adds
    features is refused.
  - **Selftest fixtures:**
    - the spaced `cfg ! (test)` allow fixture pins CFG_MACRO's spacing (a
      regression would flag it as a stray identifier);
    - stub_make checks that make's own child dies with the group, and the
      short timeout applies to the never-ending case only;
    - the parse-failure needle names expat's "not well-formed".
- **Round 5 (F-R5-1 to F-R5-8, R5-S1, R5-S2):**
  - **The scan:**
    - `env`/`option_env` are identifiers refused outside test-only
      files, aliases included;
    - a shebang line is refused outright in a verified crate (rustc's
      rule for it nests comments and skips doc comments, which is not
      worth mirroring);
    - `\u{..}` takes any number of `_`;
    - a test-only file must have no other `mod` declaration;
    - raw macro names count as macro definitions;
    - a trusted construct in any macro invocation other than `verus!` is
      refused.
  - **P16:** it accepts an inherited dependency restating
    `default-features = false`.
  - **Fixtures:** 7 P12/P16 cases, each red under `ce76726`. The one allow
    case was wrongly refused there.
- **Round 6 (F-R6-1, F-R6-2, Minor):** the test-only check counts raw-named
  `mod r#x;` declarations. A macro defined as, or an item imported as,
  `verus` is refused, like KANI_SHADOW for `kani`. Three fixtures, each red
  under `0b68f4f`.
- **A race in the raw-frames flood check (pre-existing since M2, surfaced
  at `0b68f4f`):** `flood` waited for `total=<last> ` and then counted lines
  in full (`lost=..`). Audit prints a character at a time, so the last line
  could be counted before its `lost=` arrived. pq's new StackHighWater
  record, printed at that moment, made the window wider. The wait now takes
  the whole line. No other wait in run.py is followed by such a recount.
- **Observed once, on z1mn only:** `rp latency` ("no WireGuard handshake
  within 19 s under a Rosenpass flood") failed inside the unfiltered
  `integration-count` run at `3ebe77a`.
  - **Elsewhere:** the same case passed in z1mn's full selftest at
    `ce76726`, and in gx10's make check and `integration-count` at
    `3ebe77a`.
  - **Likely cause:** z1mn runs QEMU's TCG on Apple Silicon under Docker
    Desktop, so its timing differs from gx10's. The case is a TCG timing
    budget from M3b.
  - **Residual:** if it recurs on either machine it is a test defect to
    find, not to widen.
