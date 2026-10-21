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
