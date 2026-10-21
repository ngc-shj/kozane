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
