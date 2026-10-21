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
