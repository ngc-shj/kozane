# Coding Deviation Log: secureos-m5-measured-release

## Slice 1 — dev image (C1) and the proof lock (C2)

### C1 deviations

- **U-Boot is not built in the image.** The image carries the
  sha256-pinned U-Boot 2025.01 source tarball (`/opt/u-boot`), and `make`
  builds U-Boot from it in slice 5 with the repo's config fragment and boot
  command. The plan put the build in the image. Building in the image would
  mean an image rebuild, and an owner transfer to z1mn, for every change to
  the C8 boot command.
- **Probe facts for slice 5** (throwaway container, 2026-10-23):
  - `qemu_arm64_defconfig` plus the fragment needs `CONFIG_TOOLS_KWBIMAGE`
    off. It selects `TOOLS_LIBCRYPTO`, and the image has no OpenSSL headers.
    With it off, U-Boot builds, and the compiled-in command and `hash
    sha256` run.
  - U-Boot embeds its build date, so `make uboot` must fix
    `SOURCE_DATE_EPOCH` for C3.
- **No new check-pins rule.** The one new download, the U-Boot tarball, is
  already covered by P1 (every download must be sha256-checked). swtpm,
  swtpm-tools and tpm2-tools come from the pinned Debian snapshot like
  every other package. So "a rule per new pin" has no new member.
- **Verus sources for C5 are not added yet.** The image already carries
  the `builtin`, `builtin_macros`, `state_machines_macros` and `vstd` source
  trees under `/opt/verus`. A probe against the registry crates shows
  content differences, not only in `Cargo.toml`:
  - `vstd`: 4 files differ.
  - `builtin_macros`: `attr_rewrite.rs` and `contrib/hooks.rs` differ, in
    code under `erase.keep()`.
  - The registry crates were published from Verus commits 919cc9d, 1b9b1d7,
    3204118 and 53ec5c4. The image's Verus is 426d8b0.

  How C5 resolves this (point the shipped build at the verified sources, or
  re-pin) is decided in slice 4, together with the `verus_syn` and
  `verus_prettyplease` sources.

### C2 deviations

- **The whole gate run holds the lock.** Each gate re-executes itself under
  `tools/proof-lock` at the top, so the lock is no longer taken only around
  the solver. The old in-script lock also covered verus-gate's
  `cargo clean -p` of the shared `build/target-verus`. Locking only the
  solver call would let one run clean another's target directory.
- **The green bound is 2 s, not the plan's 30 s.** While A holds the lock,
  a longer wait only makes "B did not start" more certain, so any bound is
  sound in the direction that matters. The red case, with the flock line
  removed from a copy of the script, keeps 30 s as its guard against a hang.
  The fixture is `tests/tools/test_proof_lock.py`, counted as
  `PROOF-LOCK-FIXTURES 2`.
- **Every Kani and Verus cache is invalidated once.** Both gate scripts are
  in their own cache keys. The plan accepted this because slice 6's
  `Cargo.lock` change invalidates them anyway.

## Slice 2 — audit console (C6) and release kernel (C7)

### C6 deviations

- **`hs` and `pq` report `KeyUnavailable` at boot, not on the first
  initiation.** Each one's first call to its key PD is the boot-seed call
  in `init`, so that is where an Unavailable `key`/`pqkey` shows. Without
  the seed neither can build its handshake state, so after the record each
  halts with `Halted` (`hs` reason 2, `pq` reason 4), as both did before
  on a refused seed. "Once per boot" therefore holds by construction. The
  mismatched-blob integration case waits for
  `audit: src=hs KeyUnavailable code=7` and then `Halted reason=2`, and
  reads both numbers from the Rust sources.
- **A fourth event code, `KeyStackHighWater { bytes }`.** The integration
  stack check needs `pqkey`'s mark after its boot KAT (M4 C8), and `pqkey`
  can no longer print it. `pqkey` now answers a new oracle label,
  `PQ_STACK_MARK`: no request words, a one-word reply, in `pq`'s row,
  charged to the bucket. `pq` fetches the mark once at init and audits it.
  The table change has two consequences:
  - `PQ_BOOT_CALLS` becomes 2.
  - check-selftest's `c2-hello-burst` mutation moves to the new boundary,
    20.

  The decapsulation is constant-time (C9), so its stack depth does not
  depend on the key.
- **Boot error codes.** `key-core` has two new `BootError` variants,
  `RndrUnavailable` and `SeedDerivation`. They cover the two `key` halts
  that had no `BootError`, so every boot failure has a stable code.
  The Unavailable reply label is `ERR_UNAVAILABLE (0x100) | code`, with
  no data and the reply zeroed. An unknown caller still gets
  `ERR_BAD_REQUEST`. `pqkey-core` mirrors the encoding without depending
  on `key-core`.
- **`Ready`'s lost count.** `audit` prints `Ready` as `<pd>: ready`, as
  the waits expect. If its record carries a nonzero lost count, the line is
  `<pd>: ready lost=N`, so the count is not dropped silently.
- **No source-pattern gate.** The forbidden pattern holds after this slice
  (grep: no match outside `crates/pds/hello`). It is not a check-pins rule.
  On a release kernel, rust-sel4's `debug_println!` compiles to nothing.
  The ELF check catches what matters for shipped images: a PD built
  against a printing kernel's headers.
- **The ELF check runs on release PDs, and checks the wrapper rust-sel4
  actually emits.** That symbol is
  `sel4_sys::syscalls::calls::seL4_DebugPutChar`. Every debug-built PD has
  it, `timer` included, because rust-sel4's panic handler prints through it
  whatever the PD's own code does. `make ct-shape` therefore builds release
  PDs (`$(MAKE) pds MICROKIT_CONFIG=release`) and checks those, which are
  also what ships. The identity and shape results are unchanged on them
  (CT-SHAPE-SYMBOLS 59). With no ELF arguments, as `tools/package` runs
  it, the check covers every PD the system file lists.
- **Laws.** The console rules (more than one console, off the PL011 page,
  a service pd owning a non-console device, not mapped `rw`) are L5
  findings, so each red fixture is a law violation with an exact message
  rather than a policy load error. Two cases are policy errors instead:
  `console = true` on a non-service owner, and `irqs` on a service pd.
  Two fixtures use existing rules with exact messages pinned:
  - the console mapped into another PD: L5, the device-ownership rule;
  - an irq on `audit`: L4.

  A seventh fixture, the console mapped `r`, covers the `rw` clause.
- **audit does not touch UARTCR.** It writes UARTDR after polling
  UARTFR.TXFF and relies on the UART as the loader and firmware left it.
  Reprogramming CR would mean disabling the UART first.

### C7 deviations

- **`make test` depends on `ct`.** A release package needs the C9 pass
  record. In `make check`, `ct` already ran earlier in the same make
  invocation, so it is not repeated. A standalone `make test` and the
  check-selftest integration cases need it: their warm tree keeps no
  record, and a harness built at another path hashes differently.
- **Per-config target dirs.** PDs build into `build/target-debug` and
  `build/target-release`, so the two configs never share objects. The ELFs
  still land in `build/` and are whatever config was built last. Every
  consumer builds `pds` in the same make invocation right before it, and
  the printing check refuses debug ELFs in a release package. The old
  `build/target` is no longer used.
- **Debug kernels and the waiver check.** Packaging refuses each
  `gen_config.h` clause on its own: `CONFIG_DEBUG_BUILD`,
  `CONFIG_PRINTING`, no `CONFIG_KERNEL_MCS 1`, not single-node. The
  waiver gate and the C9-record rule keep their "non-debug kernel"
  condition, so a debug kernel gets only the C7 refusal. The
  `stub_sc20` fixture mechanism is gone, because a release config now
  passes C7 on its own. check-selftest's `package-release` case is now
  `package-debug`: the default debug config is refused.

## Slice 4a — Verus macro/vstd pairing (C5)

### Result

The pairing failed on content, not just on the manifest. The plan said not
to pre-accept a content difference, and it is resolved structurally.

- **What differed.** crates.io's `vstd` 2026-10-04 was published from Verus
  919cc9d. Its `verus_builtin_macros` 2026-09-20 came from 3204118, and
  `verus_builtin`, `verus_syn`, `verus_prettyplease` and
  `verus_state_machines_macros` from older commits. None of them matches the
  image's Verus, 426d8b0:
  - four `vstd` files differ;
  - `builtin_macros/src/attr_rewrite.rs` and `contrib/hooks.rs` differ in
    closure-capture code under `erase.keep()`.

  So since M4, the shipped build compiled macro and library sources that
  were never the ones Verus verified with.
- **The fix.** The six crates are vendored under `third_party/verus/<name>`
  and patched in by the root `Cargo.toml`. Each vendored crate is
  crates.io's packaging (its normalised `Cargo.toml`, `.cargo_vcs_info.json`
  and README) with the 426d8b0 sources over it.
  - **Why not patch to `/opt/verus` directly:** those manifests inherit from
    the Verus source workspace, which excludes them, so cargo cannot
    resolve them.
  - **The image adds** `/opt/verus/syn` and `/opt/verus/prettyplease`, so
    all six image trees exist.
  - **Not vendored:** directories cargo never compiles for a dependency
    (`tests/`, `examples/`, `benches/`, `cargo-expand/`, `codegen/`). The
    policy lists them as `image_only`, and neither side's copy of them is
    compared. This keeps the vendored tree at 6.4 MB instead of 13 MB.
- **The gate.** `tools/verus-pairing` is a fail-closed gate run under
  `make pins`. Each Cargo.lock `vstd`/`verus_*` package must:
  - be a path source;
  - be patched to `third_party/verus/<name>` in the root `Cargo.toml`;
  - be listed in `policy/verus-pairing.toml`;
  - equal its image tree file by file (`VERUS-PAIRED 6`).

  The fixtures cover one changed byte, an extra file, a missing file, a
  registry source, a patch pointing elsewhere, an unlisted member, a
  missing tree on either side, a stale policy entry, and the `image_only`
  prefix semantics (`VERUS-PAIRING-FIXTURES 12`).
- **Verus is unchanged** with the vendored crates: 278 functions, four
  crates under `--no-cheating`, the same counts as M4.

### Deviations

- **check-pins P12 and P16 narrowed for the vendored crates.**
  - **P16:** it refused any workspace `[patch]`. It now permits exactly one
    shape: `[patch.crates-io]` entries for `vstd`/`verus_*`, each
    `{ path = "third_party/verus/<name>" }`. None of these is in
    mce460896's closure. Other keys, other paths, git sources, other
    registries and `[replace]` stay refused; four fixtures were added
    (`CHECK-PINS-FIXTURES 213`).
  - **P12:** the vendored Verus crates are no longer counted as workspace
    crates that depend on Verus.
- **Proof cache keys include the vendored sources.** Path packages outside
  the workspace have no Cargo.lock checksum, so `kani-gate.sh` and
  `verus-gate.sh` now hash their directories too. A change to a vendored
  macro therefore re-runs every proof.

## Slice 3 — reproducible build (C3)

### Result

`make repro` builds the release image twice and compares 13 artifacts
(`REPRO-ARTIFACTS 13`): `loader.img`, `report.txt` and the 11 PD ELFs.
The second build runs from a copy of the tree at another absolute path,
from a cold PD target directory, and all 13 are byte-identical. It takes
about 50 s on gx10 and is part of `make check`.

The selftest case `repro-path-leak` is red with the failure-only needle
`repro: pd-timer.elf differs between`. It appends a `#[used]` static
holding `env!("CARGO_MANIFEST_DIR")` to the timer PD.

### Deviations

- **Two sources of path dependence, two fixes.**
  1. **Source paths in panic locations.** The sel4-sys build-script
     `OUT_DIR` and the workspace sources are absolute in panic locations.
     Fixed by `--remap-path-prefix=$(CURDIR)=/secureos` in the PD
     `RUSTFLAGS`.
  2. **The ThinLTO symbol hash.** LLVM's local ThinLTO names promoted
     symbols (`….llvm.<hash>`) with a hash that depends on the absolute
     target directory, not on the source path. This was measured: two trees
     built into one target directory are identical, and one tree built into
     two target directories differs. The hash lands in `.strtab`, and from
     there one byte of `loader.img`; the loaded sections were identical.
     Fixed by a fixed PD target directory outside every tree:
     `pd_target ?= $(HOME)/.cache/secureos/pd-target-<config>`.
- **I3.1 holds with one stated input.** The published image does not
  depend on the tree's path, but it does depend on `pd_target`, which the
  Makefile fixes and which is the same in every dev container.
- **`codegen-units = 1` was tried and rejected.** It removes ThinLTO
  promotion and also made the image path-independent. But it re-inlines
  mce460896's encaps shim and its carrier, which breaks M4's C10 shape
  baseline (`expected one encaps shim ... found 0`). Taking it would have
  meant a new ct-shape carrier rule, a re-baseline of about 100
  justified function shapes, and a C9 re-run, all for a property the
  fixed target directory gives without touching codegen.
- **Trees share the PD target directory.** cargo's own lock on it
  serialises concurrent builds, and switching trees rebuilds the workspace
  crates (about 30 s). `make clean` removes it too.
- **The cross-machine comparison** (gx10 against z1mn, same image and
  commit) remains the manual end-of-milestone step the plan names.
