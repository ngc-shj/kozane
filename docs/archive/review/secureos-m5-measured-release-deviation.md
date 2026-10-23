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
