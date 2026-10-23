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
