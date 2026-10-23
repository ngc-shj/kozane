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

## Slice 4b — verified-vs-shipped MIR gate (C4)

### Result

`make mir` compares the shipped and proof MIR of every member
(`MIR-CRATES 7`, about 30 s): verus_crates (wg-wire, rosenpass-wire, msgs,
ring, wire) plus the kani_crates some PD links (ingress-core, inner-core).
The two configurations' MIR is identical as rustc prints it, with no
normalisation.

check-selftest has four cases, each red with the failure-only needle
`mir-gate: wire: shipped MIR differs from the proof build`. Each puts one
split into wire:

- `mir-target-split`: a body under `cfg(target_os = "none")`;
- `mir-env-split`: one on `option_env!("CARGO_PRIMARY_PACKAGE")`;
- `mir-debug-split`: one on `cfg(debug_assertions)`;
- `mir-feature-split`: one on a feature that only ingress-core turns on.

The comparison and member derivation are fixtured too
(`MIR-GATE-FIXTURES 9`).

### Deviations

- **No normalisation.** The plan allowed stripping spans, scope comments
  and paths. The MIR came out byte-identical without it, so the gate
  compares exact text, which is strictly stronger.
- **How the MIR is captured.** `tools/mir-capture` is a `RUSTC_WRAPPER`.
  It re-runs the unit's exact rustc command with
  `-Zunpretty=mir -Zmir-opt-level=0`, so cargo's feature unification and
  environment are what is compared, not a reconstruction of them.
- **The proof configuration is the release profile with debug assertions
  on, one member per cargo invocation.**
  - **Why not the dev profile:** it differs from the PD build in panic
    strategy (unwind edges in every MIR body).
  - **Debug assertions on:** that is the value unit tests and Kani build
    with, so the `cfg(debug_assertions)` axis is still compared.
  - **One member per invocation:** members selected together would unify
    their features, which hid the feature split. Before each member is
    built it is `cargo clean`ed, because a member compiled earlier as
    another member's dependency is fresh and the wrapper would not see it.
- **Stated limit (RM5-3, unchanged).** The Verus-only cfgs and Verus's own
  rustc are not compared. The M4 source scan covers that axis.

## Slice 5 — measured boot under QEMU (C8)

### Result

- **U-Boot:** `make uboot` builds two variants from the image's pinned
  source, each with `SOURCE_DATE_EPOCH=0`: the shipped one and the measure
  one. Both come from `support/u-boot/boot.cmd`, through
  `tools/uboot-config`, so their measurement steps are the same lines. A
  `verify` step refuses a U-Boot whose final `.config` lost any line of the
  fragment.
- **The host model:** `tools/measure.py` is the one host model of the boot
  command. It holds the descriptor format, the I8.2 checks, the PCR 8 chain
  and the assembly. `tools/package` and run.py both import it
  (`MEASURE-FIXTURES 16`).
- **Packaging outputs:** `tools/package` now also writes `published.img`,
  `boot.desc`, `secrets.env`, `pq_secrets.env` and `pcr8`. It refuses to
  publish unless the assembly U-Boot will perform reproduces microkit's
  packaged image byte for byte (two new fixtures, `PACKAGE-FIXTURES 108`).
- **Integration:** a new boot, "measured boot", has five cases (U-Boot
  only, swtpm per boot):
  - PCR 8 equals the host computation;
  - a flipped image byte moves it;
  - a range moved onto the entry code moves it;
  - a 64-bit-wrapping range is refused on-device;
  - a range ending exactly at `image_len` is allowed.

  `INTEGRATION-CASES 38`.
- **Red-proofs** (check-selftest):
  - `measure-twin`: drop the descriptor extend, and the PCR 8 no longer
    matches the host twin.
  - `measure-wrap`: drop the 32-bit field check, and the wrapping range is
    copied.

### Deviations

- **The environment is compiled in only.** Not in the plan, and found
  while writing the fragment: `qemu_arm64_defconfig` can load an
  environment from storage, which would replace the compiled-in boot
  command and break VE6's premise. The fragment sets `ENV_IS_NOWHERE` and
  turns every other location off, and `verify` checks that this took.
  `BOOTDELAY=-2` boots without a key check.
- **hush semantics the boot command had to work around:**
  - `a || b; c` parses as `(a || b); c`, so `cmd || REFUSE` would always
    power off. The generator rewrites it as
    `if cmd; then true; else REFUSE; fi`.
  - `setexpr` prints hex without `0x`, and `test` reads a bare value as
    decimal, so every compare is written `0x$var`.
  - `setexpr` wraps at 64 bits and `test` compares signed. Every
    descriptor field must therefore fit in 32 bits before any compare;
    `measure-wrap` red-proves this check.
- **Refusal powers off rather than dropping to a prompt.** A prompt would
  be an input path on the console.
- **The packaged-image boot stays until slice 7.** The existing 33 cases
  still boot microkit's packaged image directly. They switch to the U-Boot
  path once the envelopes are sealed, so the boot path changes once, not
  twice. Until then the package carries both forms, and `check_images` is
  kept.
- **run.py `Console.wait_for` re-checks the text after EOF.** A guest that
  powers off right after its last line could otherwise be reported as
  "QEMU exited".

## Slice 6 — TPM session crate (C10) and envelope sealing (C11, host)

### Result

- **Two crates, split like wg-wire/wg-core.**
  - `tpm2-wire`: no dependencies, no cryptography. It holds the
    marshalling of the ten commands, the response parsers, the two public
    areas, and the `tpm` gate (allowlist, handle ownership, Done/Failed,
    cap). Kani therefore never compiles libcrux, and slice 7's `tpm` PD
    links no crypto.
  - `tpm2`: the primitives, the envelope with its offline sealing, and the
    client state machine.
- **Interop holds against swtpm 0.7.1.** The salted policy session
  (KDFe/KDFa, the command HMAC, the response HMAC, CFB) and the offline
  TPM2_Import duplicate work. tpm2-tools agrees on the SRK public, its Name
  and the policy digest (a trial session). Twelve interop tests
  (`UNIT-SWTPM-INTEROP 12`) run under `make unit`.
- **Host sealing:** `mksecrets seal --kind key|pq --blob F --srk-public F
  --pcr8 HEX --out F`.
  - The SRK public is the TPM2B_PUBLIC that `tpm2_readpublic -o` writes.
  - The blob is format-checked before it is sealed.
  - KEK, obfuscation seed and ECDH scalar come fresh from /dev/urandom on
    every call.
- **Envelope sizes.** The header is 448 bytes and the tag 16. The payload
  is the blob without its trailing zeros; the PD zero-fills the rest of
  its region.
  - `key`: capacity 3632 bytes, so a sealed blob carries at most 110
    peers (`KEY_MAX_PEERS`). The plaintext format allows 124 and the
    config allows 8.
  - `pqkey`: capacity 15920 bytes, against the blob's 13936.
  - Both fit; no MR grows. Every envelope is exactly its region's size,
    so the C8 range length equals the envelope length.
- **IPC size (C9).** The longest command is 365 bytes: Load with the
  256-byte cap on Import's outPrivate. Every parser refuses a response
  over 960 bytes. Both are const-asserted against `IPC_MSG_BYTES`.

### Deviations

- **The plan's PolicyAuthValue red-proof does not hold, and C9's "cannot
  unsalt" claim is wrong.**
  - **What was measured:** sealed under PolicyPCR alone, with the relay
    dropping the client's PolicyAuthValue and stripping `encrypt` from
    Unseal, swtpm still answers TPM_RC_BAD_AUTH (0x9A2) and returns no
    outData.
  - **Why:** the TPM checks a policy session's command HMAC whether or
    not the policy holds PolicyAuthValue (libtpms `SessionProcess.c`,
    `CheckAuthSession`, as in the TCG reference code). The key is the
    salted session key. PolicyAuthValue only appends the authValue, and
    the authValue is empty.
  - **So in S9's deny case,** the salt is what refuses a stripped
    `encrypt`, not the clause.
  - **The unsalt rewrite C9 says is impossible works.** A relay rewrites
    StartAuthSession into an unsalted session (session key empty),
    recomputes Unseal's HMAC with the empty key (the empty authValue adds
    nothing), strips `encrypt`, and reads the KEK. The client still
    refuses the response (its response HMAC is under its own salted key),
    so integrity holds.
  - **Reading:** this is an instance of RM5-5 (no confidentiality against
    an active A7), which the plan already accepts. It is not a new
    exposure, but C9's bullet "Cannot (with PolicyAuthValue) … unsalt it"
    must be struck. Closing it would need a secret the client holds
    before unsealing, and the boot media cannot provide one.
  - **The tests pin what is true:**
    - `stripping_encrypt_from_unseal_gets_a_bad_auth_and_no_outdata`;
    - `without_policy_auth_value_a_stripped_encrypt_still_fails_the_salted_session_hmac`,
      in place of the red-proof the plan asked for;
    - `rm5_5_a_relay_that_unsalts_the_session_reads_the_kek_and_the_client_refuses`.
  - **PolicyAuthValue stays,** because the policy is contracted (C11). It
    is defence in depth, not load-bearing. Dropping it is the owner's call
    (one command and one allowlist entry fewer).
  - **The deny response code is TPM_RC_BAD_AUTH, not TPM_RC_AUTH_FAIL.**
    The sealed object is noDA (next item).
- **Sealed object attributes: noDA only.** userWithAuth is clear (policy
  only). fixedTPM and fixedParent are clear, as TPM2_Import requires.
  sign, decrypt and encryptedDuplication are clear: a data object, outer
  wrapper only, symmetricAlg NULL. noDA is set because the authValue is
  empty, so lockout protects nothing, while every relay or tamper failure
  would count toward a lockout that denies service to both clients.
- **AAD is the whole 448-byte header,** not only magic/version/kind. It
  binds the pinned SRK, the policy and the duplicate as well. Envelope
  integers are little-endian like the other blobs; the TPM structures
  inside stay in TPM (big-endian) marshalling, so the client forwards them
  unchanged.
- **The envelope parser checks consistency, not the PCR value.** The pinned
  Name must equal Name(pinned public), and the header's policy must equal
  the object public's authPolicy. The parser cannot know PCR 8; the TPM
  enforces it.
- **Primitives and pins.** No in-repo primitive; CFB is written over the
  block cipher.
  - libcrux-sha2, libcrux-hmac and libcrux-p256 are `=0.0.9`.
    libcrux-ecdh was not taken: it depends on `rand`.
  - `aes` is `=0.8.4` with its `zeroize` feature (round keys wiped on
    drop), not 0.9. 0.8 reuses the locked generic-array, crypto-common and
    cpufeatures; the lock gains only aes, cipher 0.4.4 and inout 0.1.4.
  - Without `--cfg aes_armv8`, `aes` uses its fixsliced software AES on
    aarch64: constant-time, and the same code on the host as on the PD.
    The crate builds for `aarch64-sel4-microkit`.
  - `make audit`: clean. `make pins`: P16 holds. No member names
    zeroize/sha3 features; `aes`' feature is its own.
- **Reuse.** `ct_eq` and the AEAD come from wg-core through a dependency,
  not a third copy: `aead_seal`/`aead_open` with counter 0 (an all-zero
  nonce, safe under a fresh KEK) and `Key32` for the KEK.
- **KAT sources.** TPM 2.0 Part 1 has no numeric KDFa/KDFe examples, and
  tpm2-tss vectors were not used. The sources:
  - KDFa, KDFe and P-256 ECDH: pyca/cryptography 43.0.0 (KBKDFHMAC
    counter mode, ConcatKDFHash, SECP256R1 ECDH), an implementation
    independent of libcrux;
  - CFB: SP 800-38A F.3.13;
  - HMAC: RFC 4231 case 2;
  - SHA-256: the FIPS 180 "abc" vector.

  The decisive check is still swtpm accepting the session and the import.
- **swtpm harness.**
  - Unix sockets instead of TCP ports, so there is no port allocation and
    tests can run in parallel.
  - Flow tests pass `--terminate`, so a test process that dies without
    unwinding takes its swtpm with it. The two oracle tests do not,
    because tpm2-tools opens its own connections.
  - Every test kills its swtpm and removes its state directory on drop.
- **S2 as a replay.** Client B's recorded, valid Unseal response is
  handed to client A, and A's response HMAC refuses it. The flows run one
  after the other, because swtpm has three transient object slots.
- **Gate rules beyond the plan's list.**
  - CreatePrimary, StartAuthSession, Load and Unseal are allowed once per
    client per boot.
  - The tag must match the command: sessions only where the flow uses
    them.
  - CreatePrimary only under the owner hierarchy, and StartAuthSession
    only unbound.
  - Every session in an auth area must be the password session or one the
    client owns.
  - A returned handle of the wrong kind (not 0x80…/0x03…), or one already
    recorded, fails the client instead of being recorded.
  - `CAP_DIGEST` is 32 × 0xFF. The core counts as capped once it has
    issued the cap, whatever the device answers.
- **The client flushes after any failure.** It flushes every handle it got
  (object, session, SRK), so the other client finds free slots. Flush
  responses do not change the outcome.
- **check-pins.**
  - P9 and P10 now cover `crates/tpm2`.
  - P11 gains `TAG_FILES` (`crates/tpm2/src/client.rs`): an HMAC tag
    compared with `==`/`!=` is red. This is the plan's "ct_eq-only
    forbidden pattern". Three fixtures were added
    (`CHECK-PINS-FIXTURES 216`).
  - P11 was missing from the tool's docstring and is now described there.
- **Kani: 8 harnesses in `tpm2-wire`, not run here.**
  - Parsers: two harnesses (all parsers on 64 bytes; Unseal on 120).
  - Gate, deny: an arbitrary u32 command code off the allowlist;
    cross-client handles, PolicyAuthValue included; a finished client;
    Unseal after the cap.
  - Gate, allow: the owner's flow; a flushed handle number reused by the
    other client.

  They compile against a stub `kani` crate on a scratch copy; nothing
  more was checked. `KANI-TPM2-WIRE 8` needs the owner's run.
- **bolero.** `make bolero` ran the new target (9 seeds loaded, about 18M
  runs in 30 s, no crash). It stops at the "committed seed-*" check
  because the seeds are not committed yet (no commits in this slice).

### Mutations (scratch copy, each red)

| Control | Red test | Failure-only needle |
|---|---|---|
| I10.1 response HMAC check removed | `a_forged_unseal_response_hmac_is_refused_and_no_kek_is_used`; interop: flip, swap, unsalt | `left: Ok(())` / `cause: ResponseAttributes` |
| I10.2 SRK Name check removed | `an_srk_whose_name_differs…`; interop `envelope_sealed_to_a_foreign_tpm…` | `Failure { step: Import, cause: Response(Tpm(991)) }` |
| CFB decrypt dropped | `client_runs_the_whole_flow_and_opens_the_envelope` | `Open(Auth)` |
| S17 Load Name check removed | `a_load_with_a_substituted_name…` | `left: Ok(())` |
| Gate ownership check removed | four gate tests | `Ok(Forward { client: 0, cc: 374, … })` |
| PolicyAuthValue exempt from ownership | `the_other_clients_handles_are_refused_for_every_command` | `attempt 2` |
| PCR_Extend forwarded | `command_codes_off_the_allowlist…` | `cc 0x182` |
| Unseal after the cap | `the_cap_comes_once…` | `Ok(Forward { client: 0, cc: 350, … })` |
| Fixed KEK (S13, T13) | mksecrets `two_seals_of_one_blob_give_different_ciphertexts` | `identical ciphertexts from two seals` |
| No AAD, both sides | `every_flipped_byte_in_header_or_ciphertext…` | `byte 236 flipped and the envelope opened` |
| `==` on the tag | check-pins P11 fixture | `an HMAC tag compared with == or !=` |

### Left for slice 7

- **I10.3 (T2, T10).** The envelope-open path joins the residue harness
  and `policy/ct-shape.toml`. Both need the closure `key`/`pqkey` ship.
- **MIR gate.** `tpm2-wire` enters the MIR member set once a PD links it
  (kani_crates ∩ PD closure): `MIR-CRATES 8`.
- **IPC length.** The byte length of a command or response must travel
  outside the 120 message words (the label). If a length word is used
  instead, the 365-byte maximum leaves ample room.
- **run.py.** It should read `CAP_DIGEST` from the source (RT3) for the
  expected-then-capped PCR 8.

## Slice 7 — tpm PD (C9), sealed secrets in key/pqkey (C11), integration (C14)

### Result

- **`tpm` PD** (`crates/pds/tpm`): passive, priority 145 (`key` 140,
  `pqkey` 130), budget 1000/10000, stack 64 KiB. It maps only the TIS page
  (`tpm_mmio`, uncached, at 0xc000000), has no irq and is the PPC callee of
  `key` and `pqkey` alone. The `tpm2_wire` gate is its only decision point.
  The TIS driver works on locality 0: request the locality, commandReady,
  write the command in bursts, check Expect is clear, go, poll dataAvail,
  read the header, bound the size to 960 bytes, read the rest, check no
  data is left. Every exit then writes commandReady and releases the
  locality. All waits are bounded by CNTPCT: 5 s for the register
  handshakes, 60 s for a command. A timeout or protocol error answers
  RSP_DEVICE with the failing step and leaves the gate as it was. After
  both clients' Done/Failed it issues the gate's cap. There is no audit
  channel and no printing.
- **`tpm2-wire` is unchanged**, `gate.rs` included. The PD uses the gate's
  existing `command`/`response`/`finish`/`cap`/`state`.
- **`key`/`pqkey`.** The whole unseal runs in `init`
  (`tpm2::boot::unseal`): random client entropy through `cpu::fill_random`,
  the client flow over PPC, the envelope read in place from the read-only
  secrets MR, and the plaintext written into a PD-private `static`
  buffer. The KEK is wiped in `envelope::open_sealed` and the session
  secrets in the client, on every path. Done or Failed is sent whatever
  happened. Afterwards `key_core::validate` /
  `pqkey_core::Oracle::boot` run on the plaintext as before; on their
  failure the buffer is zeroized. The plaintext `SOSSECR1` format no longer
  reaches the PDs: it fails `Envelope::parse` (`EnvelopeInvalid`).
- **New `BootError` codes**, the same numbers in `key-core` and
  `pqkey-core` (`pqkey-core` skips 10), so one failure reads the same from
  `hs` and from `pq`:

  | code | variant | cause (`tpm2::boot::UnsealError`) |
  |---|---|---|
  | 11 | EnvelopeInvalid | the region is not an envelope of the PD's kind |
  | 12 | TpmUnavailable | `tpm` refused, failed (device), stayed Busy past 120 s, a TPM command other than Unseal failed, or Done was not acknowledged |
  | 13 | SrkMismatch | CreatePrimary's Name is not the pinned SRK's (I10.2) |
  | 14 | UnsealRefused | the TPM refused Unseal (PCR 8 policy) |
  | 15 | TpmResponseInvalid | a response failed the client's checks: format, Unseal HMAC/attributes/outData, Load Name (A7) |
  | 16 | EnvelopeOpen | the unsealed KEK did not open the envelope |

  An RNDR failure, or four unusable ECDH scalars in a row, maps to the
  existing `RndrUnavailable` (9).
- **IPC** (`layout::tpm`, one definition for both sides). Each message
  carries one TPM command or response, little-endian bytes in the message
  words, with `label = kind << 16 | byte length`. `MSG_BYTES` (960) is
  const-asserted equal to `tpm2_wire::IPC_MSG_BYTES` in the PD and in
  `tpm2::boot`. Requests are COMMAND, DONE and FAILED; replies are OK
  (length), REFUSED (refusal code), DEVICE (step), BUSY and BAD_REQUEST.
- **Laws.** New role `tpm`, and device mrs gain `tpm = true` (a policy
  error on any other owner role).
  - L5: one tpm mr, pinned at the TIS page (0xc000000/0x1000); a tpm pd
    owning any other device is refused.
  - L1: a tpm pd must be untainted, map nothing but its tpm mr, have
    channels only to key pds, and never have pp on its own end. A key pd
    may have at most one pp end, and only towards a tpm pd; a pp end
    towards anything else is the existing key-exemption finding. The
    key→tpm channel is no exemption: taint crosses it both ways and both
    ends must stay clean.
  - S14: the TIS page, like the console, does not seed taint, keyed to
    the pin.
  - L13: `["key", "tpm"]` in `[priority] below`.
  - Fixtures, each with exact messages: an allow; and as denies a tainted
    tpm, a tpm with a non-device mr, a second pp channel from key, a tpm
    channel to a non-key pd, a tpm calling out (pp on its own end), a tpm
    owning a non-TIS device, a tpm not above key, and a tpm mr off the TIS
    page (refused, and it seeds taint). The live system test passes.
- **Packaging** (`tools/package --srk-public`) runs in four steps:
  1. microkit with random, size-correct stand-ins; `check_images` is kept
     for this build: it differs from the published image only where the
     stand-ins land, which held zeros;
  2. the descriptor from those ranges, and PCR 8 from `tools/measure.py`;
  3. `mksecrets seal` for each blob, from a private copy in staging that
     is deleted as soon as both are sealed;
  4. microkit with the envelopes as prefill;
     `measure.assemble(published, desc, envelopes)` must equal that image
     byte for byte.

  OUT holds exactly `published.img`, `boot.desc`, `secrets.env`,
  `pq_secrets.env` and `pcr8`. No microkit run ever sees a blob, and no
  image with a secret in it is written. A real run (microkit, mksecrets
  seal, the assembly check) passed on this tree with only the C9-record
  binding stubbed, because `make ct` has not run here
  (`PACKAGE-FIXTURES 116`).
- **I10.3.**
  - **The closure:** `tpm2::envelope::open_sealed`, `#[inline(never)]`,
    is the envelope-open closure `key` and `pqkey` ship. It runs
    `open_core` (KEK → `Key32`, KEK wiped, AEAD open), then zeroes 8 KiB
    of stack below its frame (`OPEN_SCRUB_DEPTH`). libcrux's ChaCha20
    state, which holds the key, is otherwise left in the AEAD's dead
    frames.
  - **The residue harness:** two cases, `open.Key` and `open.Pq`. Each
    opens an envelope sealed in the harness under a known KEK, and the
    stack is scanned for KEK and plaintext windows (new forms `kek` and
    `plain`). The output and the KEK wipe are checked as well.
  - **Measured natively:** green with the scrub (open depth 8280 B,
    `RESIDUE-CASES 27`). On a scratch copy without the scrub,
    `RESIDUE-HIT kek case=open.Key windows=26` and `plain … windows=33`
    appear (both kinds), with the open's own depth 1392 B. The selftest
    case `tpm2-open-residue` uses that needle.
  - **C10:** `tools/ct-shape`'s roots are now a list:
    `pd-key.elf`/`pd-pqkey.elf` → `open_sealed`, next to the McEliece
    roots. Identity holds (20 functions, 6 stops in each ELF), the
    forbidden scan is clean, and 38 shape entries were added with
    justifications that claim no C9 CT run (`CT-SHAPE-SYMBOLS 99`; the
    McEliece closures stay at 39 + 20).

### Deviations

- **TIS locality 0 only: 0x1000, not 0x5000.** QEMU 9.0's tpm-tis-device
  region is `TPM_TIS_NUM_LOCALITIES << TPM_TIS_LOCALITY_SHIFT` = 0x5000
  (`hw/tpm/tpm_tis_sysbus.c`), at the virt platform bus base 0x0c000000.
  It is the first dynamic sysbus device, which matches U-Boot's
  `tpm_tis@0` probe. The PD uses locality 0 alone. Higher localities are
  more privilege on a real TPM (locality-restricted PCR resets and
  extends), so the MR, the laws pin and `layout::tpm::TIS_SIZE` cover
  the first page only.
  - **Verification:** no QEMU source is in the image and QEMU may not be
    run in this slice. The address and size come from QEMU's source as
    above, plus slice 5's probe. The sealed boots are the check: a wrong
    address means no TPM response, so every case fails with code 12.
- **One flow at a time (Busy), beyond the plan.** swtpm (libtpms) holds
  three transient objects, and the two flows need four at once (SRK and
  sealed object each). `key`'s and `pqkey`'s inits interleave at budget
  boundaries, so the PD answers RSP_BUSY to a Fresh client while the other
  client is Unsealing, and the client retries every 10 ms for at most
  120 s. This decision is in the PD, outside the gate, but it can only
  refuse more than the gate does; a started flow always runs to its end.
  The interop test
  `both_key_pds_unseal_concurrently_through_the_pd_model_and_pcr8_is_capped`
  runs both clients in threads through a model of the PD over swtpm. It
  saw one Busy, then both opened and PCR 8 was capped.
- **The IPC encoding is in `layout`, not `tpm2-wire`.** This leaves the
  Kani-verified crate byte-identical. The proof caches are invalidated
  anyway: `Cargo.lock` changed (new member `pd-tpm`; `tpm2` now depends
  on `layout`, and `key-core`, `pqkey-core`, `pd-key` and `pd-pqkey` on
  `tpm2`; no external package was added).
- **Both ends of a key→tpm channel have `notify=false`.** This is fewer
  capabilities than the hs→key pattern, whose callee end can notify.
- **ct-shape stops at `core::panicking::` itself.** libcrux's decrypt
  calls `core::panicking::panic_fmt` directly. Past it lies the target's
  panic handler (sel4-panicking in the PD, std in the harness), so
  identity could never hold. The McEliece closures are unchanged by the
  rule (39/12 and 20/10 as before). The forbidden scan now runs once per
  ELF over all its closures, so pd-pqkey's two `[[divide]]` entries are
  judged against both of its roots.
- **ct-harness lock.** The harness now depends on `tpm2`, `tpm2-wire` and
  `secret-blob`. wg-core's wg-wire pulls `vstd`, so the harness patches
  the six Verus crates to `third_party/verus` like the root workspace;
  without that it would resolve them from the registry. Its lock was
  seeded from the root lock, and every other package in it (117) has the
  root lock's name, version and source. A unification check showed no `zeroize`
  feature turned on.
- **Tampered descriptor = `image_len` cut short, not a moved range.**
  A moved range makes U-Boot copy the envelope elsewhere, so the PD finds
  zeros (code 11, not a PCR mismatch), and the copy may overwrite code.
  Cutting `image_len` to the end of the last range keeps both envelopes in
  place, and U-Boot accepts the descriptor. PCR 8 differs, so both PDs get
  `UnsealRefused` (14). This shows that the image tail past `image_len`
  is still run while unmeasured (it is in RAM from QEMU's load); the seal
  policy is what refuses it, not the measurement. A board loader reading
  `image_len` bytes from media would not run the tail.
- **The wrong-image byte** is the first byte of audit's
  `HandshakePskStale` text (found once, inside `image_len`, outside both
  ranges). No sealed-boot case prints it, so the boot is otherwise
  identical.
- **The cap read** needs no `--server` socket. A probe (host-side,
  swtpm 0.7.1, no QEMU) showed that swtpm refuses CMD_SET_DATAFD when
  started with `--server`, so QEMU's backend and a data socket cannot be
  combined. It also showed that swtpm keeps the TPM running once the data
  fd a killed QEMU held closes. A second control connection with
  CMD_SET_DATAFD (no CMD_INIT) then reads PCR 8. run.py's `read_pcr8`
  does exactly that after `kill_qemu`, before the swtpm is stopped.
  `CAP_DIGEST` and `DIGEST_LEN` are read from `crates/tpm2-wire` (RT3).
- **The A7 proxy is implemented, its feasibility unconfirmed.** It sits
  on the socket QEMU's tpm-emulator backend uses as its control channel.
  Control bytes pass through verbatim. The data fd QEMU sends with
  CMD_SET_DATAFD is swapped for one end of a socketpair whose other end
  swtpm receives. TPM frames are relayed and framed by their headers;
  the flip variant flips outData's first byte in each successful Unseal
  response.
  - **Host-side check:** a QEMU-style session (ctrl, SET_DATAFD,
    CMD_INIT, Startup, PCR_Extend, PCR_Read) went through the proxy
    unchanged, and the flip logic was exercised on a synthetic response.
  - **Still open:** whether QEMU's backend works through it is the F6-A
    question, which only a QEMU run answers. The case first requires the
    unmodified relay to pass a sealed boot (`hs`/`pq` ready, two Unseal
    responses seen). If that fails, the case is to be recorded here as
    blocked, with slice 6's relay tests covering the property.
- **Per-deployment TPMs.** run.py provisions swtpm states `tpm-a`,
  `tpm-c` and `tpm-foreign`. Each starts once with a data socket;
  tpm2-tools creates the SRK with the storage template and reads its
  TPM2B_PUBLIC; then swtpm is killed, so no volatile state is saved and
  U-Boot's TPM2_Startup finds a fresh TPM. Only `tpm2-00.permall` is kept
  (swtpm's `.lock` is removed). A second copy must yield the same SRK.
  Every boot copies `permall` into a fresh `swtpm-*` directory; `kill()`
  stops that swtpm and fails the run if the directory survives (T6).
  - **Mismatched-blob boot:** B's key blob with A's pq blob, sealed to
    TPM A.
  - **Foreign case:** A's blobs sealed to `tpm-foreign`, booted on TPM A.
  - **Host-side check:** provisioning, the state copy, the per-boot
    CMD_INIT and Startup, `read_pcr8`, and the proxy relay were checked
    against swtpm without QEMU (local scratch scripts under `build/s7probe/`,
    not committed).
- **Pre-existing, found here:** after `make repro`, a default-config
  release build fails. `crates/config/build.rs` takes its default path
  from `env!("CARGO_MANIFEST_DIR")` at compile time, and the cached
  build-script binary in `pd-target-release` came from the repro copy,
  which no longer exists. `make check` is unaffected: `ct-shape` runs
  before `repro`, and run.py sets SECUREOS_CONFIG. A manual
  `make ct-shape` after `make repro` fails until
  `~/.cache/secureos/pd-target-release/release/build/config` is removed;
  I removed it here. A fix (reading the variable at run time) is the
  owner's call.

### Selftest cases (not run here)

| Case | Mutation | Failure-only needle |
|---|---|---|
| `tpm2-open-residue` (ct) | `open_sealed` without its stack scrub | `RESIDUE-HIT kek case=open.` (seen on a scratch copy) |
| `sealed-pcr-unbound` (test, sealed boot) | seal policy PolicyAuthValue alone, client skips PolicyPCR | `FAIL [sealed boot]: Fail: wrong image: the key PD unsealed` |
| `sealed-srk-name` (test, sealed boot) | client's SRK Name check removed | `foreign TPM: hs audited KeyUnavailable code=…, want SrkMismatch` |
| `sealed-cap` (test, sealed boot) | `tpm` never calls `cap` | `cap: PCR 8 after the boot is … (uncapped)` |
| `tpm-proxy-hmac` (test, tpm proxy) | Unseal response HMAC check removed | `A7 proxy: hs audited KeyUnavailable code=…, want TpmResponseInvalid` |

The wrong-image and tampered-descriptor controls are the TPM's PCR
policy. The mutation that reaches them removes the PCR binding on both
sides; the TPM itself cannot be mutated cheaply.

### Not run here (owner)

Kani (all caches invalidated by `Cargo.lock`), `make mir` (`MIR-CRATES 8`:
`tpm2-wire` enters through pd-tpm, pd-key and pd-pqkey), `make repro`
(`REPRO-ARTIFACTS 14`), `make ct` (`RESIDUE-CASES 27` measured natively
only), `make test` (`INTEGRATION-CASES 44`), and every selftest case.

### Side fixes

- **Two check-selftest anchors were stale before this slice.** Each makes
  its case stop with "injection anchor … matched N times":
  - `ct-identity` (since slice 3): the build_pd line now carries
    `--remap-path-prefix`. The anchor is the current line, and the
    mutation adds `-Copt-level=3` for pq as before.
  - `pins` (since slice 5): `\trm -rf $(BUILD)` also matched the U-Boot
    rule. It is now `\trm -rf $(BUILD) $(HOME)`, the `clean` recipe.

  Every `edit()` anchor in check-selftest was checked to match exactly
  once in this tree.

### Slice 7 verification (orchestrator, under QEMU)

- **Integration:** all 44 cases pass on the U-Boot + swtpm path
  (`INTEGRATION-CASES 44`). That covers the TIS mapping at `0xc000000`,
  sealed boot, the wrong-image (code 14), tampered-descriptor (code 14),
  foreign-TPM (code 13) and cap cases, and the A7 proxy. The proxy is
  feasible: the unmodified relay passes a sealed boot, and a flipped Unseal
  response byte gives code 15.
- **check-selftest:** each of these is red with its failure-only needle:
  `tpm2-open-residue`, `sealed-pcr-unbound`, `sealed-srk-name`,
  `sealed-cap`, `tpm-proxy-hmac`, the re-anchored `ct-identity` and `pins`,
  and `laws-pq-key` and `laws-hs-pqkey`.
- **`make ct`:** RESIDUE-CASES 27.
- **U-Boot `CONFIG_CMD_CACHE`.** The shipped boot command's
  `dcache flush; dcache off; icache off` printed "Unknown command": the
  fragment lacked `CMD_CACHE`. QEMU booted anyway because the Microkit
  loader manages caches itself, but the Microkit manual's board procedure
  needs caches off before `go`, so the fragment now enables it, and a
  re-run boot shows no unknown command.
- **`make repro` cleans up after itself.** The copy's build left units in
  the shared PD target directory, including config's build-script output
  with the copy's absolute path. Cargo then reused those units for the
  primary tree, whose next release build failed. `tools/repro` now removes
  the PD target directory on every exit, so the next primary build is cold
  (about 30 s).
