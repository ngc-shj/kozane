# Plan: secureos-m5-measured-release

M5 of [docs/PLAN.md](../../PLAN.md): reproducible build, measured boot, TPM
sealing, attestation, signed releases, release kernel with UART audit. It
also closes M4 carry-overs: the verified-vs-shipped build comparison (M4
deviation log, "Where the source scan stops"), the Verus macro/vstd pairing
(M4 code review S11) and the kani-gate lock split. Architecture laws L1–L13
and residuals R1–R6 are in
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md);
this plan amends L1, L5, L6 and L13 where stated.

Process (owner, 2026-10-22): contract-first, risk-tiered review, vertical
slices with fast gates, one solo `make check` at the end. Decisions the
owner delegated are recorded here, not asked (signing-key custody: dev keys,
residual RM5-1).

## Project context

- Type: `mixed` — seL4/Microkit image (no_std Rust PDs) + host tools + libraries.
- Test infrastructure: unit + Kani + Verus + bolero + C9/C10 gates + QEMU
  integration + gate self-test, all behind local `make check`; no CI (SC9).
- Verification environment constraints (new IDs continue the architecture
  plan's VE1–VE5):
  - **VE2** (existing) QEMU has no root of trust.
  - **VE6** Under QEMU, U-Boot is the first code that runs and nothing
    measures it: it stands in for the CRTM. A measured-boot claim under QEMU
    is "U-Boot measured what it ran", not "the platform measured U-Boot".
  - **VE7** swtpm is a software TPM in the host process tree: no bus,
    no physical attacks, no vendor EK certificate chain (swtpm_setup can
    issue one from a local test CA only).
  - **VE8** No offline signing host or HSM: release keys are dev keys on the
    build host (RM5-1).
  - **VE5** (existing) No verified board: everything that needs one is M7.

### QEMU-verifiable vs hardware-required

| Area | verifiable-local (QEMU, swtpm, host) | blocked-deferred to M7 (board + TPM) |
|---|---|---|
| Reproducible build | bit-identical image and PD ELFs from two trees at different paths; cross-machine (gx10, z1mn) with the same dev image | — |
| Measured boot | U-Boot extends PCR 8 with the boot descriptor and the published image, then runs exactly that (C8) | firmware measuring U-Boot into PCR 0–7 (TF-A / boot ROM); PCR 0–7 in the seal policy |
| TPM sealing | salted, parameter-encrypted policy session against swtpm; offline sealing (TPM2_Import) from the SRK public; tamper/foreign-TPM/wrong-image deny cases (C9–C11, C14) | TIS over the board's SPI/I²C; bus-interposer resistance in practice; real EK certificate chain at provisioning |
| Attestation | implicit attestation by PCR-sealed static keys; release verifier tool (C12) | explicit TPM2_Quote (SC31) |
| Signed releases | Ed25519 + ML-DSA-65 manifest, sign and verify, deny fixtures (C13) | offline/HSM custody of release keys (RM5-1) |
| Release kernel + UART | release Microkit config booted in QEMU, every PD reporting through audit to PL011 (C6, C7) | the board's UART, release kernel on the board |

Anti-Deferral for the M7 column: each needs a board with a TPM (VE5). The
cost of emulating them (firmware measured boot under QEMU via TF-A + a
measured U-Boot) is a second boot chain that M7 replaces anyway; VE6 states
what the QEMU chain proves instead. Worst case until M7: an attacker who can
replace U-Boot or its compiled-in command (boot media write) defeats
measured boot; on QEMU that is the test harness itself.

## Objective

A published, signed, bit-reproducible image whose static secrets are
released only by a TPM to the image the release manifest names, with no
plaintext secret on boot media, no kernel debug printing in shipped images,
and gates that tie what Verus/Kani verified to what ships.

## Threat model additions

| ID | Adversary | Capability |
|---|---|---|
| A6 | Boot-media attacker | Reads and rewrites boot media (image, blobs, descriptor) offline; cannot change U-Boot's compiled-in command (VE6: on QEMU, that is the harness) |
| A7 | TPM-bus attacker | Reads and rewrites TPM command/response bytes (on QEMU: a proxy between QEMU and swtpm, or a compromised `tpm` PD) |
| A5 | (existing) supply chain | now also: a release-signing key thief (RM5-1) |

## Contracts

Control classes follow R49. "Gate" = fail-closed verification gate unless
stated.

### C1 — Dev image rebuild (Minor tier; mechanical)

- Adds, pinned as the image already pins (snapshot apt or sha256 tarball):
  swtpm + swtpm-tools, tpm2-tools (provisioning and interop oracle), and
  U-Boot built from a sha256-checked source tarball, offline after fetch,
  with a config fragment enabling TPM2 MMIO (TIS), `hash`, `tpm2`, and a
  compiled-in `CONFIG_BOOTCOMMAND` (C8). The Verus source subtrees
  `builtin`, `builtin_macros`, `state_machines_macros`, `vstd` are copied to
  `/opt/verus/src` (C5).
  Plus the sources of Verus's `verus_syn` and `verus_prettyplease` forks
  (F3: C5's member set has six crates).
- Class: fail-closed verification gate (`check-pins`); adjudication: the
  pinned digests.
- `tools/check-pins` gains rules for each new pin; fixtures per rule.
- Acceptance: `make pins` green with the new rules; each new rule red on a
  fixture that drops its pin.

### C2 — Proof lock out of the hashed gate (Minor tier)

- The `flock` on `/tmp/secureos-proof.lock` moves to a wrapper that both
  `kani-gate.sh` and `verus-gate.sh` call through; the wrapper is not in
  either cache key. The lock comment says "container".
- Done in the same commit range as the first `Cargo.lock` change (C10), which
  invalidates every Kani cache anyway, so the split costs no extra re-prove.
- Invariant: two proof runs in one container never overlap (I2.1).
- Class: enforceable boundary within one container (`flock` by the kernel);
  none across containers or machines (stated).
- Acceptance (T7, T9): stub A runs through the wrapper, writes `A-start`
  and then waits, unbounded, for a release file the harness creates. Once
  `A-start` exists the harness (1) asserts `flock -n` on the lock path
  fails (structural: A holds it), (2) runs stub B (writes `B-start`)
  through the wrapper under `timeout 30` and asserts B timed out with no
  `B-start`, then releases A. A slow host can only make B look more
  blocked, so the green outcome cannot flip to a false pass. Paired red
  run with the lock bypassed: B must write `B-start` within the same 30 s
  (one file write, normally milliseconds); if it does not, the red-proof
  itself fails loudly rather than passing.

### C3 — Reproducible build gate (Major tier)

- `make repro`: builds the published image (`loader.img` with zero
  placeholders), every PD ELF in `$(pds)` and `report.txt` in a second tree
  at a different absolute path, and compares sha256 of each with the
  primary build. Class: gate; adjudication: byte equality of the artifacts
  Microkit and cargo produce.
- Member set: `$(pds)` from the Makefile + `loader.img` + `report.txt`
  (`grep '^pds :=' Makefile`). The C10/C11/C9 new PD (`tpm`) joins via `$(pds)`.
- Invariant I3.1: the published image is a pure function of the git tree
  and the dev image digest. Path and time do not enter it.
- Cross-machine: the same comparison between gx10 and z1mn (same image, same
  commit) is a manual verification step at the end of M5, recorded with
  hashes; not a `make check` gate (needs two machines).
- Deny fixture: a PD that embeds its absolute build path (`file!()` without
  remapping, or `env!("CARGO_MANIFEST_DIR")`) → gate red, needle names the
  differing artifact.
- If the first run shows non-determinism, the fix (e.g. `--remap-path-prefix`,
  Microkit ordering) is part of this contract, recorded in the deviation log.

### C4 — Verified-vs-shipped MIR gate (Critical tier: closes an M4 accepted gap)

- For each crate in `verus_crates`, and each crate in `kani_crates` that a
  PD links, the shipped toolchain emits MIR (`-Zunpretty=mir`, spans and
  build paths normalised) twice: (a) under the exact PD build configuration
  (target `aarch64-sel4-microkit`, release profile, the feature set cargo
  unifies for that PD, `CARGO_PRIMARY_PACKAGE` unset); (b) under the
  configuration the proofs used (host aarch64 target, the gate's profile
  and features, `CARGO_PRIMARY_PACKAGE=1`, `cfg(kani)` off). Both are
  aarch64, so target-dependent layout matches; a difference is a cfg,
  feature, profile or env split.
- Class: gate over the axes it compares (target cfgs, features,
  debug-assertions, overflow-checks, primary-package env). Adjudication:
  rustc's own MIR. Not compared, and stated: the Verus-only cfgs
  (`verus_keep_ghost*`) and Verus's own rustc (1.98.1 vs the nightly) — the
  M4 scan still covers that axis (RM5-3). Equal MIR does not prove Verus saw
  it; it proves the shipped body is the body the host builds see.
- Invariant I4.1: every function body a PD ships from a verified crate is
  textually identical (normalised MIR) to the one the host-side proof
  configuration compiles.
- Member set: `verus_crates` ∪ (`kani_crates` ∩ PD dependency closure via
  `cargo metadata`), derived by the gate, printed as `MIR-CRATES <n>` and
  counted in the manifest.
- Deny fixtures (each red, needle = failure-only diff line): a body under
  `#[cfg(target_os = "none")]`; one on `option_env!("CARGO_PRIMARY_PACKAGE")`;
  one on `cfg(debug_assertions)`; one on a feature only a PD enables. Allow
  fixture: `cfg!(target_os)`-free identical crate passes.
- Both dumps use `-Zmir-opt-level=0` (S8-A), so optimisation passes cannot
  differ; the profile axes compared are `debug-assertions` and
  `overflow-checks`. No member crate uses `debug_assert!` today (`grep -rc
  debug_assert crates/<member>/src` = 0 for all seven), so the
  debug-assertions axis has nothing legitimate to differ on.
- Normalisation is the contested part: it may strip only spans, scope
  comments and absolute paths (listed in the gate). A fixture shows a
  changed constant survives normalisation.

### C5 — Verus macro/vstd content pairing (Major tier; closes S11)

- Compares the registry sources cargo resolves for `vstd`,
  `verus_builtin`, `verus_builtin_macros`, `verus_state_machines_macros`,
  `verus_syn`, `verus_prettyplease` (Cargo.lock versions) with `/opt/verus/src/<crate>` file by file. Allowed
  differences: listed per file in a policy file (expected: `Cargo.toml`
  version/metadata fields only). Class: gate; adjudication: byte equality.
- Member set: every Cargo.lock package whose name starts with `verus_` or is
  `vstd` (`grep -E '^name = "(vstd|verus_[a-z_]+)"' Cargo.lock` → the six
  above, re-run 2026-10-23); a new one without a pairing entry fails, and so
  does a member with no counterpart in `/opt/verus/src`.
- Deny fixture: one byte changed in a copied registry source → red.
- If the sources differ today, that is a finding against M4's pairing:
  either re-pin to matching versions or record the diff as reviewed in the
  policy file with the reviewer; the plan does not pre-accept it.

### C6 — Audit as the only console; UART driver role (Critical tier: L10 on shipped images)

- `audit` maps the PL011 TX page (`0x9000000`, user-mappable in both SDK
  configs per `platform_gen.json`) and writes events to it; no RX interrupt,
  no receive path. Decided against a separate UART PD (SC11's wording):
  audit's input is already the closed L10 enum, so a second PD adds a ring
  and buys no isolation.
- No PD calls `seL4_DebugPutChar`. Readiness and halt lines move into
  closed `AuditEvent` codes (`Ready`, `Halted` with a closed reason code,
  `KeyUnavailable`). Like every multi-producer code today they carry no
  producer field: the producer is the `audit_<pd>` region the record came
  through (F5). `key` and `pqkey` share no memory with audit (L1), so
  their failure is reported by their callers: a `key`/`pqkey` that failed
  to unseal stays up and answers every oracle call `Unavailable`; `hs`/`pq`
  emit `KeyUnavailable`.
- Laws: audit gets role `service` + a UART device MR; L5 extended: a
  `service` PD may own exactly one device page whose policy entry is marked
  `console`, mapped `rw` (Microkit refuses write-only maps; read is for the
  TX-FIFO flag only). The no-RX guarantee is no IRQ and no RX code, not the
  permission bit (F4). C7 fixtures for: a second console page, a
  console page mapped into another PD, an IRQ on audit.
- Member set (R42): files calling debug printing,
  `grep -rlE 'debug_put_char|DebugPutChar|debug_print!|debug_println!' crates/`
  → netdrv, pds/{audit,data,hs,ingress,inner,key,pq,pqkey} (hello excluded:
  not in `$(pds)`, not shipped). Each is migrated.
- Forbidden: `pattern: debug_print|debug_println|debug_put_char|DebugPutChar`
  in `crates/pds/` (except `hello`) and `crates/netdrv` — reason: L10/R4.
  Plus an ELF check in `ct-shape`'s pass over PD ELFs: no PD references the
  DebugPutChar syscall wrapper symbol.
- Class (S3): the boundary is the release kernel itself (C7: no
  `CONFIG_PRINTING`, so the syscall does not exist). The source and ELF
  scans are best-effort tripwires for debug images and early detection;
  known bypasses: inline `asm!` issuing the syscall, an unlisted wrapper.
- Acceptance: every integration readiness wait reads audit lines; a release
  image boots with readiness for every PD.

### C7 — Release kernel images (Major tier; closes SC20, R4 on shipped images)

- `tools/package` refuses `debug` and accepts only `release` (`gen_config.h`:
  `CONFIG_PRINTING` absent, `CONFIG_KERNEL_MCS 1`, single node). The C9
  record requirement on non-debug kernels stays.
- `make test` packages and boots release images. `make image`/`make run`
  keep `MICROKIT_CONFIG ?= debug` for development.
- Invariant I7.1: no packaged image has a printing kernel.
- Class: fail-closed verification gate in `tools/package`; adjudication:
  the built `gen_config.h` the image was linked against.
- Fixtures: package refuses a debug `gen_config.h`; refuses a release one
  with `CONFIG_PRINTING` defined.

### C8 — Measured boot under QEMU (Critical tier)

- U-Boot's compiled-in boot command (not a loaded script; VE6) does, in
  order: read the boot descriptor at a fixed address; `PCR8 ← extend(sha256(descriptor))`;
  `PCR8 ← extend(sha256(image[0, descriptor.image_len)))` at the fixed load
  address; check on-device that every descriptor range lies in
  `[0, image_len)` without wrap (`offset ≤ image_len` and
  `len ≤ image_len − offset`; `offset + len == image_len` is allowed, S12),
  ranges are disjoint, and each length equals its
  envelope's length (S1); copy each sealed envelope into the image at those
  ranges; jump to the fixed loader entry. Any step failing → U-Boot stops
  (no boot).
- The command is one script fragment in the repo, compiled into U-Boot as
  `CONFIG_BOOTCOMMAND`; the harness-only variant (C8 acceptance) is the same
  fragment with the final jump replaced by a stop, generated from it, never
  hand-written (T5).
- Packaging model change (F2): the published `loader.img` is never modified
  per device. `tools/package` outputs the descriptor and the envelopes only;
  its `check_images` per-device image diff is retired, and its replacement
  is: the assembled image (published image + envelopes at the descriptor's
  ranges, as U-Boot does) differs from the published one only inside those
  ranges, checked by the same shared assembly helper the expected-PCR tool
  uses. L6's sentence from "Packaging re-runs C7 and `microkit`" through
  "and the blob (or its sealed form) separately" is replaced as a whole
  (F7): packaging emits the descriptor and envelopes for the published
  image; the shared helper's assembled image differs from the published one
  only inside the descriptor's ranges; verification hashes the published
  image (C3 reproduces it) and the envelopes separately.
- Descriptor: magic, version, `image_len`, and for `secrets` and
  `pq_secrets` the file offset and length of the MR range (the ranges
  `tools/package` already computes for L6). Public; part of the release.
- Invariants:
  - I8.1 what runs is what was measured: the entry is fixed, the measured
    range starts at it, and every later write is confined to ranges the
    measured descriptor names.
  - I8.2 the descriptor's ranges lie inside `[0, image_len)`, are disjoint,
    and equal the system file's prefill MR ranges (checked at packaging and
    by the expected-PCR tool, so a release cannot name a code range).
  - I8.3 expected PCR 8 is computable from public release files alone, by
    one host extend helper that the expected-PCR tool, `tools/package` and
    run.py's cap check all call (T5); a fixture pins the helper against the
    probe's observed value (`sha256(0^32 || 0^32)` =
    `f5a5fd42…59fb4b`) and a known-image chain.
- Class: enforceable boundary under the VE6 assumption (A6 cannot change
  U-Boot's command); detection-only against an attacker who replaces U-Boot
  on QEMU (stated, VE6).
- Probe (done during plan review, 2026-10-23, throwaway container from the
  dev image + Debian trixie `u-boot-qemu` 2025.01 and `swtpm` 0.7.1): with
  `-bios u-boot.bin`, `tpm-tis-device` (U-Boot sees `tpm_tis@0`, TPM 2.0 on
  the platform bus at `0xc000000`), `tpm2 startup`, `tpm2 pcr_extend 8`,
  `tpm2 pcr_read 8` returned the expected
  `sha256(0^32 || digest)`; then `dcache flush; dcache off; icache off; go
  0x70000000` started the Microkit loader at EL2 and the system booted to
  the PDs. Debian's build lacks the `hash` command and has a distro
  `bootcmd`, so C1's source build (with `CMD_HASH` and the compiled-in
  command) is required, not optional.
  The loader printed `CurrentEL=EL2`, so U-Boot's `go` did not drop to EL1
  on QEMU virt (F1; the Microkit manual's ZCU102 note about `do_go_exec`
  stays a M7 board question).
- Acceptance: the host expected-PCR tool's value equals swtpm's PCR 8 read
  with tpm2-tools after a boot of the harness-only variant; a one-byte
  change inside `image_len` or in the descriptor changes it.
- I8.2 fixtures (T1), each red with a needle naming the range: a range past
  `image_len`; two overlapping ranges; a range that differs from the system
  file's prefill MR range; an envelope longer than its range. Allow: ranges
  equal to the prefill MR ranges. Refused by `tools/package` and by the
  expected-PCR tool; the on-device check (S1) is exercised by the C14
  tampered-descriptor case, plus a wrap fixture (offset + len past 2^64
  landing inside the image) refused on-device (S12), paired with an allow
  case at the boundary `offset + len == image_len`.

### C9 — `tpm` driver PD (Critical tier)

- Maps only the TPM TIS MMIO pages (QEMU platform bus; address fixed by the
  probe and the system file), no other MR. Role `tpm`. Channels: PPC from
  `key` and from `pqkey` only (callee). Priority (Microkit PPC
  rule: the callee's `priority` value is strictly greater than every caller's, e.g. `tpm` 145 > `key` 140 > `pqkey` 130); not tainted (no NIC, no tainted peer). Polls the TIS FIFO with
  bounded CNTPCT timeouts; a timeout or protocol error answers the caller
  with an error, never blocks forever.
- Command allowlist (by TPM command code; anything else is refused before
  any TIS register write): CreatePrimary, StartAuthSession, PolicyPCR,
  PolicyAuthValue (S16), Import, Load, Unseal, FlushContext, PCR_Read; `PCR_Extend` is issued only
  by `tpm` itself (the cap) and never forwarded from a client (S11). The allowlist
  and the state machine live in a pure core crate the PD wraps, so they are
  unit- and Kani-testable (T3): deny — every code outside the list (Kani:
  arbitrary `u32`) yields a refusal and no device write; allow — each of
  the nine is forwarded.
- Handle ownership (S11; this is the L2 control between the `key` and
  `pqkey` domains, which share `tpm` as a callee): `tpm` records which client
  each handle came from (CreatePrimary, StartAuthSession, Load outputs) and
  forwards PolicyPCR, PolicyAuthValue, Unseal and FlushContext only on
  handles the caller owns, and Import/Load only under a parent the caller
  owns; FlushContext removes the entry, so a reused handle number belongs
  to its new owner (S16, S19). A client in Done or Failed is refused every
  command. The client flushes its SRK, object and session and then sends an
  explicit Done (or Failed) message; Unseal succeeding does not move it to
  Done, so its own flushes are not refused. Kani over call sequences: deny — a cross-client handle (including
  PolicyAuthValue on the other client's session) is refused, and a client
  after Done is refused; allow — the owner's CreatePrimary → StartAuthSession
  → PolicyPCR → PolicyAuthValue → Import → Load → Unseal → flush flow
  passes, and client B may use a handle number client A flushed; red-proof —
  drop the ownership check, and separately drop PolicyAuthValue from it.
- The whole unseal flow runs in `key`'s and `pqkey`'s `init` (S18). A
  passive PD's endpoint is served only after `init` returns (while `init` is
  blocked in its call to `tpm`, a caller of `key` blocks on the endpoint),
  so no tainted input reaches a client before it is Done or Failed; Import,
  which creates no handle, is therefore never reachable from tainted input.
- Message size (S5): seL4's IPC buffer carries 120 words (960 bytes); every
  command and response of the flow must fit one call, asserted at compile
  time in the core crate from the format's maximum sizes. If one cannot,
  the protocol chunks over several calls. No shared MR is added (key's L1
  exemption forbids it).
- State: per client {Fresh → Unsealing → Done | Failed}; one unseal flow per
  client per boot. After both clients reach Done or Failed, `tpm` extends
  PCR 8 with a fixed separator (cap) and refuses Unseal from then on. Cap is
  permanent for the boot. Tests (T4): the core crate refuses Unseal after
  the cap (unit + Kani over call sequences up to a bound), and refuses a
  second unseal flow from the same client.
- What a hostile `tpm` or an active TPM-bus attacker (A7) can and cannot
  do (S2, S9):
  - Cannot: make a client accept a forged or swapped KEK or secret (response
    HMAC under a session key salted by ECDH to the SRK; per-client AEAD with
    the header as AAD; nonces against replay). Test: a fake TPM returning the
    other client's valid response → `Unavailable`.
  - Cannot strip `encrypt` from a client's salted session: the TPM checks
    a policy session's command HMAC, keyed by the salted session key, before
    releasing anything. (Corrected in slice 6 by measurement: the salt, not
    PolicyAuthValue, carries this; PolicyAuthValue is kept but not
    load-bearing. A relay that rewrites StartAuthSession to unsalted CAN
    then recompute the HMAC and read the KEK; the client refuses the
    response afterwards. That is RM5-5, not a new exposure.) Object substitution is refused by the
    client: it computes the object Name (nameAlg ‖ H(objectPublic)) from its
    own envelope, refuses a Load response whose name differs, and uses its
    own Name in cpHash; unit tests allow a matching name and deny a
    substituted one (S17).
  - Can: run its own session against a loaded or re-imported object and
    unseal the KEK while PCR 8 holds the expected value — before the cap,
    or after a TPM reset and a replay of the two public extends. The policy
    binds the secret to the TPM and PCR 8, not to the caller. So until the
    cap, `tpm` and the TPM bus are trusted for KEK confidentiality (RM5-5).
    On QEMU the bus is the harness; on a board this is the interposer and
    reset-line class, closed in SC32. A host test documents it: a relay
    running its own session unseals (so the C14 A7 case is read as integrity
    evidence only).
  - Can: deny service, skip the cap.
- Class: enforceable boundary for device ownership (C7 laws: only `tpm`
  maps the TIS pages; only key-role PDs reach `tpm`). The handle-ownership
  state machine is the enforcement point for L2 between the two key
  domains (S11). The command allowlist and the cap are defence in depth.
- Laws amendments: L1 — `key`-role PDs may have exactly one channel with
  `pp="true"` on their own end, to a `tpm`-role PD; a `tpm`-role PD must be
  untainted, map only device MRs marked `tpm`, and have channels only to
  `key`-role PDs. Taint seeding (S14): policy/laws.toml today treats every
  device as a NIC; the `tpm` and `console` exemptions are keyed to the pinned
  `phys_addr`/`size` of the TIS pages and the PL011 page, and L5 is amended
  to allow roles `tpm` and `service` (console) for exactly those pages.
  Fixtures: a `tpm` PD owning a non-TIS device and an audit PD owning a
  non-console device are both refused. L13 — `tpm` ordered above `key`. C7 fixtures for each
  clause (a tainted tpm, a tpm with a non-device MR, a second pp channel
  from key, a tpm channel to a non-key PD).
- No audit channel: `tpm` stays untainted and shares nothing with audit;
  its state is observable through `key`/`pqkey` replies (C6) and the C14
  harness reading swtpm after shutdown.
- Kani: the TIS state machine and response length handling (bounded).

### C10 — `tpm2` session crate (Critical tier; parser of A7 bytes)

- no_std, no alloc. Marshals the allowlisted commands; parses responses
  with every length checked (A7 controls them). Salted policy session:
  the caller's ephemeral P-256 key against the pinned SRK public point
  (tpmKey, KDFe), then KDFa
  (SP 800-108 HMAC-SHA256 counter mode as TPM 2.0 Part 1 specifies),
  AES-128-CFB response parameter encryption, response HMAC verified before
  any parameter is used. Offline-sealed object path: Import → Load → Unseal.
- Primitives: libcrux where it has them (SHA-256, HMAC, P-256 ECDH);
  otherwise a pinned RustCrypto crate (expected: `aes` for the block
  cipher), added to the audit gate. No in-repo primitive.
- Invariants:
  - I10.1 no response parameter is read before its HMAC verifies, and the
    tag comparison is constant-time (S7, settled as hardening in round 2:
    `wg_core::crypto::ct_eq`, reused through a dependency or moved to a
    crate both import, not a third copy; or the library's verify API if
    constant-time).
  - I10.2 the TPM is identified by the pinned SRK name; a different SRK
    fails the session (foreign TPM).
  - I10.3 the unsealed KEK appears only decrypted inside the client PD and
    is zeroized after use (L12), on every exit path. `tpm` never sees it in
    plaintext (response encryption), so it has no KEK to wipe (S6); the
    session keys likewise exist only in the client.
- Class: enforceable boundary against a passive A7 (confidentiality) and
  against forged or tampered responses (the client never accepts a forged
  KEK); no confidentiality against an active A7 running its own session
  (S9, RM5-5). Adjudication: the TPM's own HMACs and the pinned SRK name.
- Tests: KATs for KDFa/KDFe/CFB/HMAC from TPM 2.0 Part 1 examples or
  tpm2-tss vectors; host interop against swtpm (the crate drives swtpm's
  socket directly, the way the PD would); Kani on response parsing; bolero
  on response parsing; mutations: skip HMAC check, accept any SRK name,
  drop CFB decrypt, short-circuit `==` on the tag (red via a `ct_eq`-only
  forbidden pattern) — each red. swtpm relay tests (S9): deny — a relay
  that strips `encrypt` from the client's Unseal gets an auth failure from
  swtpm and no outData crosses; allow — the unmodified relay unseals;
  red-proof — remove PolicyAuthValue and the KEK crosses in plaintext. A
  relay running its own session unseals (documents RM5-5).
- I10.3 test (T2): the envelope-open path (unseal result → AEAD open →
  wipe) joins M4's C9 residue harness (the `ct` gate, residue mode), which
  scans for the KEK after return; a selftest case strips the wipe (like
  `strip_mce_wipes`) and the residue gate must go red naming it. The
  envelope-open closure joins `policy/ct-shape.toml`, so M4's C10
  identity check proves the harness scans the same compiled closure
  `key`/`pqkey` ship, not a copy (T10).

### C11 — Sealed secrets envelope (Critical tier)

- Envelope (fits the existing fixed MR sizes; if not, the MR grows and
  `crates/layout` + laws follow): header (magic `SOSSEAL1`, version, kind),
  pinned SRK name and public, PCR selection (8) and policy digest, the
  TPM2_Import duplicate (encrypted seed, duplicate, object public with
  `userWithAuth` clear and authPolicy = PolicyPCR(8, sha256) ∧
  PolicyAuthValue with an empty authValue, S9; slice 6 measured that the
  command-HMAC check comes from the salted policy session itself, so
  PolicyAuthValue is defence in depth, not the control), and the existing secret-blob
  plaintext under ChaCha20-Poly1305 (libcrux) keyed by the 32-byte KEK the
  sealed object holds, header as AAD. The KEK is fresh random per envelope,
  which makes a fixed nonce safe; a host check seals the same blob twice
  and requires different ciphertexts (S13).
- `key` and `pqkey` accept only this format. The plaintext `SOSSECR1`
  format is removed from the PD path. Reason (S10): one format, one parser.
  Not authenticity: A6 can seal attacker-chosen secrets to the real SRK and
  PCR 8 offline (the SRK public is on the boot media), which equals A6
  booting its own image and is accepted under VE6; the genuine keys still
  never unseal for it, so C12 holds. Decrypted secrets live in PD-private memory;
  the MR stays read-only ciphertext.
- Host side (`mksecrets`/`tools/package`): seals offline from the SRK
  public + expected PCR 8 (C8). L6's location rules for the plaintext input
  blob and the outputs are unchanged; the output is envelopes + descriptor,
  not a modified image (C8, F2).
- Class: enforceable boundary (AEAD + TPM policy); the format check is
  the parser's, the decision is the AEAD tag's.
- Invariant I11.1: a blob that does not decrypt (wrong PCR, wrong TPM,
  tampered byte anywhere) leaves the PD `Unavailable`, never partially
  loaded.
- L6 text updated: "M5 replaces the blob with TPM sealing" → the above.

### C12 — Implicit attestation and the release verifier (Major tier)

- Attestation in M5 is implicit: only an image whose PCR 8 matches the
  sealed policy obtains the static WireGuard and Rosenpass keys, so a peer
  completing a handshake has evidence that the gateway booted the image the
  operator sealed to. `tools/release verify` checks a release manifest's two
  signatures (C13), recomputes expected PCR 8 from the published image and
  descriptor, and checks the envelope's policy against it: the digest is
  taken from the duplicate's object public (the one the TPM enforces), not
  the header copy, with `userWithAuth` clear and the PolicyPCR selection
  {8}/sha256 checked; deny fixture: header digest right, object public
  different (S15).
- Class: detection only (evidence for a verifier; it denies nothing).
- What it does not claim (doc): runtime integrity after boot; freshness
  beyond the handshake's own; anything if the static key ever existed in
  plaintext outside the TPM path (provisioning host, RM5-2).
- Explicit TPM2_Quote is SC31: it needs a request path from a tainted PD to
  the TPM, which C9's untainted `tpm` deliberately excludes.

### C13 — Signed releases (Major tier)

- Manifest (canonical text, one `key=value` per line, sorted, LF): version,
  git commit, dev image digest, `loader.img` sha256, descriptor sha256,
  expected PCR 8, `Cargo.lock` sha256, Verus/Kani versions. Signed with
  Ed25519 and ML-DSA-65 over `"secureos-release-v1\0" || manifest`;
  verification requires both (AND).
- Libraries: libcrux ML-DSA-65; Ed25519 from libcrux if available, else
  `ed25519-dalek` pinned. Host tool only.
- Dev keys: `make release-keys` writes them outside the repo, `build/` and
  cache volumes (same location check as L6). Tests use ephemeral keys.
- Class: fail-closed verification gate in the verifier; adjudication: the
  two signature algorithms over the exact signed bytes; unknown or
  duplicate keys refused before any field is used.
- Allow fixture (T8): a valid dual-signed manifest verifies and its fields
  are returned. Deny fixtures: either signature missing/invalid; one manifest byte
  flipped; a key swapped; an image whose hash differs from the manifest;
  a manifest with a duplicate or unknown key.

### C14 — Integration on the measured, sealed, release path (Critical tier)

- Class: test evidence for C8–C11 (not a control).
- `run.py` gives every boot its own swtpm state directory and socket
  inside the run's existing temp dir, started before and killed after that
  boot; removal is checked like `final_teardown` and a leftover fails the
  run (T6). Provisioning (SRK with the standard template, public read once)
  happens per state directory; packages a release image with
  envelopes sealed to it, and boots through U-Boot with `tpm-tis-device`.
  All existing cases run on this path.
- New cases (failure-only needles from audit lines or harness messages):
  - allow: sealed boot → handshake, as today;
  - wrong image: one byte changed inside `image_len` outside the MR ranges,
    same envelopes → `KeyUnavailable`, no handshake;
  - tampered descriptor (MR range moved into code) → U-Boot refuses or
    PCR mismatch → no handshake;
  - foreign TPM: envelopes sealed to another swtpm's SRK → `KeyUnavailable`;
  - A7: a proxy between QEMU and swtpm flips one byte in the Unseal
    response → `KeyUnavailable`. Feasibility criterion (F6-A): the proxy
    must first pass an unmodified sealed boot (allow) on the same path; if
    QEMU's emulator backend (data + control channels) cannot be proxied so
    that the allow boot succeeds, the case is recorded as blocked with that
    evidence and covered by C10's host tamper tests. This case is
    integrity evidence only (S9);
  - cap: after boot, swtpm's PCR 8 equals expected-then-capped, read with
    tpm2-tools after QEMU has exited and before that boot's swtpm is
    stopped (T11).
- Each new case gets a selftest red-proof on a scratch tree (control named:
  e.g. remove the HMAC check → A7 case red).

## Testing strategy

- Per slice: crate unit tests, targeted Kani harness (alone first, under
  `timeout`, watching `docker stats`), the slice's selftest case(s), `make
  test` whenever run.py or a crate it reads changes, the integration cases
  the slice touches.
- Mutations per Critical invariant (I4.1, I8.1, I8.2, I10.1 incl. the
  constant-time compare, I10.2, I10.3, I11.1, allowlist, cap, handle
  ownership, fresh KEK — the KEK fixed on a scratch tree must turn the
  seal-twice check red with a needle naming the identical ciphertexts,
  T13):
  break it on a scratch tree, name the red test and its failure-only needle,
  record in the deviation log.
- `tests/manifest.txt` updated with every new count (MIR-CRATES, new
  fixtures, Kani harnesses, integration cases).
- Final: one solo `make check` on gx10; full selftest split with z1mn;
  cross-machine repro hashes recorded.

## Slices (order)

1. C1 image rebuild (owner loads it on z1mn), C2 lock split.
2. C7 + C6 release kernel and audit console (independent of TPM).
3. C3 repro gate.
4. C5 then C4.
5. C8 probe (U-Boot + tpm-tis-device + Microkit loader); the C11 envelope
   size computed from the format so the MR sizes are settled before the
   descriptor; then C8.
6. C10 crate with swtpm interop, C11 host sealing.
7. C9 `tpm` PD, C11 in `key`/`pqkey`, C14.
8. C13 + C12.
9. Final gates.

## Considerations & constraints

- Every `Cargo.lock` change invalidates all Kani caches (hours). C2 lands
  with the first one; heavy crates are re-proved on z1mn in reverse order
  and the caches copied back.
- No Kani/Verus concurrency; container at 40 GB; subagents run no Kani,
  `make check` or QEMU.
- Boot time: U-Boot adds to every integration boot under TCG; measured in
  slice 5 and recorded; budgets are not widened to absorb it without a cause.

### Residual risks added

- **RM5-1** release keys are dev keys on the build host (owner decision).
  Worst case: key theft lets an attacker sign a release; devices still only
  unseal for the PCR the operator sealed to, so a forged release does not
  get secrets without a re-seal. Close: offline/HSM custody (M7 or ops).
- **RM5-2** secrets are generated on the packaging host and exist there in
  plaintext before sealing. Close: on-device generation, which needs a
  write path to the boot media (L6 forbids runtime configuration).
- **RM5-3** C4 does not compare the Verus-only cfg axis or Verus's rustc;
  the M4 source scan covers that axis (accepted in M4).
- **RM5-5** the seal policy binds secrets to the TPM and PCR 8, not to the
  caller: anyone with TPM command access while PCR 8 holds the expected
  value (before the cap, or after a TPM reset and a replay of the public
  extends, or by rewriting a client's StartAuthSession to unsalted) can
  unseal the KEK and, with the envelope from boot media, the
  secrets (S9). Worst case: gateway impersonation by an active bus
  attacker. Likelihood on QEMU: the harness only. On a board: needs
  physical access to the TPM bus or reset line. Close (SC32): a
  non-interposable TPM (fTPM or SoC-integrated), reset-line protection, or
  locality-restricted PCRs.
- **RM5-4** no rollback protection: an older signed image with its own
  sealed envelopes still boots. Close: a TPM NV counter in the policy.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC9 | CI | when a remote exists |
| SC11 | Closed by C6 (audit owns the console; no separate UART PD) | M5 |
| SC17 | Whole-system halt / watchdog reset on PD fault | M7 |
| SC20 | Closed by C7 | M5 |
| SC24 | Rosenpass V03 | first upstream release containing V03 |
| SC28 | Dedicated InitConf ring, if needed | M7 measurement |
| SC30 | amd64 dev image for the ul9c hosts | unscheduled (not needed for M5 gates) |
| SC31 | Explicit TPM2_Quote attestation over the network | unscheduled; needs a tainted request path to the TPM |
| SC32 | Firmware-measured U-Boot, PCR 0–7 in the policy, board TIS bus, EK certificate verification at provisioning, closing RM5-5 | M7 |
| SC33 | Anti-rollback NV counter (RM5-4) | unscheduled |

## User operation scenarios

1. Release engineer: `make release` → published `loader.img`, descriptor,
   manifest, two signatures; a second machine reproduces the same hashes.
2. Operator provisioning a device: reads its SRK public once, runs
   `make package` with it → envelopes sealed to that TPM and the release's
   PCR 8; copies image, descriptor, envelopes to boot media.
3. A6 swaps the image for a patched one but keeps the envelopes → gateway
   boots, keys stay sealed, peers see no handshake, audit says
   `KeyUnavailable`.
4. A6 replaces the envelope with a plaintext `SOSSECR1` blob → `key`
   rejects the format.
5. Verifier: `tools/release verify` on the manifest and the device's
   envelope → signatures valid, policy digest matches the manifest's PCR 8.

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Dev image rebuild (swtpm, tpm2-tools, U-Boot, Verus sources) | locked |
| C2 | Proof lock outside the hashed gates | locked |
| C3 | Reproducible build gate | locked |
| C4 | Verified-vs-shipped MIR gate | locked |
| C5 | Verus macro/vstd content pairing | locked |
| C6 | Audit as the only console (PL011), no debug printing | locked |
| C7 | Release-kernel packaging and integration | locked |
| C8 | Measured boot under QEMU (U-Boot, PCR 8) | locked |
| C9 | `tpm` driver PD and laws amendments | locked |
| C10 | `tpm2` session crate | locked |
| C11 | Sealed secrets envelope | locked |
| C12 | Implicit attestation and release verifier | locked |
| C13 | Signed releases (Ed25519 + ML-DSA-65) | locked |
| C14 | Integration on the measured, sealed, release path | locked |

## Implementation Checklist

Written at the end of Phase 2 from the slices' impact analyses, which the
deviation log records slice by slice. Each contract's files:

| Contract | Files |
|---|---|
| C1 | `docker/Dockerfile` |
| C2 | `tools/proof-lock`, `tools/kani-gate.sh`, `tools/verus-gate.sh`, `tests/tools/test_proof_lock.py` |
| C3 | `tools/repro`, `Makefile` (`pd_target`, remap, `repro`), `crates/config/build.rs`, `tools/check-selftest` (`repro-path-leak`) |
| C4 | `tools/mir-gate`, `tools/mir-capture`, `tests/tools/test_mir_gate.py`, `tools/check-selftest` (`mir-*`) |
| C5 | `third_party/verus/*`, root `Cargo.toml` `[patch]`, `policy/verus-pairing.toml`, `tools/verus-pairing`, `tests/tools/test_verus_pairing.py`, `tools/check-pins` (P12, P16) |
| C6 | `crates/audit-event`, `crates/pdkit`, `crates/netdrv`, `crates/pds/{audit,data,hs,ingress,inner,key,pq,pqkey,eth-in,eth-out}`, `crates/key-core`, `crates/pqkey-core`, `system/secureos.system`, `policy/laws.toml`, `tools/laws`, `tools/ct-shape` |
| C7 | `tools/package`, `tests/tools/test_package.py`, `Makefile` (`test`), `tests/integration/run.py` |
| C8 | `support/u-boot/{secureos.config,boot.cmd}`, `tools/uboot-config`, `tools/measure.py`, `tests/tools/test_measure.py`, `tools/package`, `tests/integration/run.py` |
| C9 | `crates/pds/tpm`, `crates/tpm2-wire` (`gate.rs`, `proofs.rs`), `crates/layout`, `system/secureos.system`, `policy/laws.toml`, `tools/laws` |
| C10 | `crates/tpm2`, `crates/tpm2-wire`, `tools/check-pins` (P9–P11), `tools/ct-harness`, `policy/ct-shape.toml` |
| C11 | `crates/tpm2/src/envelope.rs`, `tools/mksecrets`, `crates/pds/{key,pqkey}`, `tools/package` |
| C12 | `tools/mksecrets` (`check-envelope`), `tools/release.py` |
| C13 | `tools/release/*`, `tools/release.py`, `tests/tools/test_release.py`, `policy/audit-ignore-release.toml`, `Makefile` (`release-*`, `pins`, `audit`) |
| C14 | `tests/integration/run.py`, `tools/check-selftest`, `tests/manifest.txt` |
