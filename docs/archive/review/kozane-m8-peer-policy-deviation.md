# Coding Deviation Log: kozane-m8-peer-policy

Observations and deviations against
[kozane-m8-peer-policy-plan.md](kozane-m8-peer-policy-plan.md), in order.

## Slice 0: probes

Probe scripts live under `build/probes/` (untracked scratch), and each
result below names the facts it established. The scripts run in the
`kozane-dev` container on gx10 unless stated.

### P1 — swtpm NV semantics (passed, 2026-10-29)

Run on swtpm 0.7.1 with tpm2-tools 5.7 (`build/probes/p1/{probe,special,undef}.sh`, twin
`build/probes/p1/twin.py`). Every check passed:

- **Definitions.** The counter `0x01500100` was defined with attributes
  `0x42040414` and the base `0x01500101` with `0x42042404`, both under the
  platform hierarchy and both with the delete policy. The attribute sets
  are the C3 ones:
  - counter: `TPM_NT_COUNTER`, `AUTHWRITE`, `AUTHREAD`, `NO_DA`,
    `POLICY_DELETE`, `PLATFORMCREATE`;
  - base: the same bits with `WRITEDEFINE` instead of the counter type.

  tpm2-tools' attribute keywords do not cover `policy_delete`, so the
  numeric values are used. The host twin needs them anyway.
- **Delete policy twin.** The twin computes
  `PolicyCommandCode(NV_UndefineSpaceSpecial) ∧ PolicySigned(op1) ∧
  PolicySigned(op2)` with a fixed `policyRef`, and the TPM accepted that
  digest as the indices' authPolicy.
- **Counter and base.** The first `NV_Increment` gave counter 1 on a fresh
  swtpm, and the next increment gave exactly +1. With `base =
  counter.wrapping_sub(7)`, the logical version came out as 7. A write to
  the base after `NV_WriteLock` was refused.
- **Names.** Both Names match the twin. The counter's Name includes
  WRITTEN, and the base's Name includes WRITTEN and WRITELOCKED.
- **Plain undefine is refused by the TPM.** A raw `TPM2_NV_UndefineSpace`
  of the counter returns `0x282` (TPM_RC_ATTRIBUTES on the NV handle),
  under both the owner and the platform hierarchy. The probe sends it raw
  because tpm2-tools refuses it client-side, so the tool alone never
  reaches the TPM.
- **TPM2_Clear.** `TPM2_Clear` (platform) succeeds and leaves both indices
  with their Names and the counter value unchanged.
- **Persistence.** The counter value survives a SIGKILL of swtpm followed
  by Startup(CLEAR).
- **`resetCount`.** It goes up by exactly 1 across a power cycle, both
  after an orderly Shutdown(CLEAR) and after a SIGKILL. That is the C10
  `reset_at_provision + 1` fact.
- **`NV_UndefineSpaceSpecial`.** It succeeds only with both operators'
  PolicySigned in the session, each bound to the session's own
  `nonceTPM`, `expiration = 0`, the fixed `policyRef`, and `cpHashA` of
  this command and index. The refusals:
  - one signature only: refused (policy check);
  - signatures bound to the other index's cpHash: both PolicySigned
    calls are accepted, then the command is refused;
  - a signature replayed into a new session: PolicySigned refuses it
    with `TPM_RC_SIGNATURE` (0x5DB), because the nonce differs.
- **Capabilities.** `phEnableNV` and `phEnable` are readable through
  `GetCapability`, and `ownerAuthSet` is 0.

Note for C3: tpm2-tools leaves `loadexternal` objects loaded. More than
three PolicySigned calls in one run exhaust swtpm's object slots
(`0x902`) unless transient contexts are flushed. The provisioning tool
must flush after each one.

### P2 — no_std signature verification (build and vectors passed; TCG timing moved)

Probe crate: `build/probes/p2`. It contains the verify path the `policy`
PD would use, with Ed25519 AND ML-DSA-65 over `DOMAIN ‖ body` and an
empty ML-DSA context, the same convention as `tools/release`.

- **Build.** It builds for `aarch64-sel4-microkit` with
  `-Z build-std=core,compiler_builtins` (core only, no alloc), at
  `tools/release`'s pins `libcrux-ml-dsa =0.0.11` and
  `libcrux-ed25519 =0.0.10`.
- **Lockfile impact.** Only those two packages are new to the PD
  `Cargo.lock`. Every dependency they pull in (libcrux-sha3/-sha2/
  -intrinsics/-platform/-secrets/-hacl-rs/-traits, libc 0.2.191,
  rand 0.10.3) is already locked at the same version.
- **Vectors.** Allow; a flipped body byte is denied; the Ed25519 half bad
  alone is denied; the ML-DSA half bad alone is denied.
- **Native cost per boot** (SHA-256 of both slots plus verification of
  both, gx10): 33 ms at the maximum body (4.25 MB), 4 ms at one peer.
- **Deviation:** the plan's pass condition measures `policy` under TCG
  at its real priority, with the key PDs running above it. That needs the
  `policy` PD, which does not exist until slice 3. That measurement moves
  to the first boot carrying `policy` in slice 3, with the pass condition
  unchanged. The container has no qemu-user for a stand-alone TCG run.
  - Anti-Deferral: the native cost leaves a 30× margin under one second,
    so the design premise the probe guards (verification fits the boot
    budget) holds now.
  - The worst case is a TCG slowdown far beyond the usual 10–50×, found
    in slice 3. It would only re-time `CAP_BARRIER_TIMEOUT_NS` and
    `BOOT_TIMEOUT_S`, not change a contract.

### P3 — measuring and loading two `BUNDLE_MAX` slots (passed in two parts)

Run in a scratch worktree (`build/probes/p3/tree`, since removed).

- **U-Boot under TCG.** A probe variant of the boot command loads two
  random 4.5 MiB slots at `0x6f100000` and `0x6f600000` (below the
  `0x6fb00000` scratch), hashes each, extends PCR 9 with A then B,
  copies both and prints PCR 9.
  - The two hashes, two extends and two copies take **0.15 s** under TCG
    (`cortex-a72`, the shipped TF-A and U-Boot).
  - PCR 9 equals the host twin `extend(extend(0, sha256(A)), sha256(B))`.
  - The probe ran on the `measure` firmware path through
    `run.boot_uboot`, with QMP reporting `guest-shutdown`.
- **Microkit image.** The current system plus two prefill MRs of
  `0x480_000` builds. The test mapping is `r` into `inner`, outside its
  existing window.
  - The loader image grows from 8.2 MiB to 17.6 MiB, inside U-Boot's
    256 MiB `MAX_IMAGE`. U-Boot's PCR 8 hash of the image grows by the
    same 9 MiB, about 0.15 s on the figure above.
  - Two facts for C11 and C6: a prefill MR mapped without `setvar_vaddr`
    needs no symbol in the ELF, and a PD's window must avoid its
    existing maps. `inner`'s ring data already sits at `0x10_000_000`.
- **Deviation:** the plan's P3 pass condition says "boots". The enlarged
  image is not booted end to end in slice 0, because that needs the C4
  descriptor v3 and a sealed package.
  - The first C4 integration boot (slice 2) carries that check. The
    PCR 9 path and the image build, the parts slice 0 can isolate, both
    passed.
  - Anti-Deferral: the remaining risk is the Microkit loader's copy of
    9 MiB more, a memcpy that U-Boot's 0.15 s already bounds from above.
    Worst case it adds well under a second to `BOOT_TIMEOUT_S`'s budget.

### P4 — TPM command support (narrowed)

- P1 exercised every command P4 names against swtpm through tpm2-tools,
  with password sessions where needed: `NV_ReadPublic`, `NV_Read`,
  `NV_Increment`, `ReadClock` and `GetCapability`
  (`TPM_PT_PERMANENT` / `STARTUP_CLEAR`). The TPM side holds.
- **Deviation:** the `tpm2-wire` builders and parsers do not exist yet.
  Their round trip against swtpm becomes part of C3's interop tests in
  `crates/tpm2/tests` (slice 2) rather than a slice-0 probe.
  - Anti-Deferral: writing them now would be C3's implementation. The
    probe's question, whether swtpm supports these commands in this form,
    is answered.

### P5 — `make test` wall clock (passed)

- On z1mn at 7cf3f20, which has the same code as main 06b280b, a cold
  `make test` (ct, firmware, all 94 integration cases) took **2517 s**
  (42 min), rc 0.
- **Projection.** M8 adds about 40 boots: C13's 12 rows (some two-boot),
  C6, C8, the C10 capture, and the bundle-sourced re-runs of existing
  groups. At about 25 s a boot that is +17 min, so about 1 h.
- That is under the 3 h pass line, inside `CASE_TIMEOUT_S` (4 h) for
  `integration-count`.

## Slice 1

### D-1 — the Kani re-proof starts at slice 1, not slice 3

- The plan says the PD lockfile changes once, in slice 3, and that the
  ~13 h re-proof begins there. But `tools/kani-gate.sh:57` keys every
  cached proof on the root `Cargo.toml` and `Cargo.lock`. Adding
  `policy-wire` to the workspace in slice 1 already changes both, and so
  do `release-seq`, `audit-core`, `auditkey-core` and the new PDs.
- Decision:
  - During slices 1–5, new or changed crates are proved directly with
    `cargo kani -p <crate>`, one job at a time and capped at 40g.
  - `make kani` (the cached gate) runs once, after the last workspace
    change in slice 5, split across gx10 (head) and z1mn (tail).
  - Nothing is lost: until that run the existing crates' proofs are
    unchanged sources under a new key.

### D-2 — `parse` needs the `verifier` feature (C1, I1.2)

- The first `policy-wire` made `parse` public. A consumer PD could then
  build a `Bundle` without the `policy` PD's token, which C1 rules out.
- `parse` is now compiled only with the feature `verifier` (or under test
  or Kani), and `open` reaches the same parser through a private
  function. check-pins P27 lets only `crates/pds/policy` and
  `tools/policy` enable the feature.
- A `compile_fail` doctest shows a consumer cannot call `parse`, and a
  `no_run` doctest shows `open` compiles. Red-proof: built with
  `--features verifier`, the compile-fail doctest fails ("compiled
  successfully").

### D-3 — I1.1 is proved by step lemmas, not over the whole slot

- One harness over a whole slot at a small key length timed out after
  30 min with no verdict: a symbolic buffer of about 3.5 KiB, most of it
  the fixed signatures, under nested loops.
- The loop bodies are now `walk_peer` and `walk_group`, extracted without
  any behaviour change (65 unit tests unchanged).
  - Each step is proved on a small symbolic buffer from an arbitrary
    start: `Ok ⇒ start < next ≤ len`, with a `kani::cover!` that `Ok` is
    reachable.
  - The two loops (≤ `MAX_PEERS`, ≤ `MAX_GROUPS` iterations) compose the
    steps by induction.
  - The crate's lints (`indexing_slicing`, `unwrap_used`,
    `arithmetic_side_effects`, `panic` denied) rule out a panic.
  - M6 used the same shape for `http-wire` (RM6-11).
- All seven `policy-wire` harnesses verify: the two steps, three
  `select` harnesses plus their reachability harness, and the init
  machine. Every `cover!` is satisfied.
- **Red-proofs**, run on a scratch copy outside the tree:
  - `walk_peer` returning `pos + 1` makes the peer-step harness fail.
  - An ADVANCE check mutated to accept any value first stayed green.
    I5.1 asserted the machine's own `current + 1` rather than the
    TPM's reply. The property now asserts the reply itself, and the same
    mutant now fails.

### D-4 — the genesis-roster pin is compiled in, not a flag (C2, D11)

- The delegated `tools/policy` had `--pinned <file>`, which let whoever
  runs the tool replace the genesis-roster pin. That is the single-insider
  re-genesis S15 closed.
- The pin is now compiled in: `tools/policy/genesis-roster.sha256`, which
  ships all zeros, so every command fails closed until a fleet's genesis
  ceremony (C12). A build-time `KOZANE_POLICY_GENESIS_PIN` replaces it,
  and the tool tests use that. They now also assert that the unpinned
  build refuses a genesis roster.
- Four fixtures were red for the wrong reason, and now assert their own
  refusal:
  - **Restore bound to another fleet.** Both fixture contexts shared one
    fleet ID, and the fixture passed only because their rosters differed.
    It now uses a second fleet, and the restore check compares `fleet_id`
    before the head digest so the fleet binding is the one observed.
  - **Wrong approval domain (bundle and restore).** Both are refused by
    their record kind (disjoint key sets). Signature-domain separation is
    covered by `tools/policy`'s unit tests.
  - **"Second body for a signed version".** At `sign` it is the
    `version == head + 1` refusal; with that rule the separate check
    cannot be reached through `sign`.
- check-pins P28 matches the bypass flags only as quoted literals, and
  skips comment lines, because the tool's docs name them.

## Slice 2

### D-5 — five descriptor ranges now, the sixth with `auditkey` (C4)

- C4's sixth range is the audit envelope, and the `auditkey` PD that owns
  it lands in slice 5. Slice 2 builds descriptor v3 with five ranges (the
  three envelopes and the two slots), and slice 5 adds the sixth with its
  pair cases.
- Anti-Deferral: a sixth range sealed now would be a placeholder with no
  owner and no test that can fail. The cost is one more descriptor
  revision inside M8, and v3 is not released before M8 ends.

### D-6 — the cap waits for `policy` only once `policy` exists (C3)

- With the cap waiting on `policy_finished`, today's image, which has no
  `policy` PD, would never cap, and every key PD would time out.
- `layout::tpm::POLICY_PRESENT` gates that term. Slice 3 sets it to true
  in the same commit that adds the PD, and a laws/layout test ties the
  constant to the `.system` file.
- Kani I3.1 is proved for both values.

### D-7 — provisioning's TPM Clear ends the "same SRK twice" check

- `run.py`'s `read_srk` provisions a copy of the state a second time and
  requires the same SRK. With TPM2_Clear first (D5), the storage seed is
  fresh each time, so the two SRKs differ by design.
- That check becomes: the second provisioning's SRK differs from the
  first. That is S18's "the SRK Name changed", now asserted on every
  provisioning.

### D-8 — C3's forbidden pattern is scoped (check-pins P29)

- The plan's literal pattern `NV_?(UNDEFINE|WRITE|DEFINE)|Clear\b` over
  `crates/` would match three things:
  - the refused-set constants the gate needs (I3.2 lists them);
  - the attribute names `NV_WRITTEN`/`NV_WRITELOCKED`;
  - a comment ("Clear that stack").
- P29 matches the command-code constants `CC_NV_{UNDEFINE_SPACE[_SPECIAL],
  WRITE[_LOCK], DEFINE_SPACE}`, `CC_CLEAR` and `CC_HIERARCHY_CHANGE_AUTH`.
  They are allowed only where they are defined, in the gate's refused set,
  in that crate's tests and proofs, and in `crates/tpm2/tests` (the swtpm
  interop tests drive swtpm directly).
- It remains a tripwire. The control is the gate's per-client allowlist,
  proved by Kani I3.2.

### D-9 — slot ranges are exactly `BUNDLE_MAX`

- The delegated boot.cmd and measure.py accepted any slot length up to
  `BUNDLE_MAX`. U-Boot hashes the whole load slot for PCR 9, so a shorter
  range would copy fewer bytes than it measures.
- Both now require `len == BUNDLE_MAX`, as C1's "slot media is always
  exactly `BUNDLE_MAX`" does. test_measure has the shorter and longer
  denies, and its boot.cmd line check expects `-ne` for slots.

### D-10 — the slot MRs and the `bundle_slot` laws kind land in slice 2

- `tools/package` can only emit descriptor v3 when the system file has
  the slot MRs. The laws refused them (L2: prefill only on secrets MRs;
  L4: an MR not in the policy).
- So the slot-MR part of C11 moved up from slice 3:
  - the MR kind `bundle_slot` (prefill allowed, never mapped `w`/`x`,
    readers listed);
  - both slots declared with `readers = []` and mapped into no PD.
- Slice 3 adds `policy` and the barrier PDs as readers.

### Note — a delegated agent used `git stash` briefly

- During slice 2, the Rust batch ran `git stash` / `git stash pop` once
  while the provisioning batch was editing `tools/` and `tests/`. The
  stash list is empty, and every file both batches reported is present.
- The gates for this slice re-run every suite on the final tree.
