# Plan Review: kozane-m7-qemu-platform
Date: 2026-10-27
Review round: 1

## Changes from Previous Round

Initial review of plan v1, after a local-LLM pre-screen. The pre-screen
found three issues, all fixed in v1:

- I6.1 contradicted I6.2. The fix keeps a fingerprint of the previous
  block, not the block.
- A fixture was missing for an rng channel from a PD outside the member
  set.
- The `neoverse-n2` pattern's scope was too narrow.

The local merge helper did not return in time, so deduplication was done
by hand (Step 1-5 fallback). The prefixes are FN (functionality), SE
(security) and TE (testing). Where several experts raised one root cause,
the most complete one is kept and the others are cross-listed.

Plan v2 resolves every finding below. The rest of this section lists
each one with its resolution.

## Functionality Findings

- **FN1 Critical, design, R38/R13. Fixed (D4, C8, C9).**
  - Problem: deterministic boot-time halts become an endless reset loop.
    Cross-listed with SE9.
  - Resolution: two classes of stop. A boot stop is raised only through
    the `Init` context, which rustc keeps from escaping `init`. It is
    recorded and the PD stays stopped. Every other fault resets.
  - Scenarios 2 and 3 and the M6 "tls halted, VPN handshakes" case are
    re-asserted with the boot-stop record. That last case is no longer
    inverted.
- **FN2 Major, design, R29/R48. Fixed (C2, C3, C11).**
  - Problem: the measure variant's BL33 differs from the shipped one, so
    the release PCR 0 is never observed. Cross-listed with TE1.
  - Resolution: two firmware images. PCR 0–8 are read host-side from
    swtpm after the shipped boot.
- **FN3 Major, design, R41/R38. Fixed (D2, I6.1).**
  - Problem: `VirtIORng::request_entropy` spins without bound inside a
    PPC. Cross-listed with SE7.
  - Resolution: reuse the transport and the queue, and poll against a
    CNTPCT deadline that returns `Unavailable`. The deadline is the
    boundary.
- **FN4 Major, design, R2/R16. Fixed (C6, C10, P1).**
  - Problem: the rng bus was not pinned.
  - Resolution: `virtio-mmio-bus.0`, on page 0x0a000000. The NICs' legacy
    or modern default is unchanged. There is an L5 fixture for an rng MR
    on a NIC page.
- **FN5 Major, design, R40/R3. Fixed (C4).**
  - Problem: one constant has three jobs, and consumers were missing.
  - Resolution: the policy selection and the cap-read selection are split
    and asserted to be a subset. Every consumer is listed, including
    `mksecrets seal`/`check-envelope`, `pcr8` → `pcrs`, `release.py` and
    `PCR_READ_8`.
- **FN6 Major, design, R52/R50. Fixed (C10).**
  - Problem: the laws parser reads only the root's children.
  - Resolution: a recursive parse, a count of parsed PDs that refuses on
    a mismatch, and one existing deny fixture per law re-run under
    nesting.
- **FN7 Major, design, R3/R20. Fixed (Testing strategy, bookkeeping).**
  - Problem: existing self-test injections target text this plan
    rewrites. Cross-listed with TE16.
  - Resolution: re-targeting them is a slice obligation, each re-target is
    proven red, and an injection whose needle text is absent is an error.
- **FN8 Major, design, R47/R50. Fixed (C2 I2.1).**
  - Problem: the `-bios` pattern matched nothing. Cross-listed with TE11.
  - Resolution: one argv builder asserts the firmware image. `make run`
    uses the firmware, so there is no unmeasured dev path. Today's tree
    must go red.
- **FN9 Major, R29. Fixed (C11).**
  - Problem: the C11 order was wrong, there were no PD hashes, and
    `flash.bin` was not shipped.
  - Resolution: provision, package, release, verify, boot.
    `loader_img_sha256` binds the PDs, and `flash.bin` is in the manifest.
- **FN10 Minor, R42. Fixed (C7 member set).**
  - Problem: the indirect members were incomplete.
  - Resolution: a hardware-trait grep was added, and the hs-core,
    rosenpass-core, tlskey-core and tpm2 members are listed.
- **FN11 Minor, R29. Fixed.**
  - Problem: three wrong claims: `firmware_outputs` (there is no such
    variable; the set is `tools/repro`'s list), the PD count (16 PDs and
    15 children with `rng`), and the generated table (it is
    `crates/layout` plus its test).
  - Resolution: each claim is corrected.
- **FN12 Minor, question. Fixed (P2).**
  - Problem: the DTB measurement, PCR 1–7 and the event-log location
    were unknown.
  - Resolution: P2 records all three.
- **FN13 Minor, prose. Fixed (I3.1, intro).**
  - Problem: I3.1 claimed PCR 0 covered more than it does, and "C8" was
    ambiguous.
  - Resolution: I3.1 is scoped to FIP entries, and the intro names "M5
    C8".
- **FN-A1 Minor, Adjacent. Fixed (C4).**
  - Problem: the M5-envelope deny is refused by the envelope parser,
    before the TPM sees it.
  - Resolution: it is stated as a parser refusal. The TPM-level deny is
    the injected PCR 3 extend (TE4).

## Security Findings

Observed sound in round 1:

- D1 (direct extend) is the right choice.
- No stage after BL1 can forge PCR 0.
- U-Boot's environment is `ENV_IS_NOWHERE`.
- The sealed object is `noDA` (`crates/tpm2-wire/src/lib.rs:102`), so
  resets cannot cause a dictionary-attack lockout.

The findings:

- **SE1 Major, design, R47/R49. Fixed (C8).**
  - Problem: the TCB/SMC denylist could be evaded by rust-sel4 spellings:
    `.tcb()`, `tcb_*` and `Cap::from_bits`. `microkit_arm_smc_call` is the
    C API.
  - Resolution: an allowlist over `use` paths. `unsafe`,
    `Cap::from_bits`, TCB use and the SMC invocation are allowed only in
    the reset module, with one function ID. There is a deny fixture per
    evading spelling, and an unparseable crate is a refusal. The control
    is declared a best-effort tripwire with its known bypasses (RM7-5).
    P3 records the rust-sel4 API names.
- **SE2 Major, design, R49, Adjacent. Fixed (C3).**
  - Problem: the mutation did not prove BL1's extend, and there was no
    BL2 deny. Cross-listed with TE2.
  - Resolution: a deny case per stage, including a BL2 without its own
    extends, and a mutation per extend. The control class now says BL1's
    extend of BL2 is the boundary, and BL2's extends are measured, not
    trusted.
- **SE3 Major, design, R42. Fixed (P2, I3.1, C4 twin).**
  - Problem: the measured set was open-ended, so unmeasured configs could
    steer BL1 or BL2.
  - Resolution: P2 enumerates the consumed ToC entries. I3.1 covers
    images and configs before they are consumed. The twin refuses unknown
    entries, and there is a config-byte deny.
- **SE4 Major, design, crypto. Fixed (C7 construction).**
  - Problem: the DRBG construction and the reseed combine were not
    locked.
  - Resolution: draw, next-key, reseed and instantiate are locked. Reseed
    combines with the old K and never assigns it. Kani covers the
    properties.
- **SE5 Major, design. Fixed (C7 instantiate, RM7-2).**
  - Problem: the tainted PDs would lose the hedge from their key PD's
    boot seed.
  - Resolution: `hs`, `pq` and `tls` instantiate from their key-PD boot
    seed combined with the rng seed. `ingress` has no hedge, and that is
    named and accepted (its cookie secrets rotate). There is a unit test
    of that construction.
- **SE6 Major, design, R51. Fixed (C5 flow).**
  - Problem: the SRK was bound by name rather than by the bytes recorded.
  - Resolution: read the public once, check its attributes, compute the
    name host-side, MakeCredential to the certificate's EK, activate, then
    record the same bytes atomically. There are denies for fixedTPM clear
    and for a second swtpm.
- **SE7 Minor. Fixed (I6.1, I6.3).**
  - Problem: no completion deadline, and the quota key was not stated.
  - Resolution: the deadline returns `Unavailable`. The quota is keyed by
    channel id and charged before the device is touched.
- **SE8 Minor. Fixed (I3.2).**
  - Problem: a non-success Startup, `TPM_RC_INITIALIZE` included, was not
    a stop.
  - Resolution: any non-success Startup now stops the boot.
- **SE9 Minor, Adjacent.** Merged into FN1.
- **SE10 Minor, prose, R49. Fixed (C9 class, I8.1).**
  - Problem: the control classes claimed too much.
  - Resolution: C9 is a code property, with RM7-3 for spins. I8.1's
    dependence on `timer` is stated.
- **SE11 Minor, prose. Fixed (RM7-10).**
  - Problem: the dev EK CA had no residual.
  - Resolution: RM7-10 records it.

## Testing Findings

- **TE1 Major.** Merged into FN2.
- **TE2 Major.** Merged into SE2. The C3 deny cases cover BL2, BL31, BL33
  and the configs, each with its own mutation.
- **TE3 Major, design, RT8/RT4. Fixed (C3).**
  - Problem: I3.2 had one error path and an absence oracle.
  - Resolution: one case per path (startup, BL1 extend, BL2 extend),
    selected by command ordinal. The terminal is observable: a fixed TF-A
    line plus QMP `guest-shutdown`. Each has an allow pair.
- **TE4 Major, design, RT7. Fixed (C4).**
  - Problem: nothing could fail on PCR 1–7.
  - Resolution: an independent digest from `tpm2_policypcr`, and a deny
    in which the proxy injects a PCR 3 extend.
- **TE5 Major, design, RT4/RT8. Fixed (C11 harness change).**
  - Problem: a reset could hide a fault in an existing case.
  - Resolution: `-no-reboot` and QMP by default. An unexpected `SHUTDOWN`
    fails the case. There is a red-proof with the fault-inject image.
- **TE6 Major, design, RT2. Fixed (C6).**
  - Problem: the no-device oracle contradicted D4.
  - Resolution: post-slice-5 and interim oracles are stated. With D4 v2 a
    boot stop does not reset, so the oracle is the positive boot-stop
    records.
- **TE7 Major, design. Fixed (C8).**
  - Problem: the audit needle asserted a best-effort property, and the
    mutation relied on a wall clock.
  - Resolution: the audit needle gates only in the preemption ordering.
    The resume mutation is detected by positive evidence. The wall-clock
    bound is a hang guard only.
- **TE8 Major, design, RT2. Fixed (C8 variant).**
  - Problem: the `audit`/`timer` exception had no trigger.
  - Resolution: `fault-inject` triggers on `audit` and `timer` at boot.
- **TE9 Major. Fixed (C6 acceptance).**
  - Problem: I6.3 had no test.
  - Resolution: quota unit tests with the boundary, and non-starvation of
    a `key`-role caller.
- **TE10 Major, design, RT10. Fixed (C10 acceptance).**
  - Problem: fixtures were missing.
  - Resolution: priority, cardinality, tainted callers without `pp`,
    second device, supervisor PPC, device and `rw` record page.
- **TE11 Major, design, RT7. Fixed (Contracts preamble, C2, C3, C7, C8).**
  - Problem: the forbidden patterns named no enforcing gate.
  - Resolution: each pattern names its gate and has deny and allow
    fixtures. Absence-style rules are positive checks that refuse a
    missing input.
- **TE12 Major, design, RT7/RT5. Fixed (C8 variant, C9 link check).**
  - Problem: the fault-inject release refusal and the C9 hook link had no
    red-proof.
  - Resolution: a release-with-fault-inject injection must fail. An ELF
    rule requires the hook symbol, red-proved by one PD without it.
- **TE13 Major, design, RT11. Fixed (C5 isolation).**
  - Problem: the provisioning fixtures could leak state.
  - Resolution: one per-run directory, removed in `finally`. A directory
    that survives fails the case.
- **TE14 Minor. Fixed (C11).**
  - Problem: the boot might not use the verified bytes.
  - Resolution: the sha256 of the `-bios` and loader files must equal the
    verified manifest.
- **TE15 Minor. Fixed (C7 mutation).**
  - Problem: the planted RNDR call would not compile.
  - Resolution: plant the raw encoding instead, in slice 5.
- **TE16 Minor.** Merged into FN7. The counters are enumerated.
- **TE17 Minor. Fixed (P6).**
  - Problem: the boot and line timeouts were not re-derived.
  - Resolution: P6 re-derives them.
- **TE18 Minor, question. Fixed (P2, walkthrough).**
  - Problem: the event-log location was unknown.
  - Resolution: P2 records it, and `run.py` reads it there.
- **TE19 Minor. Fixed (I7.2).**
  - Problem: the `RESEED_DRAWS` boundary was not stated.
  - Resolution: draws 0..N−1 succeed, and draw N needs a successful
    reseed first.

## Adjacent Findings

- SE2 (Security → Testing): merged with TE2. It is resolved in C3.
- SE9 (Security → Functionality): merged with FN1. It is resolved in D4.
- FN-A1 (Functionality → Testing): resolved in C4.

## Quality Warnings

The merge helper finished after the manual merge. It flagged one item:
the FN12/TE18 event-log and DTB questions were marked `[VAGUE]` because
they were posed as questions. They were not sent back to the experts: they
are Minor questions by the Finding Floor, and the plan resolves them by
making P2 record the answers. The helper's dedup agreed with the manual
merge.

## Recurring Issue Check

### Functionality expert

| Rule | Status |
|---|---|
| R1 | F3 (the D2 reuse is right, but the API chosen is wrong); otherwise OK |
| R2 | F4 (the bus number is missing in three QEMU command lines) |
| R3 | F5, F7 |
| R4–R12 | N/A |
| R13 | F1 (reset loop) |
| R14, R15 | N/A |
| R16 | F4, F8 (`make run` parity) |
| R17–R19 | N/A |
| R20 | F7 |
| R21–R28 | N/A |
| R29 | F2, F9, F11 |
| R30, R31 | N/A |
| R32 | Covered by C11 |
| R33 | N/A |
| R34 | F1 (the M6 tls-halt case is inverted and not listed) |
| R35–R37 | N/A |
| R38 | F1, F3 |
| R39 | No issue in scope; I6.2 covers it |
| R40 | F5 |
| R41 | F3 |
| R42 | F10; the C7 and C8 greps were re-run and confirmed (7 PDs, 14 PDs) |
| R43–R46 | N/A |
| R47 | F8 |
| R48 | F2 |
| R49 | No issue; classes are declared |
| R50 | F6, F8, F12 |
| R51 | N/A |
| R52 | F6 |
| R53 | Covered by P6 |
| R54–R57 | N/A |

### Security expert

| Rule | Status |
|---|---|
| R1 | Checked: D2 reuses virtio-drivers; no issue |
| R2 | Checked: I4.2 gives the selection one source; no issue |
| R3 | Checked: the RNDR removal propagates through the C7 member set; no issue |
| R4–R16 | N/A |
| R17 | Checked: the shared DRBG crate's adoption is covered by the C7 member set; no issue |
| R18 | Checked: L4's `smc` and child allowlist applies only to the supervisor; no issue |
| R19–R21 | N/A |
| R22 | Checked; no issue |
| R23, R24 | N/A |
| R25 | Checked: the re-seal covers old envelopes; no issue |
| R26–R28 | N/A |
| R29 | Checked: the rust-sel4 API citation is wrong (`microkit_arm_smc_call` is the C API) → F1 |
| R30, R31 | N/A |
| R32 | Checked: C11 readiness lines; no issue |
| R33 | N/A (no CI) |
| R34 | Checked: the `hs` halt interacts with the reset policy → F9 |
| R35 | Checked: C11 is the operator flow; no issue |
| R36, R37 | N/A |
| R38 | Checked: the reset loop is a wedge → F9 |
| R39 | Checked: I6.2 zeroization holds; the caller-side IPC-buffer zeroization is not stated (folded into F7; low) |
| R40 | Checked: the `Seed` reply shape is fixed; no issue |
| R41 | Checked: the SMC path names no Rust backing → F1 |
| R42 | F3 (the measured set) and F5 (the hedge's consumers) |
| R43 | Checked: tainted callers' reach to `rng` is bounded by the C10 L1 shape; no issue |
| R44–R46 | N/A |
| R47 | F1 |
| R48 | Checked: C3's allow case pins the twin against the TPM; no issue |
| R49 | F2, F10 |
| R50 | Checked: P1–P6 have refutation paths; no issue |
| R51 | F6 |
| R52 | Checked: the L1 exemption is reshaped for `key`→`rng`; no issue |
| R53 | Checked: P6 re-measures the budgets; no issue |
| R54 | N/A |
| R55 | Checked: the all-zero and repeated-block checks are not sentinels; no issue |
| R56, R57 | N/A |
| RS1 | Checked: the C5 secret comparison is host-side and the value is not secret after activation; no issue |
| RS2 | Checked: I6.3 quota → F7 (its key) |
| RS3 | Checked: I6.4 bounds the device lengths; no issue |
| RS4 | Checked: the dev CA key in `support/keys` → F11 |
| RS5 | Checked: the EK CA is pinned; no issue |
| RS6 | N/A |

### Testing expert

| Rule | Status |
|---|---|
| R1 | Checked: D2 reuses virtio-drivers; no issue |
| R2 | Checked: I4.2 covers the selection constant; no issue |
| R3 | Checked → F11 (the pattern scope does not reach the new files) |
| R4 | N/A: no event dispatch |
| R5, R6 | N/A |
| R7 | N/A: no E2E selectors |
| R8–R11 | N/A |
| R12 | Checked: the C8 label/child enum is Kani-exhaustive; no issue |
| R13–R15 | N/A |
| R16 | N/A: no CI |
| R17 | Checked → F12 (that every PD links the hook is unproven) |
| R18 | Checked → F10 (C10 exemption fixtures) |
| R19 | N/A: no mocks |
| R20 | N/A |
| R21 | N/A: plan stage |
| R22–R24 | N/A |
| R25 | Checked: the re-seal and the stale-envelope deny are present (C4) |
| R26–R28 | N/A |
| R29 | Checked: the measure-variant claim contradicts the Makefile build (F1) |
| R30, R31 | N/A |
| R32 | Checked: C11 boots the release; F14 |
| R33 | N/A |
| R34 | Checked; no issue |
| R35 | N/A: no deployment |
| R36 | Checked: no suppression |
| R37 | N/A |
| R38 | Checked: the I3.2 fail-closed terminal is unobservable (F3) |
| R39 | Checked: I6.2 zeroization has no stated test; outside testing scope (Minor, not raised) |
| R40 | N/A |
| R41 | Checked: F8 (a declared exception path with no trigger) |
| R42 | Checked: the C7 and C8 member sets are derived by command |
| R43 | N/A |
| R44 | Checked; no issue |
| R45, R46 | N/A |
| R47 | Checked: F11 (`smc_call` scoping) |
| R48 | Checked: F1 (twin–TPM agreement unpinned for the release) |
| R49 | Checked; no issue |
| R50 | Checked: F11, F13 (refuse when an input is absent) |
| R51 | Checked: F14 |
| R52 | Checked: F10 |
| R53 | Checked: P6, plus F17 |
| R54–R56 | N/A |
| R57 | Checked: F9, F19 (boundaries) |
| RT1 | Checked: the proxy is a real swtpm with an injected failure; no issue |
| RT2 | Checked: F6, F8, F18 |
| RT3 | Checked: I4.2 shares the selection constant |
| RT4 | Checked: F3, F5 |
| RT5 | Checked: F1, F12, F14 |
| RT6 | Checked: the new crates have tests |
| RT7 | Checked: F2, F4, F11, F12, F15 |
| RT8 | Checked: F3 |
| RT9 | Checked: F1 (the variant twin) |
| RT10 | Checked: F2, F10 |
| RT11 | Checked: F13 |

(The expert-local IDs F1… in these blocks are the experts' own. They map
to the FN, SE and TE prefixes above.)

---

# Review round 2 (incremental, plan v2 → v3)

Date: 2026-10-27

The three experts verified the round-1 fixes. Most are confirmed. FN1,
FN5, FN8, FN9, SE1, SE2, SE7, TE2, TE3, TE4 and TE5 were incomplete or
introduced new defects, and those are listed below under the prefix R2.
Every finding below is labelled design by its expert and resolved in plan
v3.

## Functionality (R2 FN-N*)

- **N1, Critical, R38/R41.**
  - Problem: a boot stop in a PPC callee (`rng`, `key`, `pqkey`,
    `tlskey`) leaves its callers blocked forever.
  - Resolution (D4, C6, C9): only leaf PDs boot-stop. Callees stay up and
    answer `Unavailable`. The link check keeps the boot-stop symbol out of
    callee, `audit` and `timer` ELFs, and the supervisor treats a non-leaf
    boot stop as a fault.
- **N2, Major, R38/R40.**
  - Problem: key PDs need randomness for the unseal salt before the blob
    seed exists.
  - Resolution (C7): two-phase instantiation. K0 comes from the rng seed
    and serves only the salt. Then K = PRF(blob_seed, "init" ‖ K0).
- **N3, Major, R49.**
  - Problem: the `Init` boundary depended on constructor reachability, not
    only on the lifetime.
  - Resolution (C9): a private constructor, no Clone, Copy or Default, a
    one-shot entry wrapper, and compile-fail doctests with error codes for
    both escape and construction.
- **N4, Minor.**
  - Problem: the package had no firmware input and no `flash.bin` output.
  - Resolution (C4 consumers): both added, and a mismatch is refused.
- **N5, Minor.**
  - Problem: `make run` needs a swtpm.
  - Resolution (C2 I2.1): the argv builder starts one.
- **N6, Minor.**
  - Problem: the boot-stop sets omitted `pq`.
  - Resolution (C11, scenarios): exact sets.
- **NA1, Adjacent.**
  - Problem: the boot-stop class is self-declared.
  - Resolution (D4): equivalence to a spin is stated (RM7-3). See SE-N3.

## Security (R2 SE-N*)

- **N1, Major, R49, Adjacent.**
  - Problem: the C3 BL2 deny did not forge, and the mutations were not
    consistent drops. Same root cause as TE-N1.
  - Resolution (C3): the deny is a forging BL2. Each mutation drops the
    stage from the patch and from the twin's closed list, then re-seals,
    and each mutation reddens its own deny.
- **N2, Minor, R47.**
  - Problem: the allowlist checked only `use` items.
  - Resolution (C8): every path node is checked by a path-aware parser.
    The `tcb_*` family, `from_cptr` and `CPtr` are confined to the reset
    module, and a fully-qualified-path fixture is added.
- **N3, Minor, R49.**
  - Problem: boot-stop class abuse, the source of the reason, and which
    children are eligible.
  - Resolution (D4, C8, C9): the reason is decoded from the `brk`
    immediate through a closed enum, and an unknown immediate is a fault.
    The leaf list is in place, Kani covers it, and the immediate is
    emitted only in the `Init` crate.
- **N4, Minor.**
  - Problem: a late rng completion.
  - Resolution (C6 I6.5): completions match by token, a stale completion
    is discarded, and a descriptor is not reused until it is reclaimed.
    There is a unit test.
- **N5, Minor, Adjacent.**
  - Problem: a transient seed failure became a permanent stop, and
    records could be lost.
  - Resolution (D4, C7, C8): `RNG_INIT_TRIES` retries, and the record page
    is a ring with an overflow count.
- **N6, Minor, R29.**
  - Problem: the DRBG encoding, and the rationale for `ingress`.
  - Resolution (C7): one block per `ctr`, u64 LE fields, the `ingress` K
    is stated, and the justification is by impact.
- **N7, Minor.**
  - Problem: the QMP socket.
  - Resolution (C11): a 0700 UNIX socket in the per-run directory, removed
    in `finally`.
- Answered in round 2: the DRBG construction is sound, reading the
  syndrome adds no meaningful surface, and every one of the 25 halt sites
  is safe left up.

## Testing (R2 TE-N*)

- **N1, Major, RT7.**
  - Problem: the stage mutations did not redden their denies. Merged with
    SE-N1.
- **N2, Major, RT8/RT7.**
  - Problem: a PCR 3 injection after PolicyPCR is refused through
    pcrUpdateCounter, whatever the selection.
  - Resolution (C4): inject before PolicyPCR, assert the policy-failure
    code, and red-prove by dropping PCR 3 from the selection and the twin.
- **N3, Major, RT10/R3.**
  - Problem: `-no-reboot` as the default breaks S11 and the REFUSE and
    measure poweroffs.
  - Resolution (C11): each case declares its expected SHUTDOWN reasons.
    S11 is the second opt-out. A REFUSE case that gets `guest-reset` is
    the red-proof.
- **N4, Major, RT4.**
  - Problem: a QMP connect race, and EOF without an event.
  - Resolution (C11): `-S`, then `cont` after capabilities. EOF without
    SHUTDOWN is a named failure, red-proved by a kill.
- **N5, Major, RT7/RT2.**
  - Problem: a compile-fail test in `pdkit` would never run.
  - Resolution (C9): `Init` moves to a host crate. The doctests carry
    error codes, there is an allow doctest, and both are counted.
- **N6, Major, RT8.**
  - Problem: selecting by ordinal can hit the wrong stage.
  - Resolution (C3): select by code and occurrence, assert the code and
    the preceding success, and put a stage token in the error line.
- **N7, Major, RT8.**
  - Problem: the boot-stop set was not enumerated.
  - Resolution (C6, C11): exact sets. A missing or an extra record fails
    the case.
- **N8, Minor.**
  - Problem: the resume mutation's form.
  - Resolution (C8): the record write is kept, and only the reset is
    replaced.
- **N9, Minor.**
  - Problem: the "no record" check is an absence.
  - Resolution (C11): the whole log is checked after serving, with
    Inject A as the positive pair.

## Recurring Issue Check (round 2)

### Functionality expert

| Rule | Status |
|---|---|
| R1 | Reuse resolved (D2 now uses the transport and queue) |
| R2 | Resolved (bus 0 pinned) |
| R3 | Resolved for the selftest injections |
| R4–R12 | N/A |
| R13 | Resolved (no boot loop) |
| R14, R15 | N/A |
| R16 | N5 |
| R17–R28 | N/A |
| R29 | Resolved; the claims were re-verified |
| R30, R31 | N/A |
| R32 | Covered by C11 |
| R33 | N/A |
| R34 | Resolved (the M6 case is re-asserted) |
| R35–R37 | N/A |
| R38 | N1, N2 |
| R39 | Unchanged (I6.2) |
| R40 | N2, N4 |
| R41 | N1 |
| R42 | N6. The C7 and C9 member sets were re-verified (7 PDs; 25 sites) |
| R43–R46 | N/A |
| R47 | Resolved (argv builder) |
| R48 | Resolved |
| R49 | N3 |
| R50 | Resolved (the PD-count refusal) |
| R51 | N/A |
| R52 | Resolved |
| R53 | Unchanged (P6) |
| R54–R57 | N/A |

### Security expert

| Rule | Status |
|---|---|
| R1, R2 | Unchanged from round 1 |
| R3 | Checked: no issue |
| R4–R16 | N/A |
| R17 | Checked: adoption of the `Init` helper → N3 |
| R18 | Checked: the supervisor allowlist → N2 |
| R19–R28 | N/A, or unchanged |
| R29 | N6 |
| R30, R31 | N/A |
| R32 | Unchanged |
| R33 | N/A |
| R34 | Checked: the halt sites were reviewed; no issue |
| R35 | Unchanged |
| R36, R37 | N/A |
| R38 | Checked: a transient cause becomes a terminal stop → N5 |
| R39 | Checked: I6.2 holds; the late DMA write → N4 |
| R40 | Checked: no issue |
| R41 | Checked: D2 avoids the spinning API; no issue |
| R42 | Checked: the C7 member set was re-derived; no issue |
| R43 | Checked: the `rng` caller set is fixed by C10; no issue |
| R44–R46 | N/A |
| R47 | N2 |
| R48 | Checked: the twin against the TPM; the mutations need consistent drops → N1 |
| R49 | N1, N3 |
| R50 | Checked: the refusals are named; no issue |
| R51 | Checked: SE6 is fixed |
| R52, R53 | Unchanged |
| R54 | N/A |
| R55 | Checked: no issue |
| R56, R57 | N/A |
| RS1 | Unchanged |
| RS2 | Checked: the quota is keyed by channel id; no issue |
| RS3 | Checked: the syndrome goes through a closed enum → N3 |
| RS4 | Checked: RM7-10 |
| RS5 | Unchanged |
| RS6 | N/A |

### Testing expert

| Rule | Status |
|---|---|
| R1, R2 | Unchanged from round 1 |
| R3 | N3 (the change to the harness default reaches the existing cases) |
| R4–R28 | Unchanged from round 1 |
| R29 | Checked: the run.py and Makefile claims were verified (`system_reset`, `HALT`, `host_crates`) |
| R30, R31 | Unchanged from round 1 |
| R32 | Checked: C11 boots the verified bytes |
| R33–R37 | Unchanged from round 1 |
| R38 | Checked: the I3.2 terminal is observable; the race is noted in N4 |
| R39, R40 | Unchanged from round 1 |
| R41 | Checked: the triggers are defined |
| R42 | Checked: N7 |
| R43–R46 | Unchanged from round 1 |
| R47 | Checked: the C8 allowlist; no issue |
| R48 | Checked: fixed by FN2 |
| R49 | Unchanged from round 1 |
| R50 | Checked: N4 (EOF without an event) |
| R51 | Checked: TE14 is fixed |
| R52 | Checked: the laws re-run under nesting; no issue |
| R53 | Checked: P6 covers the timeouts |
| R54–R56 | Unchanged from round 1 |
| R57 | Checked: the RESEED and deadline boundaries are stated |
| RT1 | Checked: the proxy's model of PolicyPCR is wrong (N2) |
| RT2 | Checked: N5 |
| RT3 | Unchanged from round 1 |
| RT4 | Checked: N4 |
| RT5 | Checked: fixed by FN2 and TE14 |
| RT6 | Unchanged from round 1 |
| RT7 | Checked: N1, N2, N5, N8 |
| RT8 | Checked: N2, N6, N7, N9 |
| RT9 | Checked: the twin is mutated in step (N1) |
| RT10 | Checked: N3 |
| RT11 | Checked: TE13 is fixed |

---

# Review rounds 3 and 4 (targeted re-checks, plan v3 → v4 → final)

Date: 2026-10-27

Following the risk-tiered stopping rule, each Critical or Major finding was
re-checked by the expert who raised it, and only for that finding.

## Round 3

- **FN-R3-1, Major, R49.**
  - Problem: a private constructor in a separate crate cannot be called
    by `pdkit` alone.
  - Resolution (C9): `run_init` lives in the `Init` crate and is one-shot.
    A second call takes the generic fault path.
- **FN-R3-2, Minor.**
  - Problem: a key PD whose phase 1 fails must still send Failed to `tpm`.
  - Resolution (C7): it goes through the existing unseal entry as the
    entropy error.
- **TE-R3-1 / SE-P1, Major, RT7/R49.**
  - Problem: the BL1-drop mutation could not unseal a forger that extends
    a fixed honest chain.
  - Resolution (C3): the forger is built from the twin's closed list in
    the tree under test.
- **TE-R3-2, Minor.**
  - Problem: the opt-out cases lost reset detection.
  - Resolution (C11): they assert their QMP `RESET` events exactly.
- **TE-R3-3, Minor.**
  - Problem: the host crate's `brk`.
  - Resolution (C9): the asm is gated on `target_os = "none"`.
- **TE §3, answered.**
  - Question: which response code the PolicyPCR mismatch gives at Unseal.
  - Answer: Unseal returns 0x99D (TPM_RC_POLICY_FAIL, session 1), not
    0x9A8. The earlier commands return 0.
  - Resolution (C4): this is the asserted sequence.
- **SE-P2, Minor.**
  - Problem: RM7-2 omitted the unhedged phase-1 salt, and K0's
    zeroization was not stated.
  - Resolution (RM7-2, C7): both added.
- **Security:** no new Critical or Major. The answer to the question was
  that K0 serving the salt is acceptable, recorded under RM7-2 and RM5-5.

## Round 4

- **Testing:** R3-1, R3-2 and R3-3 are resolved, with no findings.
- **Functionality:** R3-1 and R3-2 are resolved. Two Minors remained, and
  both were fixed in the final plan:
  - **R4-1, design Minor, R49:** the one-shot must be consumed by every
    PD's `init`. Every PD now enters through `pdkit`, direct
    `#[protection_domain]` is a `check-pins` deny, and the flag also
    closes on the first handler entry.
  - **R4-2, prose:** `run_init<T>(…) -> T`.

## Outcome

- Four rounds ran. The final round left no open Critical or Major in any
  category, and the round-4 Minors were applied to the plan, so no finding
  remains open.
- Nothing is carried forward. All eleven contracts are `locked`.

## Recurring Issue Check (rounds 3–4)

| Expert | Status since round 2 |
|---|---|
| Functionality | R38 (N1, R3-2) and R40 (N2) resolved; R41 resolved; R42 re-derived from the system file (leaf list matches); R49 R3-1 resolved, R4-1 fixed in the plan. All other rules unchanged from round 2. |
| Security | R29 (P2) and R49 (P1) fixed in the plan. All other rules unchanged from round 2. |
| Testing | RT7 (R3-1), RT4 (R3-2) and RT2 (R3-3) resolved; RT1 (the proxy injection point) fixed. All other rules unchanged from round 2. |

---

# Re-plan R1 review (slice 0 probe P5)

Date: 2026-10-27

Probe P5 showed that a seL4 fault message carries no `brk`/`udf`
immediate: `brk` delivers the IP and a reason code, and for `udf` the ISS
is 0. A release-config `brk` still faults to the parent. Because the
supervisor cannot decode the stop class, a boot stop no longer faults.
Instead the PD records `Halted` and returns an init-only `Dormant`
handler, and every fault resets. Functionality and security re-checked
only this change.

- **FN-RP1, Major, R40. Fixed (C9 shape).**
  - Problem: `init` returns one concrete handler type, and 22 sites rely
    on `halt`'s `!`.
  - Resolution: `run_init<H>(… -> Result<H, Dormant>) -> Stage<H>`.
    `Stage` is a pdkit enum, and the init helpers propagate `Dormant` with
    `?`. A compile-fail doctest covers a handler path returning `Dormant`.
- **FN-RP2, Minor, prose. Fixed (C6).**
  - Problem: the `Halted` lines were attributed to the supervisor.
  - Resolution: the audit shows them, with no supervisor record.
- **FN-RP3, Minor, R42. Fixed (C6, C11, C9).**
  - Problem: the oracles needed "no supervisor record, no QMP SHUTDOWN",
    and the new halt reason codes were missing.
  - Resolution: both are added, and the reason code is `RNG_UNAVAILABLE`.
- **SE-D1, Minor, R47. Fixed (C9).**
  - Problem: a symbol-presence check can miss an inlined `boot_stop`.
  - Resolution: a `boot-stop` cargo feature that only leaf crates may
    enable (`check-pins`), `#[inline(never)]` with stable names, a check on
    the release-profile ELF, and a missing ELF or symbol table is a
    refusal.
- **SE-D2, Minor, L12/R39. Fixed (C9).**
  - Problem: the boot-stop path must drop what it holds.
  - Resolution: `Dormant` is a unit type, boot-stop sites return so drops
    run, holders of seed-derived material zeroize on drop, and a unit test
    shows `hs`'s seed reads zero after `boot_stop`.
- **Security answers:** dormant leaves keep no authority that matters, and
  dormant is better for secrets than today's abort, which never ran the
  destructors. Removing the syndrome input is a net gain.

No Critical or Major finding remains open, and C8 and C9 are `locked`
again.
