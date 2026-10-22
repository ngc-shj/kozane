# Code Review: secureos-m4-verus-mceliece
Date: 2026-10-22
Review round: 1

## Changes from Previous Round

Initial review of `be5d54a..fc683d2` (M4 after the Phase 2 self-check). Seeds
were not generated: the diff is 778 KB, beyond the local model's input, so
each expert reviewed the full diff (branch (a)).

## Functionality Findings

- **F1 Major:** the required-function check keys on the bare fn name and
  takes the max over definitions. It cannot fail for 7 of msgs' 8 `decode`s,
  nor for wg-wire's and rosenpass-wire's `parse`/`emit`.
- **F2 Major:** the trusted allowlist is a set of (crate, file, construct),
  so a second `external_body` in `msgs/src/lib.rs` passes the gate and P12.
- **F3 Major [Adjacent]:** the plan's `ct-c1-barrier` selftest is missing,
  and the omission is not recorded.
- **F4 Major [Adjacent]:** 2 of the 10 `mce-residue-<form>` cases exist.
- **F5 Major:** C8's PD stack measurement was not redone for mce460896.
  The `.system` peaks are cmr-era, and the 96 KiB scrub in `pq` is
  unmeasured.
- **F6 Minor:** pqkey-core keeps a 13.6 KB stack copy of the secret key,
  needed only by cmr.
- **F7 Minor:** the C9 pass record survives a failed `make ct`, because
  clippy and the unit tests run after ct-gate.
- **F8 Minor:** ct-shape's stop and forbidden-call checks miss alias-joined
  names.
- **F9 Minor:** the deviation log says ring's two-sided ownership is
  recorded under SC30, but the SC30 row does not name it.
- **F10 Minor [Adjacent]:** P9 over mce460896 checks nothing.
  `SECRET_TYPES` matches no type there.
- **F11 Minor [Adjacent]:** integration-test unit keys use the bare file
  stem, and `stack_probe_child` inflates UNIT-STACK.

## Security Findings

The KEM port itself was found sound: no constant-time or zeroisation defect.

- **S1 Major (escalate: false):** = F2.
- **S2 Major (escalate: false):** `cfg(verus_keep_ghost)` and `cfg!` splits
  let the shipped body differ from the verified one, undetected.
- **S3 Major (escalate: false):** the admit/assume scan covers only
  `verus! { }` bodies in `src/`. It is bypassed by `verus!( )`,
  `macro_rules!`, `#[path]` and `include!`.
- **S4 Major (escalate: false):** C10 containment covers only pd-pq and
  pd-pqkey. Another PD linking mce460896 would ship it unchecked.
- **S5 Major (escalate: false):** = F1.
- **S6 Minor:** is the TRUSTED set complete for the pinned Verus?
- **S7 Minor:** P16 ignores `.cargo/config.toml` patch/source and features.
- **S8 Minor:** package binds identity and forbidden, but not shape.
- **S9 Minor:** = F6.
- **S10 Minor [Adjacent]:** = F5.
- **S11 Minor:** the crates.io `verus_builtin_macros`/`vstd` are paired
  with the verified tarball by version only.

## Testing Findings

- **T1 Major:** = F3.
- **T2 Major:** = F4. The g, bm, ind and e-bitsliced needles were never
  red-proved.
- **T3 Major:** the `kani-chunk-ref` needle is printed for SUCCESS checks
  too, and its mutation breaks two assertions.
- **T4 Major:** = F1.
- **T5 Major:** P13's rp-vectors lock deny fixture is missing; the fixture
  tree excludes `tools/`.
- **T6 Major:** `test_ct_record.py`'s reason assertion is dead (the `any()`
  generator never tests membership).
- **T7 Minor:** the `ct-barrier` needle names no file.
- **T8 Minor:** `ct-identity` has no allow-side run.
- **T9 Minor:** = F11.
- **T10 Minor:** verus-gate's own-summary clause is never red-proved.
- **T11 Minor:** check-selftest runs have no timeout.
- **T12 Minor:** the `ct` gate's harness clippy/unit sub-steps have no
  selftest case.
- **T13 Minor [Adjacent]:** package checks that the C9 record's lines are
  present, not their values.

## Adjacent Findings

F3, F4, F10, F11 (Functionality → Testing/Security); S10 (Security →
Functionality); T13 (Testing → Security). Each is resolved under its merged
entry below.

## Quality Warnings

None. Every finding carried file:line evidence. The counts (8 decodes, 4/3
parse/emit, 64 wipes) were re-run by the orchestrator.

## Recurring Issue Check

### Functionality expert

| Rules | Result |
|---|---|
| R1 | OK |
| R2 | OK (residue SK offsets duplicated, asserted indirectly) |
| R3 | F6, F8 |
| R4–R15 | N/A |
| R16 | OK |
| R17 | OK |
| R18 | F2 |
| R19–R20 | N/A |
| R21 | F3, F4 |
| R22–R28 | N/A |
| R29 | F2, F5, F9 |
| R30–R33 | N/A |
| R34 | none |
| R35 | N/A |
| R36 | OK |
| R37–R38 | N/A |
| R39 | OK |
| R40 | N/A |
| R41 | OK |
| R42 | F1 |
| R43 | N/A |
| R44 | OK |
| R45–R46 | N/A |
| R47 | F1, F2 |
| R48 | OK |
| R49 | F2, F7 |
| R50 | OK |
| R51 | F2 |
| R52 | N/A |
| R53 | F5 |
| R54–R57 | N/A |

### Security expert

| Rules | Result |
|---|---|
| R1 | OK |
| R2 | OK |
| R3 | S4 |
| R4–R9 | N/A |
| R10 | OK |
| R11–R15 | N/A |
| R16 | OK |
| R17 | OK |
| R18 | S1 |
| R19–R20 | N/A |
| R21 | OK |
| R22–R28 | N/A |
| R29 | S11 |
| R30–R31 | N/A |
| R32 | OK |
| R33 | OK |
| R34 | N/A |
| R35 | N/A |
| R36 | OK |
| R37–R38 | N/A |
| R39 | OK |
| R40 | OK |
| R41 | OK |
| R42 | S4, S6 |
| R43 | OK |
| R44 | OK |
| R45 | OK |
| R46 | S5 |
| R47 | S2, S3 |
| R48 | OK |
| R49 | S1–S3, S5 |
| R50 | OK |
| R51 | Minor, accepted |
| R52 | OK |
| R53 | S10 |
| R54–R57 | N/A |
| RS1 | OK |
| RS2 | N/A |
| RS3 | OK |
| RS4 | OK |
| RS5 | N/A |
| RS6 | OK |

### Testing expert

| Rules | Result |
|---|---|
| R1 | N/A |
| R2 | OK |
| R3 | T4 |
| R4–R16 | N/A |
| R17 | OK |
| R18 | OK |
| R19–R20 | N/A |
| R21 | noted (the Phase 2 host_crates gap, fixed) |
| R22–R28 | N/A |
| R29 | T7 |
| R30–R32 | N/A |
| R33 | OK |
| R34–R35 | N/A |
| R36 | OK |
| R37–R41 | N/A |
| R42 | T2, T4 |
| R43 | N/A |
| R44 | OK |
| R45 | N/A |
| R46 | T4 |
| R47–R48 | N/A |
| R49 | T13 |
| R50 | T10 |
| R51–R52 | N/A |
| R53 | N/A |
| R54–R57 | N/A |
| RT1 | OK |
| RT2 | OK |
| RT3 | OK |
| RT4 | N/A |
| RT5 | OK |
| RT6 | OK |
| RT7 | T1, T2, T3, T5, T6, T10, T12 |
| RT8 | OK |
| RT9 | OK |
| RT10 | OK except P13 (T5) |
| RT11 | OK |

## Environment Verification Report

N/A: no environment constraints were declared in Phase 1 beyond the
hardware-free QEMU target. All paths below are `verified-local`, in the dev
container.

## Resolution Status

(Filled in once the round's fixes pass their gates.)
