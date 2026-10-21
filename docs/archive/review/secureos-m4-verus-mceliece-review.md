# Plan Review: secureos-m4-verus-mceliece
Date: 2026-10-21
Review round: 1

## Changes from Previous Round

Initial review of rev 1. A local LLM pre-screen ran first. It found that C7
returning rosenpass-core's `Secret` would create a crate cycle, and that the
size constants needed an owner. Both were fixed before the expert round.
Rev 2 answers every Round 1 finding.

## Functionality Findings

F1 through F20 are filed in full in the Round 1 outputs and summarised in
the resolution table below. The headline finding:

- **F1 [Critical, design]:** libmceliece is round 4, with 156-byte
  ciphertexts. The system, the wire, the blob and the peers are round 3:
  188-byte ciphertexts, `K = H(1,e,C0‖C1)`.

## Security Findings

S-1 through S-14 are summarised below. The headline finding:

- **S-1 [Critical, design, escalate: false]:** no check decides secret
  dependence on the shipped PD ELF. C9 ran on a host build, and F1 was
  exactly the case where host and PD code differ.

## Testing Findings

T1 through T17 are summarised below. The headline findings:

- **T1 [Major]:** C9 has no positive control inside a run.
- **T3 [Major]:** C10 can read a stale ELF.

## Adjacent Findings

- **F12** (functionality, tagged adjacent): C9's report filter and the
  missing declassification list. Merged with T2 and S-5.

## Quality Warnings

The merge pass flagged F19, F20 and T17 as `[VAGUE]`: each is a question
with no proposed fix. The orchestrator answered them with evidence instead
of returning them:

- **F19:** the Verus pin was resolved through the GitHub tag API. Z3 4.16.0
  is from BUILD.md at that commit, recorded in the V0 section.
- **F20:** `crates/secret-blob/src/pq.rs` documents cmr's layout as the
  round-3 spec layout with δ‖c zero, plus the liboqs mapping.
- **T17:** C9 now runs from a working directory under `build/ct`.

## Resolution (rev 2)

Findings that the experts raised from different angles are merged on root
cause. Severity takes the highest of the merged findings.

| Root cause | IDs | Severity | Resolution in rev 2 |
|---|---|---|---|
| Round 3 vs round 4 | F1 | Critical | Owner-decision row 1 refined: libmceliece `vec` decoding core, round-3 framing and keygen, liboqs 0.8 round-3 oracle; `CT_LEN` 188 |
| C9 judges a binary other than the one shipped | S-1, S-4 | Critical | C9 built with the PD's exact codegen (overflow checks included). C10(a) makes a normalised-disassembly identity check fail-closed. If identity is infeasible, stop and do not close SC23 |
| C9 decision rule | T1, T2, S-5, F12 | Major | `--error-exitcode`, no suppressions, no frame filter; a `RUNNING_ON_VALGRIND` assert; a canary; `CT-MARKED-BYTES`; a committed declassify list with `CT-DECLASSIFY`; RNG fills marked undefined; valgrind added to the image |
| C10 subject set, freshness and instruction classes | T3, S-6, S-7, F13 | Major | Symbol set derived from the ELF (path prefix plus closure into sha3/keccak); missing or extra symbols fail; runs after `pds`; `udiv`/`sdiv`/`br`/`blr` forbidden; register-offset memory ops added to the shape; `#[inline(never)]`; no write mode |
| SC23 closure binding | S-2 | Major | `tools/package` runs ct-shape (a)(b) on the packaged ELFs, with fixtures; waivers.py and waivers.toml comments updated |
| L2 overstated | S-3 | Major | L2 amended to name the basis and its residuals, rather than "lifted" |
| Zeroization unchecked | S-8 | Major | C8 residue test on a painted stack, plus the `mce-residue` selftest; caller-provided output buffers |
| Verus trusted escapes | S-9, F2 | Major | Full construct list in both spellings; allowlist compare; required-function list; vstd trusted base as R-M4 |
| Verus manifest zero rule | T4, F9 | Major | No zero-valued keys; `VERUS-TRUSTED-CHECKED`; per-crate `VERUS-<CRATE>` |
| Verus needles and spec deletion | T6 | Major | Clause-specific named cases; `VERUS-ENSURES-<CRATE>`; required list |
| Verus cache and selftest | T7 | Major | Both sides of `verus-cache`; seeding; `verus_crates`; full key inputs; `--locked` |
| Verus lock | T8, F18 | Major | Shares `build/kani.lock` |
| PD-binary-unchanged claim | T12, F4, S-10 | Major | Per-PD `.text` hash before and after each V slice; `verus-erasure`; R-M3 corrected |
| Toolchain coverage of V0 | F3 | Major | V0b slice on the real wg-wire through pds, lint-pds, Kani, bolero, unit and verus |
| Specs against code | F5, F6, F7, F8 | Major | C2, C3 (member set from `pub fn decode`), C5 (entry points, RFC 1812 recompute, semantic round trip) and C6 (mask, power-of-two N, trusted models) restated against the code |
| Forbidden patterns unenforced | T5, F10 | Major | check-pins P12–P14 with deny and allow fixtures, scoped by path; harness outside `mce460896` |
| Oracle provenance and the bridge | T9, T10, F11 | Major | liboqs KAT never regenerated; v02 and its keys untouched; bridge vectors frozen with provenance, mode deleted in C11; P13 scoped |
| Waiver member set | T11, F15, F16, S-11 | Major | `git grep` over the tracked tree minus docs/archive, plus the L2 rows; `package-waiver` injects an open waiver; allow case |
| File list | F17 | Major | "Files to update" section |
| Stack | T14, F14 | Major (F14) | Stack painting cited; `pq` and `pqkey` re-measured |
| Minor items | T13, T15, T16, T17, S-12, S-13, S-14, F19, F20 | Minor | KAT digest plus 3 entries; profile override; line tables; replacement tests listed; `build/ct`; I3 mapping table; corrected pin statements; R-M5/SC31; V0 citation; layout answered |

No finding was skipped.

## Recurring Issue Check

### Functionality expert

| Rule | Status |
|---|---|
| R3 | F16, F17 |
| R17 | F17 |
| R29 | F1, F5, F7, F14, F19 |
| R40 | F9 |
| R41 | F10 |
| R42 | F2, F6, F13, F14, F16 |
| R49 | F4, F16 |
| R50 | F13 |
| R55 | F9 |
| Others | clean or N/A |

### Security expert

| Rule | Status |
|---|---|
| R3 | S-11 |
| R16 | S-4 |
| R29 | S-1, S-10, S-13 |
| R36 | S-5 |
| R38 | S-2 |
| R39 | S-8 |
| R42 | S-7, S-9, S-11, S-12 |
| R44 | OK; see also S-5 |
| R47 | S-5, S-9, S-12 |
| R48 | related to S-1 |
| R49 | S-1, S-3, S-8, S-10, S-12 |
| R50 | S-1, S-5, S-7 |
| Others | N/A |
| RS1 | OK |
| RS2 | N/A |
| RS3 | OK |
| RS4 | OK |
| RS5 | N/A |
| RS6 | N/A |

### Testing expert

| Rule | Status |
|---|---|
| R3 | T11, T13 |
| R16 | T7 |
| R29 | T14 |
| R33 | T11 |
| R42 | T11 |
| R44 | OK |
| R49 | T12, T5 |
| R50 | T1, T3 |
| R55 | T4 |
| Others | N/A or OK |
| RT5 | T2 |
| RT6 | T16 |
| RT7 | T1, T3, T5, T6 |
| RT9 | T9 |
| RT10 | T2, T5, T7 |
| RT11 | T17 |

# Round 2

Date: 2026-10-21

## Changes from Previous Round

Rev 2 addressed every Round 1 finding. Round 2 confirmed that most of them
are resolved. Its new findings converge on one point: the C10 identity
design, as written, could not hold. That point and the other gaps are
resolved in rev 3.

## Findings and resolution (rev 3)

All three experts raised the identity problem independently. Each expert
numbers its findings N1… on its own, so the prefixes S-, F- and T- mark
the security, functionality and testing experts.

| Root cause | IDs | Severity | Resolution in rev 3 |
|---|---|---|---|
| Identity unsatisfiable: generic `encaps`, different halves of the KEM per ELF, closure stopping at sha3 | S-N1, F-N1, F-N2, T-N3 | Major | Non-generic `#[inline(never)]` core `encaps_attempt` that returns the accept bit; the generic shim is excluded by name with a justification. Expected roots per ELF (pqkey → `decaps`, pq → `encaps_attempt`); full call-graph closure, with only `compiler_builtins` `mem*` allowlisted |
| Codegen parity between the harness and the PD target | F-N3, S-N6, T-N3 | Major | `-C relocation-model=static`, frame pointers; target-spec deltas listed with probe evidence; normaliser masks only immediates and relocations, with a one-instruction unit test; identity probe slice M-1 before the port |
| Package binding: inputs, ordering, C9 record | S-N2, F-N4, T-N5, T-N8 | Major | `ct-harness` is a prerequisite of `package` and `ct-shape`; a missing or stale harness refuses; release configs need `build/ct/pass-<sha>`; fixtures cover these, and one fixture runs the real ct-shape |
| Declassification: mechanism, width, member set | S-N3, T-N2 | Major | No client requests in `mce460896` (P15); declassification only in the harness at function boundaries, via site ids that must equal the policy; 1-byte predicate width enforced; member set = accept bit, plus ct/ss at the harness boundary |
| Round-3 framing mask sites and the C1-only input class | S-N4 | Major | I3 table includes the round-3 framing source sites; four rejection classes in C8 and C9; `ct-c1-barrier` selftest |
| Residue scan subject and needle forms | S-N5, T-N7 | Major | Scan moved into the harness (identity-bound codegen); outputs on the heap; painted-depth floor; needles in every stored form; three per-representation selftests |
| Exit status, completion sentinel, marked bytes | T-N1 | Major | `--error-exitcode=97`, required exactly; `CT-DONE`; distinct harness exit code; V-bits read back; `ct-early-exit` selftest |
| ct-identity mutation not injectable | T-N4 | Major | Scratch Makefile gives `pd-pq` alone `RUSTFLAGS=-C opt-level=3`; the uninjected copy is shown green |
| verus-erasure unproven | T-N6 | Major | Positive control (entry symbol), plus `verus-erasure` selftest |
| P13 denies the binding | F-N5, T-N9 | Major | P13 limited to Cargo dependency keys and Rust use/paths, across all manifests and locks including rp-vectors; allow fixture over `waivers.py`; rp-vectors exception dropped |
| Equivalent window mutation | F-N6 | Major | `<` becomes `<=` in the window compare; the spec uses the literal `BITS - 1` |
| Minor items | S-N7, T-N10, T-N11, T-N12, T-N13, F-N7, F-N8, F-N9, F-N10, F-N11 | Minor | cfg_attr spelling via a shared scanner; ensures conjuncts with the residual stated; KAT claim narrowed to 3 entries; EXPECT_SUCCESS/ABSENT entries named; ct-shape gate with prerequisites; ct-harness unit test and LINT +2; vstd version named; wg-wire type names; Verus source as a sha256-checked tarball |

No finding was skipped.

## Recurring Issue Check (Round 2)

### Functionality

| Rules | Status |
|---|---|
| R16 | fired (F-N3) |
| R29 | fired (F-N9) |
| R40 | fired (F-N8) |
| R42 | fired (F-N1, F-N2) |
| R50 | fired (F-N4) |
| All others | clean or N/A |

### Security

| Rules | Status |
|---|---|
| R3 | fired (S-N4) |
| R16 | fired (S-N5, S-N6) |
| R36 | fired (S-N1, S-N3, S-N6) |
| R38 | fired (S-N2) |
| R39 | fired (S-N5) |
| R42 | fired (S-N3, S-N4, S-N5) |
| R47 | fired (S-N7) |
| R49 | fired (S-N1, S-N2) |
| R50 | fired (S-N1, S-N2, S-N5) |
| RS1 | fired (S-N4) |
| R44, R48, RS3, RS4 | OK |
| All others | N/A |

### Testing

| Rules | Status |
|---|---|
| R16 | fired (T-N3) |
| R41 | fired (T-N2) |
| R44 | fired (T-N1) |
| R48 | fired (T-N11) |
| R49 | fired (T-N10) |
| R50 | fired (T-N1, T-N5, T-N6) |
| RT5 | fired (T-N8) |
| RT7 | fired (T-N1, T-N2, T-N4, T-N5, T-N6, T-N7) |
| RT9 | fired (T-N11) |
| RT10 | fired (T-N13) |
| All others | OK or N/A |

# Round 3

Date: 2026-10-21

## Changes from Previous Round

Rev 3 moved the identity check onto a non-generic KEM core with per-ELF
roots. Round 3 confirmed that every Round 2 finding is resolved. Its new
findings concern details of rev 3's own mechanisms. Rev 4 resolves them.

## Findings and resolution (rev 4)

| Root cause | IDs | Severity | Resolution in rev 4 |
|---|---|---|---|
| A residue scan cannot share a run with memcheck's exact-one-error rule | T-P1, S-R3-2 | Major | The same binary runs twice: in CT mode under memcheck, and in residue mode natively (exits 4 under valgrind) on a harness-owned `mmap` stack, with its own count and sentinel |
| The shim's `rand` determines `e` and was covered by no gate | S-R3-1, F-N13 | Major | `rand` is held in `Zeroizing` and wiped after each attempt and on error; I8 (fresh full draw, no reuse) justifies the exclusion; residue mode runs the real shim with a rejecting RNG; `mce-residue-shim`; the shim's shape is baselined |
| The closure reached panic, core and libc code, which differs by construction | F-N12 | Major | The closure follows `bl` and tail calls and stops at panic entries (public cold edges). `mem{cpy,set,move}` are allowlisted by name; `memcmp`/`bcmp` are forbidden. Both builds use `-Z share-generics=no`. M-1 probes a bounds-checked, overflow-checked, `copy_from_slice` function |
| Pass record key and forgeability | S-R3-3 | Minor | Key = harness + declassify policy + vectors + valgrind version; the record holds the counts; forgeability declared under R49 (b) |
| Dependency set unenforced; P15 checks a surface form | S-R3-4 | Minor | P16 checks the resolved dependency set; (b) rejects the client-request preamble in the compiled closure |
| Twin needle helpers | T-P2 | Minor | Needles come from the port's own `pub` pack and transpose functions |
| Erasure injection and vstd exec code | T-P3 | Minor | A reachable `black_box` call as the injection; "no vstd exec" constraint; residual declared |
| Allow-case inputs; C9-record fixture | T-P4 | Minor | `package-waiver-closed` uses mksecrets blobs in the copy; the fixture uses `stub_sc20=True` |
| Exit 3 unproven | T-P5 | Minor | `ct-not-valgrind` selftest |
| Window initial state | F-N14 | Minor | Clause added |
| P13 scope | F-N15 | Minor | Tracked files (`git ls-files`) |
| "Stale harness" | F-N16 | Minor | Dropped; make rebuilds the harness, and a missing one refuses |
| Plan header | F-N17 | Minor | Rev 4 |

No finding was skipped.

## Recurring Issue Check (Round 3)

### Functionality

| Rule | Status |
|---|---|
| R16 | fired (F-N12) |
| R39 | fired, adjacent (F-N13) |
| R42 | fired (F-N12, F-N13) |
| All others | clean or N/A |

### Security

| Rule | Status |
|---|---|
| R3 | fired (S-R3-1) |
| R29 | fired (S-R3-1) |
| R36 | fired (S-R3-2) |
| R39 | fired (S-R3-1) |
| R42 | fired (S-R3-1) |
| R47 | fired (S-R3-4) |
| R49 | fired (S-R3-3) |
| R50 | fired (S-R3-2, S-R3-3) |
| R16, R38, R44, R48, RS1, RS3, RS4 | OK |
| All others | N/A |

### Testing

| Rule | Status |
|---|---|
| R41 | fired (T-P3) |
| R49 | fired (T-P3) |
| R50 | fired (T-P1) |
| RT7 | fired (T-P1, T-P3, T-P5) |
| RT9 | fired (T-P2) |
| RT10 | fired (T-P4) |
| All others | OK or N/A |

# Round 4

Date: 2026-10-21

## Changes from Previous Round

Rev 4 resolved every Round 3 finding, and all three experts confirmed it.
Round 4 raised one Major, R4-1 (security), and ten Minors. Rev 5 resolves
all of them. Under the risk-tiered process, only the security expert
re-checks R4-1, and only R4-1.

## Findings and resolution (rev 5)

| ID | Severity | Resolution in rev 5 |
|---|---|---|
| S-R4-1: residue in sha3, keccak and spill frames the port cannot wipe | Major | `scrub_stack()`: `#[inline(never)]` volatile zeroing to a `SCRUB_DEPTH` asserted against the measured peak and the painted floor. Called by the thin `decaps`/`encaps_attempt` roots after `_core`. In the identity set. keccak/`ss` needles stay mandatory |
| S-R4-2: I8 unchecked | Minor | I8 in the control class; recording-RNG unit test; `mce-fresh-draw` |
| S-R4-3: needle forms without red-proofs | Minor | One `mce-residue-<form>` case per needle form |
| T-Q1: pass-record key | Minor | One key function (`tools/ct_record.py`) shared by ct and package; stale-policy fixture |
| T-Q2: exit 4 unproven | Minor | `residue-under-valgrind` |
| T-Q3: needle location and stage values | Minor | Needles computed on the main thread into the heap; `pub` `syndrome`/`bm` stages |
| T-Q4: allow case `OUT` | Minor | `OUT` inside the scratch copy, asserted |
| F-N18: panic stop list | Minor | Defined by property; unit test includes `len_mismatch_fail` |
| F-N19: P16 dependency kinds | Minor | Normal dependencies only |
| F-N20: I5 wording | Minor | Reworded |
| F-N21: share-generics in every PD | Minor | Makefile entry; M-1 records hashes before and after the flag |

The security expert's `mem*` soundness argument is written next to the
allowlist (a suggestion, not a finding).

## Recurring Issue Check (Round 4)

### Functionality

| Rule | Status |
|---|---|
| R3 | fired (N21) |
| R42 | fired (N18) |
| All others | clean or N/A |

### Security

| Rule | Status |
|---|---|
| R36 | fired (R4-1) |
| R39 | fired (R4-1, R4-3) |
| R42 | fired (R4-3) |
| R49 | fired (R4-2) |
| All others | OK or N/A |

### Testing

| Rule | Status |
|---|---|
| R29 | fired (Q1) |
| RT7 | fired (Q2) |
| RT11 | fired (Q4) |
| All others | OK or N/A |

# Round 5

Date: 2026-10-21

## Changes from Previous Round

The security expert re-checked only R4-1 against rev 5 (risk-tiered: only
the expert who raised a Major re-checks it). R4-1 is resolved, with no new
Critical or Major finding.

The expert added three Minor notes, all applied in rev 5:

- the I5 prose was split back into two statements;
- `_core` is now stated `#[inline(never)]`;
- register residue was recorded as R-M7.

## Saturation call

The plan phase is saturated after Round 5, and all four conditions hold:

1. Five rounds have completed.
2. No Critical or Major finding is open in any category. The two Round 1
   Criticals (F1, S-1) and every Major from Rounds 1–4 are resolved in the
   plan file, and each round re-checked them.
3. No open finding is against the design.
4. Every remaining note was applied. None is carried forward.

All contracts C1–C11 are `locked` in the Go/No-Go gate. There is no
`## Carried-Forward Plan Findings` section, because no finding remains
open.
