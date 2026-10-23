# Code Review: secureos-m5-measured-release
Date: 2026-10-24
Review round: 1

## Changes from Previous Round

Initial review of `e132cd6..HEAD` (M5 slices 1–8 plus the Phase 2
self-check fixes).

- **How it ran:** three experts reviewed in parallel. The first security
  reviewer split its work into five area sub-reviews and handed back before
  any of them returned. A second security reviewer then covered the whole
  scope directly. Four of the five area sub-reviews later returned on their
  own (key/laws/console, tpm PD + gate, tpm2 crypto, measured boot). Their
  findings were verified against the code before being merged below.
- **Seeds:** the Ollama pre-screen and seeds (step 3-2) were skipped. They
  diff against `main`, which does not hold M4, so their base would be
  wrong.

## Functionality Findings

- **F1 Major** `tools/release.py make()` was not transactional. A failure
  after `mkdir` left an OUT that refused every retry.
- **F2 Minor** `tools/repro`'s comment blamed config's `env!`, which the R34
  fix removed.
- **F3 Minor** `measure.pack(..., expected=ranges)` in `tools/package` was a
  self-comparison. Duplicate of S3 and S-BOOT-3.

## Security Findings

- **S1 Major** `key` kept the unsealed plaintext in `PLAINTEXT` when RNDR
  or seed derivation failed after validation. That broke C6 ("Unavailable
  holds no secret") and I11.1.
  - Also raised by the key/laws sub-review as Critical with escalate:true.
    The direct reviewer, with the wider view, rated it Major: a reader of
    `key`'s memory gets the same data in Ready.
  - Merged at Major, with the escalation request recorded. The fix is the
    same either way.
- **S2 Minor** after `go`, the shipped boot command could fall through to
  U-Boot's prompt with PCR 8 at its sealed value.
- **S3 Minor** I8.2's `expected` check was a self-comparison, and
  `release.py verify` did not check ranges.
- **S4 Minor** `--allow-dirty` signed a manifest naming HEAD with no dirty
  marker.
- **S5 Minor** C8's on-device "length equals the envelope's length" check
  is not implemented, and no deviation was recorded.
- **S-BOOT-1** (sub-review, Critical, escalate:true) the boot command is one
  hush line. If `poweroff` ever returned, a refusal would fall through to
  the next statement, then an out-of-bounds `cp.b` and an unconditional
  `go`. Not demonstrated on QEMU, where PSCI `SYSTEM_OFF` halts. There was
  no backstop. Severity is merged at Major: it needs a firmware fault, and
  it is defence in depth for the VE6 boundary.
- **S-BOOT-2** (sub-review, Major) `measure.py` refuses an envelope range
  longer than its load slot, and `boot.cmd` did not: two adjudicators with
  different semantics (R48).
- **S-BOOT-4** (sub-review, Minor) the two `cp.b` copies had no refusal on
  failure.
- **S-TPMPD-1** (sub-review, Critical, escalate:true) the gate marks the cap
  done when it builds the PCR_Extend. The PD discarded the TIS result and
  the TPM's response code, so a failed extend left PCR 8 at its sealed
  value. Merged at Major: inducing that failure needs A7, and A7 can already
  unseal before the cap (RM5-5).
- **S-TPMPD-2-A** (sub-review, Major) a client stuck in Unsealing keeps the
  other client Busy indefinitely, so one key domain can deny the other its
  unseal.
- **S-TPMPD-3** (sub-review, Minor) `MAX_RESPONSE <= IPC_MSG_BYTES` is a
  tautology.
- **S-TPM2-1** (sub-review, Major) the session key's HMAC and KDF state is
  left on the stack by libcrux, with no scrub.
- **S-TPM2-2-A** (sub-review, Minor) no seal/open test has a region that
  ends in zero bytes.

## Testing Findings

- **T1 Major** the record did not show `tpm2-wire`'s eight Kani harnesses
  ever running at HEAD, nor any red-proof of them.
- **T2 Minor** `TpmProxy.close()` did not fail on a surviving relay thread,
  unlike `Swtpm.close()`.

## Adjacent Findings

- **S3-A** (to Testing): duplicate of S3; the vacuous expected-range clause
  is removed.
- **S-TPM2-2-A** (to Testing): fixed by a new test.
- **S-BOOT-1-A** (to Testing): `measure_boot` killed QEMU after "boot
  refused" without asserting that it stopped by itself. Fixed with S-BOOT-1.
- **S-KEYLAW-1-A** (to Security): L10 has no laws-tool check. It is
  structural, because `Event::value()` returns `Option<u32>`.

## Quality Warnings

None. Every finding cites code. The sub-review findings were each verified
by reading the cited lines before merging.

## Recurring Issue Check

### Functionality expert
R1–R57: as reported by the functionality reviewer (all clean except R5 →
F1). Per rule: R1, R2, R3, R4 clean; R5 F1; R6–R16 N/A or clean; R17–R20
clean; R21 N/A; R22 clean; R23, R24, R26–R28 N/A; R25 clean; R29 clean;
R30 N/A; R31 F1; R32 clean; R33 N/A; R34 closed (config fix); R35 clean;
R36, R37 clean; R38 clean; R39 confirmed fixed; R40–R42 clean; R43 N/A this
round; R44 clean; R45 not evaluated; R46 N/A; R47, R48 clean (single
adjudicator); R49, R50 clean; R51, R52 clean; R53 clean; R54 N/A; R55
clean; R56 N/A; R57 clean.

### Security expert
- **Direct reviewer** (R1–R57, RS1–RS6):
  - R3 partial (S1); R39 S1; R41 S5; R49 S3, S5.
  - R2, R12, R18, R29, R47, R48, R53 and R55 checked.
  - Everything else OK or N/A, as in the reviewer's list.
  - RS1–RS5 OK; RS6 N/A.
- **Sub-reviews:**
  - key/laws: R48 parity of codes clean, zeroize parity → S1.
  - tpm PD: R42 → S-TPMPD-1, R13/R44/R48/R51 clean.
  - tpm2: R39 → S-TPM2-1, RS1/R1/R40/R47/R48 clean.
  - measured boot: R48 → S-BOOT-2.

### Testing expert
- R1–R57: clean or N/A, except R21/R50 → T1.
- RT1–RT6 clean; RT7 → T1; RT8–RT10 clean; RT11 → T2.

## Environment Verification Report

| Constraint | Path | Status |
|---|---|---|
| VE2/VE6 (QEMU has no root of trust; U-Boot unmeasured) | measured boot, sealed boot | verified-local (`make check`, integration 44/44) as a demonstration; the firmware-measured chain is blocked-deferred (VE5, SC32, plan "QEMU-verifiable vs hardware-required") |
| VE7 (swtpm) | TPM session, A7 proxy, cap | verified-local; bus attacks on a board are blocked-deferred (SC32) |
| VE8 (no offline signing host) | release signing | verified-local with dev keys; custody is blocked-deferred (RM5-1) |
| VE5 (no board) | UART, release kernel on a board, PCR 0–7 | blocked-deferred (M7), Anti-Deferral entry in the plan |

## Resolution Status
