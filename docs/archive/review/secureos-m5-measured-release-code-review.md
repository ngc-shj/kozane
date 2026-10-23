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

The late area sub-review (packaging, release, supply chain) added:
- **S-REL-1** (sub-review, Critical, escalate:true) `tools/verus-pairing`
  did not refuse a vendored or image crate path that is itself a symlink.
  `rglob` follows a linked root, so a vendored crate linked at the image
  tree compared a tree with itself. Merged at Major: it needs a committed
  symlink, which is visible in review as a mode change.
- **S-REL-2** (sub-review, Major) the release tool's `SigningKeys` drop and
  keygen seed used `fill(0)`. The optimiser may remove that as a dead
  store.
- **S-REL-3** (sub-review, Major) the P11 tag tripwire scanned one file.
  A check moved elsewhere in tpm2 would be uncovered.

Found by the full check-selftest run at `9bd8436` (140 min, 128/130):
- **The `package-debug` and `package-waiver` cases were stale.** Slice 7
  made `SRK_PUBLIC` required and did not update them, so both stopped at the
  Makefile's argument check, before the refusals they name.
- **The `run_make` fixture failed once under load.** It judged the
  grandchild's death on the first look after the group SIGKILL, which is
  not instant. This race predates M5.

## Resolution Status

### F1 Major release.py make() not transactional
- Action: `make` builds in a staging directory beside OUT and renames it
  into place once the signature and both files are written. Any failure
  removes the staging directory.
- Fixture: a signing failure leaves no OUT and no staging, and the retry
  succeeds (`RELEASE-FIXTURES 11`).
- Modified file: tools/release.py (`make`), tests/tools/test_release.py

### F2 Minor stale repro comment
- Action: the comment now names the general hazard and says config's case
  was fixed at its source.
- Modified file: tools/repro

### F3 / S3 / S-BOOT-3 Minor tautological expected-range check
- Action: `expected=ranges` was dropped. The independent I8.2 check is now
  `measure.check_placeholder`: the published image must hold the zero
  placeholder over every envelope range. `tools/package` runs it, and so
  do `release.py make` and `verify`, from public files.
- Fixtures: allow and deny in `test_measure.py` (`MEASURE-FIXTURES 18`); a
  release with a range over non-zero bytes is refused.
- Modified file: tools/measure.py, tools/package, tools/release.py, tests

### S1 / S-KEYLAW-1 Major key kept plaintext on a post-validation boot failure
- Action: validation and the boot seed moved into one fallible
  `key_core::Oracle::boot`, beside the new `BootEntropy` trait (the same
  shape as pqkey-core). The PD wipes `PLAINTEXT` with a single
  `inspect_err` over the whole call, so every `BootError` after the unseal
  leaves no secret.
- Tests: an allow test (boot with entropy answers) and a deny test (RNDR
  failing after validation is `RndrUnavailable`).
- No new dependency and no `Cargo.lock` change: samples and the seed are
  `tpm2::Secret`s.
- Modified file: crates/key-core/src/lib.rs, crates/key-core/src/tests.rs,
  crates/pds/key/src/main.rs

### S2 Minor fall-through to the prompt after `go`
- Action: the shipped command ends with
  `go …; echo secureos: loader returned; poweroff; while true; do true; done`.
- Modified file: tools/uboot-config

### S4 Minor dirty release named by HEAD
- Action: a dirty tree gives `commit=<sha>-dirty`, and `verify` refuses it
  unless `--allow-dirty` is passed. Fixture added.
- Modified file: tools/release.py, tests/tools/test_release.py

### S5 Minor on-device envelope-length check
- Action: recorded as a deviation. U-Boot cannot know the size of a file
  QEMU loaded at a fixed address. What holds instead:
  - each length is bounded on-device by its load slot (S-BOOT-2) and by
    `image_len`;
  - `Envelope::parse` requires the exact region size;
  - the AEAD decides.
- Modified file: docs (deviation log)

### S-BOOT-1 Major (merged) refusal could fall through if poweroff returned
- Action: `REFUSE` is now `echo …; poweroff; while true; do true; done`.
  `measure_boot` requires QEMU to stop by itself after a refusal, with
  nothing measured after it.
- Red-proof: the new check-selftest case `measure-halt` replaces the halt
  with `true` and is red with "measure_boot: U-Boot did not stop at its
  refusal".
- Modified file: tools/uboot-config, tests/integration/run.py,
  tools/check-selftest

### S-BOOT-2 Major on-device and host adjudicators differed
- Action: boot.cmd refuses `l0`/`l1 > 0x100000`, the host's
  `ENVELOPE_ROOM`.
- Modified file: support/u-boot/boot.cmd

### S-BOOT-4 Minor unguarded cp.b
- Action: both copies are `cp.b … || REFUSE`.
- Modified file: support/u-boot/boot.cmd

### S-TPMPD-1 Major (merged) cap extend unconfirmed
- Action: the PD confirms the extend through the TPM's own response
  (`parse_pcr_extend`) and retries up to `CAP_ATTEMPTS` (3). The gate's
  software refusal is unchanged; the Kani-verified `gate.rs` is not
  edited.
- Modified file: crates/pds/tpm/src/main.rs

### S-TPMPD-2-A Major a stuck client keeps the other Busy — Accepted
- **Anti-Deferral check:** acceptable risk.
- **Justification:**
  - **Worst case:** `key` crashes or is compromised mid-flow, and `pqkey`
    gets Busy until its 120 s budget expires, then `TpmUnavailable`; `pq`
    reports `KeyUnavailable`.
  - **That is no worse than today:**
    - a compromised `key` already holds every WireGuard secret (the
      architecture plan's threat table: "`key`: Everything");
    - a crashed `key` already ends every handshake, since `hs` cannot boot
      without it;
    - so the extra loss, Rosenpass for a gateway that cannot handshake
      anyway, adds nothing an attacker can use.
  - **The mirror case, a stuck `pqkey` denying `key`,** needs a
    compromised `pqkey`. That PD sees only Rosenpass ciphertext from `pq`,
    and only after init. Before its init returns, no tainted input reaches
    it (S18).
  - **Likelihood:** low. It needs an init-time crash or a compromise of a
    PD that is not callable before its init ends.
  - **Round 2 addition, the mirror crash:** if `pqkey` crashes mid-unseal
    (a fault, or A7 feeding it a malformed response), `key` gets Busy and
    then `TpmUnavailable`, so the whole gateway is out. That is worse than
    the worst case stated above. The acceptance stands all the same:
    - whoever can crash `pqkey` mid-unseal can already deny `key` directly.
      A7 can cut the TPM off entirely, and a bug in `tpm2::boot::unseal`
      is code `key` runs too;
    - so the outage needs no capability the attacker lacks without this
      path.
  - **Cost to fix:** a PD-level liveness deadline that force-fails a stuck
    client. It needs care to avoid racing the client's own retry budget
    (about 1 day with Kani coverage of the new transition). Recorded here
    as a known limitation.
- **Orchestrator sign-off:** acceptable-risk exception satisfied (worst
  case, likelihood and cost stated).

### S-TPMPD-3 Minor MAX_RESPONSE assert tautological — no change
- Action: none. The comment "No parser accepts a longer response" is
  accurate:
  - `response_header` refuses longer input;
  - the PD's TIS driver bounds the size field to `..=MSG_BYTES` before it
    reads.

  The constant is a shared bound, not a computed maximum. Editing the
  Kani-verified crate for a comment would re-prove it (about 45 min) and
  would change no behaviour.

### S-TPM2-1 Major (merged as Minor) session-key residue in libcrux frames
- Action: `tpm2::boot::unseal` scrubs `OPEN_SCRUB_DEPTH` bytes of stack
  below its frame once the session is over (`scrub_session_stack`). The
  scrub is its own copy because calling open_sealed's scrub would enter
  that closure at a non-root function, which ct-shape refuses.
- Severity merged as Minor: the client PD holds the decrypted plaintext for
  its whole life, so a stack reader gains nothing new.
- Modified file: crates/tpm2/src/boot.rs (round 2 correction: envelope.rs is not modified)

### S-TPM2-2-A Minor no zero-tailed region test
- Action: `a_region_ending_in_zero_bytes_opens_to_itself`
  (`UNIT-TPM2 +1`).
- Modified file: crates/tpm2/src/tests.rs

### S-REL-1 Major (merged) verus-pairing followed a linked crate root
- Action: a vendored or image crate path that is a symlink is refused
  before any comparison. Fixture: a vendored crate linked at the image tree
  is refused (`VERUS-PAIRING-FIXTURES 13`). The allow fixtures, real
  directories, still pass.
- Modified file: tools/verus-pairing, tests/tools/test_verus_pairing.py

### S-REL-2 Major release key wipes could be dead-store eliminated
- Action: `SigningKeys`' drop and keygen's seed (and the early-return path)
  use `zeroize`.
- **Swept the class:** every `fill(0)` in M5 code is either a write to
  caller-visible memory (an `&mut` parameter) or to a local holding public
  data or ciphertext (TPM command and response buffers, hs requests). Only
  the release tool's two wipes held secrets in memory nothing reads again.
- Modified file: tools/release/src/sig.rs

### S-REL-3 Major P11 tag tripwire scanned one file
- Action: P11 scans every `.rs` under `crates/tpm2`, and `client.rs` must
  exist. The docstring now states the tripwire's limits: lowercase names,
  `==`/`!=` only. Fixture: a tag `==` in `boot.rs` is flagged
  (`CHECK-PINS-FIXTURES` +1). The widened scan has no false hit in the
  crate today.
- Modified file: tools/check-pins, tests/tools/test_check_pins.py

### T1 Major tpm2-wire's Kani harnesses unrecorded
- Action: recorded in the deviation log. All eight harnesses ran alone at
  HEAD (`the_owners_flow_is_forwarded` took 1,248 s; peak 22.4 GiB), and
  again in the full `make kani` (68 harnesses, 134 min, peak 23.5 GiB).
- Red-proofs per deny harness: see the Kani mutation table appended below.

### T2 Minor TpmProxy teardown
- Action: `close()` fails the case if the relay thread survives, as
  `Swtpm.close()` does.
- Modified file: tests/integration/run.py

### Stale package selftest cases, and the run_make fixture race
- **Stale cases:** `package-debug` and `package-waiver` now pass
  `SRK_PUBLIC`. Re-run, both are red with their own needles.
- **Fixture race:** the `run_make` fixture now waits, with a bound, for the
  grandchild's death after the group SIGKILL, instead of judging the first
  look. It passed three consecutive runs.
- Modified file: tools/check-selftest, tests/tools/test_check_selftest.py

### S-KEYLAW-1-A Minor (Adjacent) L10 has no laws-tool check — no change
- Action: none. L10 is structural: `Record` is
  `{code: u16, _reserved: u16, a: u32, b: u32}` and `Event::value()` returns
  `Option<u32>`, so a byte-carrying variant cannot be encoded without
  changing those types, and that change would show in review.

#### T1 Kani mutation table

Each mutation was applied to its own scratch copy of the tree, and only the
harness it targets was run (`cargo kani -p tpm2-wire --harness … --exact`
under `tools/proof-lock`):

| Mutation in gate.rs | Harness | Result |
|---|---|---|
| allowlist check disabled (`if false && !ALLOWED.contains(&cc)`) | `unlisted_command_codes_never_reach_the_device` | 1 failure |
| ownership always true (`if true { Ok(()) }`) | `cross_client_handles_are_refused` | 1 failure |
| Done/Failed refusal disabled | `a_finished_client_is_refused` | 1 failure |
| cap refusal disabled (`if false && self.capped`) | `unseal_after_the_cap_is_refused` | 1 failure: the harness asserts `Err(Refusal::Capped)` exactly, so the Finished refusal does not mask it |

---

# Round 2
Date: 2026-10-24

## Changes from Previous Round

Round 2 reviewed only the round-1 fixes (`9bd8436..6aa9f15`). Each
expert resolved every round-1 finding of theirs, or upheld its accepted or
no-change disposition. The security expert's R43 comparison against the
previous round found no widening. There are no new Critical or Major
findings.

## New findings (all Minor)

- **S-BOOT-5 (security)** hush loops poll Ctrl-C, and autoboot leaves Ctrl-C
  on without `CONFIG_AUTOBOOT_KEYED`. One 0x03 on the UART breaks the
  refusal's spin, and the sticky flag also ends every later loop,
  including the 32-bit field checks. The deviation log's "runs nothing
  after a refusal" was false.
- **S-TPM2-3 (security) / F5 (functionality)** the session scrub reuses
  `OPEN_SCRUB_DEPTH` with no measurement of the HMAC/KDF chain's depth and
  no red-proof. The resolution named envelope.rs as modified, which it is
  not.
- **S-REL-4 (security)** verify's placeholder refusal had no fixture of its
  own, and the default verify path (no flag, clean commit) had lost its
  allow test.
- **F4 (functionality)** a cap retry after a lost response may extend PCR 8
  twice. That is fail-closed, but the PD comment claimed PCR 8 stays at its
  sealed value.
- **T3 (testing)** the PD-side wipe after a failed `Oracle::boot` has no
  automated proof. `pds/key` is not host-testable, and no integration case
  takes that path.
- **Nit (security)** `crates/pds/tpm/src/main.rs` kept an old sentence
  beside the new one.

## Resolution Status (round 2)

### S-BOOT-5 Minor Ctrl-C breaks the refusal spin
- Action:
  - The fragment sets `CONFIG_AUTOBOOT_KEYED=y` and leaves
    `AUTOBOOT_KEYED_CTRLC` unset. Autoboot then disables Ctrl-C around the
    boot command; with `BOOTDELAY=-2` no prompt appears. `uboot-config
    verify` refuses a build where Kconfig drops it.
  - `measure_boot` sends 0x03 after "boot refused", then requires that
    neither a later "secureos: measured" nor a `=>` prompt appears while
    U-Boot powers off (or spins, bounded).
- Red-proof: the new check-selftest case `measure-ctrlc` removes the
  power-off and the `AUTOBOOT_KEYED` line and is red with "measure_boot:
  U-Boot did not stop at its refusal".
- The deviation-log sentence is corrected.
- Modified file: support/u-boot/secureos.config, tests/integration/run.py,
  tools/check-selftest, deviation log

### S-REL-4 Minor verify-side fixtures
- Action: two new fixtures (`RELEASE-FIXTURES 13`):
  - a clean-commit release verifies by default, with no flag;
  - a signed release whose image is non-zero inside a range is refused by
    verify with "zero placeholder".
- Red-proof on a committed scratch copy: removing verify's
  `check_placeholder` turns exactly that fixture red. A helper now signs
  releases by hand, so each verify check can be met on its own.
- Modified file: tests/tools/test_release.py

### F4 Minor cap comment
- Action: the comment states the double-extend case and its fail-closed
  direction. The duplicate old sentence is removed (the security nit).
- Modified file: crates/pds/tpm/src/main.rs

### S-TPM2-3 / F5 Minor session scrub unmeasured — Accepted
- **Anti-Deferral check:** acceptable risk.
- **Justification:**
  - **Worst case:** the libcrux HMAC/KDF frames of the TPM session run
    deeper than 8 KiB, so some session-key-derived state survives on the
    client PD's stack.
  - **That gains a reader nothing:** the same PD holds the decrypted blob
    in its private memory for its whole life (Ready state), so anyone who
    can read its stack can read the plaintext secrets directly. In the
    Unavailable states the plaintext is wiped. Getting the KEK there would
    also need the boot's captured TPM traffic and the envelope from boot
    media, and all of that comes to the same blob.
  - **Likelihood:** low. It needs a memory-read capability inside
    `key`/`pqkey`, which is already the "Everything" row of the threat
    model.
  - **Cost to fix:** a residue-harness `unseal` case over a fake TPM that
    holds an SRK private key, plus a measured floor. About 2 to 3 hours. It
    is recorded as a known limitation; the scrub stays as defence in depth.
- **Orchestrator sign-off:** acceptable-risk exception satisfied.

### T3 Minor PD-side wipe not proven by a test — Accepted
- **Anti-Deferral check:** acceptable risk.
- **Justification:**
  - **Worst case:** a later edit drops the PD's `inspect_err` wipe, and no
    test notices.
  - **Likelihood:** low, for three reasons:
    - the wipe is one expression over the single fallible call;
    - it mirrors pqkey's reviewed shape line for line;
    - a reviewer of any change to `crates/pds/key` sees it.
  - **Cost to fix:** a QEMU case that makes RNDR fail after a valid unseal
    and then scans guest RAM for the blob. That needs a fault-injection
    hook in a shipped PD, which is itself an attack surface. Not worth it
    for a defence-in-depth wipe, since the Ready state holds the same data.
- **Orchestrator sign-off:** acceptable-risk exception satisfied.
