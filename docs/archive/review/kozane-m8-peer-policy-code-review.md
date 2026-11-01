# Code Review: kozane-m8-peer-policy
Date: 2026-11-01
Review round: 8

## Changes from Previous Round
Initial review, at 751e95b, after Phase 2 Step 2-5's self-check (D-23).

The local LLM was unavailable, so there were no seeds and no pre-screen.
Each expert reviewed `git diff main...HEAD` directly, and every Seed
Finding Disposition reads "Seed unavailable — no dispositions to record."

## Functionality Findings

- **F-F1 Major: `approve` recorded the draft as the approver's head.**
  At tools/policy/src/main.rs:506 it wrote the draft's version and digest.
  An abandoned or revised draft then locked that approver out of every
  later `approve` and `ledger restore`.
- **F-F2 Major: a boot with a halted source never signed its ready
  checkpoint.** When `policy` is Unavailable, all five barrier PDs halt
  (`Halted`, never `Ready`), so the ready checkpoint never fired
  (crates/audit-core/src/lib.rs:258). The boot's `policy: unavailable` line
  stayed `verified=no`, and audit-verify FAILed "no signed checkpoint".
- **F-F3 Major: the runbook's capture rule made `--after` fail on routine
  captures.** It said "capture without gaps", but a capture has to start
  right after the anchor, repeating the previous unverified tail.
- **F-F4 Minor: `policy fleet` overrode a node's compiled `[policy]
  fleet_id`.** The fleet.rs docs were also stale: they said there was no
  fleet_id yet and gave the neighbor count as u8.
- **F-F5 Minor: `policy: rejected` dropped the slot's version.**
- **F-F6 Minor: diff.rs had its own `hex`** instead of `sig::hex`.

The functionality expert checked the Implementation Checklist: every file
is in the diff except tools/uboot-config and tools/supervisor-allowlist.
Neither needs a change.

## Security Findings

- **S-F1 Major: `policy diff` showed only the header and `body_sha256`.**
  Approvers could not see peer, key or rule changes (S8, A14), and the
  diff reviewed was bound to the draft approved only by a file name (R51).
- **S-F2 Major: `record` and `nv` never checked that the Clear had
  happened.** If step 1 was skipped, a pre-M8 envelope would still unseal
  (D5, S18, A15/A16).
- **S-F3 Minor: `--head` was optional, and the head recorded the draft.**
  The second half is the same defect as F-F1.
- **S-F4 Minor: nothing showed where the anchor's boot ended.**
  audit-verify cannot tell how far the anchor's boot ran past the anchor
  at a capture boundary.
- **[Adjacent] Minor: the diff property tests passed on the
  `body_sha256` line alone.**

The device path held: signatures are checked before `parse`, domains are
separated, encodings are fixed-width, the gate allows at most one
increment, Names are compared before any read, the PCR 9 twin matches,
peer ids agree across hs, data and inner, and the checkpoint layout is the
same on both sides.

## Testing Findings

- **T-F1 Major: the policy-wire Kani harnesses did not bind a used slot's
  version.** No unit test had a lone `current+1` slot, so the
  `is_next → false` mutant survived every harness and test, and
  Equivocation was only covered.
- **T-F2 Major: the I8.3 step lemmas did not say where an inbound Allow
  writes.** The `share(peer ^ 1)` mutant survived every inner-core
  harness.
- **T-F3 Major: the Kani manifest and gate had not been brought to the M8
  crate set.** The counts were stale.
- **T-F4 Major: P31 did not pin `sign(`'s single call site in the
  `Action::Call` arm.**
- **T-F5 Major: the compile_fail doctests failed on missing fields,** not
  on field privacy.
- **T-F6 Minor: the bolero I1.3 target was weak.** It checked three fields
  rather than byte identity, and its signature anchor landed in the zero
  tail.
- **T-F7 Minor: `sign_refused` snapshotted only `ledger/entries`.**
- **T-F8 Minor: a fixture printed `reason=Version`,** which the device
  never emits.
- **T-F9 Minor: P1's TPM-side delete refusals have no in-tree test,** and
  that narrowing was not recorded.
- **T-F10 Minor: a stale comment said "two entries a peer"** under Kani.

## Adjacent Findings
- Security, Minor: the diff property tests were vacuous for S8. Resolved
  with S-F1.

## Quality Warnings
None. Every finding names a file, a line or a mutant, and a concrete
failure.

## Recurring Issue Check
### Functionality expert
These rules fired: R1 (F-F6), R29 (F-F4), R38 (F-F1, F-F2) and R41
(F-F2).

These were checked and found clean or N/A: R2–R28, R30–R37, R39, R40,
R42–R57. R53 is open as recorded in D-23.

### Security expert
These rules fired: R12 (S-F1), R49 (S-F1, S-F2, S-F3) and R51 (S-F1).

These were checked and found clean or N/A: R1–R11, R13–R48, R50, R52–R57
and RS1–RS6. R53 was not re-reported (D-23).

### Testing expert
These rules fired: R21 and R50 (T-F3), R29 (T-F10), R49 (T-F1, T-F2),
RT1 (T-F8), RT7 (T-F1, T-F2, T-F4, T-F5) and RT8 (T-F7).

These were checked and found clean or N/A: the other R rules, and RT2–RT6
and RT9–RT11.

## Environment Verification Report
The plan's QEMU-only paths (C13, the audit export) run in `make test`
under QEMU/TCG on the dev hosts. Round 1's audit and C13 changes are
verified-local by the `make test` at this round's commit (below).

## Resolution Status

### F-F1 / S-F3 Major: approver head
- Action:
  - `approve` records the verified ledger head (height and body digest),
    never the draft.
  - `--head` is required.
  - Fixtures: an abandoned draft leaves the head; a head file is reused
    across versions; approve without `--head`. The abandoned-draft case
    was red on the old code.
  - The runbook wording is updated.
- Modified files: tools/policy/src/main.rs (cmd_approve);
  tests/tools/test_policy.py; docs/operations/peer-policy-runbook.md.

### F-F2 Major: a halted source counts for the ready checkpoint
- Action:
  - The audit PD calls `source_ready` on `Halted`.
  - C13 `rolled-back` waits for a signed checkpoint on the halted boot.
  - Proof at the round's `make test`.
- Modified files: crates/pds/audit/src/main.rs (the `Decoded::Halted`
  arm); tests/integration/run.py (`rolled_back`).

### F-F3 Major / S-F4 Minor: capture continuity
- Action:
  - The runbook and the audit-verify usage text say that each capture
    starts right after the anchor.
  - audit-verify notes that the anchor's boot tail is unverifiable when
    the next capture starts a new boot. There is a fixture for that note.
- Modified files: docs/operations/peer-policy-runbook.md;
  tools/audit-verify (continuity, usage); tests/tools/test_audit_verify.py.

### S-F1 Major: diff content and the reviewed digest
- Action:
  - `policy_wire::contents` is a new host-only (`render`) walk view.
  - `diff` prints a line per peer (base64 `wg_pub`, rp key BLAKE2s, group
    indices, allowed IPs) and per rule, marked `+`, `-` or unchanged.
  - `approve` prints the diff and requires `--diff-sha256`.
  - `policy rp-digest` is added.
  - Tests:
    - unit: a swapped rp key changes its peer line; a widened rule
      changes its rule lines; an unchanged body has no `+` or `-`;
    - fixtures: a stale reviewed digest is refused; `diff` shows the
      changed peer.
  - Red-proved: with the item lines and the digest compare removed, three
    unit tests and two fixtures failed.
  - The runbook steps 3–4 are updated.
- Modified files: crates/policy-wire/src/lib.rs (`Contents`);
  tools/policy/src/diff.rs; tools/policy/src/main.rs;
  tools/policy/src/ledger.rs; tools/policy/src/tests.rs;
  tests/tools/test_policy.py; tests/integration/run.py (`sign_next`); the
  runbook.

### S-F2 Major: evidence that the Clear happened
- Action:
  - Probe: `TPM2_Clear` sets resetCount and restartCount to 0
    (build/probes/clear-counts.sh, D-24).
  - `record` and `nv` refuse unless both are 0, and `nv` refuses a record
    with `reset_at_provision` ≠ 0.
  - Fixtures: `record` and `nv` after a power cycle are refused. Both were
    red with the checks removed.
- Modified files: tools/provision (clock_counts, require_cleared,
  cmd_record, cmd_nv); tests/tools/test_provision.py; the runbook.

### T-F1 Major: select and I5.1 bind versions
- Action:
  - The harness asserts:
    - Use ⇒ the slot is at exactly `current`;
    - Advance ⇒ the slot is at `current+1` and the other slot anchors it;
    - two candidates at the same version with different bodies ⇒
      Equivocation.
  - I5.1's Done(Verified) arm asserts the slot's view is at `current`.
  - A unit test covers a lone `current+1` slot beside Empty, Malformed,
    BadSignature and RolledBack, giving PrevMismatch.
  - Both harnesses were proved on gx10. The `is_next → false` mutant
    fails both the select harness and the unit test.
- Modified files: crates/policy-wire/src/proofs.rs;
  crates/policy-wire/src/tests.rs.

### T-F2 Major: I8.3 lemma (d)
- Action:
  - The new harness `i8_3_inbound_allow_writes_only_its_share_and_its_tuple`
    has a `cover!` on an own-share eviction.
  - Lemma (b) is strengthened: no tuple is rewritten, and at most one
    entry changes.
  - The proofs and the two mutants (`share(peer ^ 1)` and an outbound
    tuple rewrite) run on gx10 (build/probes/kani-p3-inner.log).
- Modified file: crates/inner-core/src/flow.rs.

### T-F3 Major: Kani counts
- Action: the full `make kani` on z1mn, then a re-run on the round's
  commit for the crates changed since. The KANI-* lines are set from its
  `build/counts/kani`. Recorded at the round's gate run.
- Modified file: tests/manifest.txt.

### T-F4 Major: P31 pins `sign(`'s single site
- Action:
  - P31 requires exactly one `sign(` call, on the line after the
    `Action::Call(words) =>` arm.
  - Deny fixtures: a second call, and a call moved out of the arm.
- Modified files: tools/check-pins (check_audit_call);
  tests/tools/test_check_pins.py.

### T-F5 Major: the doctests fail on privacy only
- Action:
  - The struct literals name every field and are marked
    `compile_fail,E0451`.
  - Red: with the fields made `pub`, both doctests fail.
- Modified file: crates/policy-wire/src/lib.rs.

### Minor findings
- **F-F4:** `fleet` refuses a provisioned node whose `[policy]` fleet_id
  differs from `--fleet-id`. A node without `[policy]` (not provisioned
  yet) still takes it, as the runbook orders the steps. Both cases have
  fixtures, and the fleet.rs docs are corrected.
- **F-F5:** `rejected … version=<v|->`. The run.py regex, the audit map
  and the fixture are updated.
- **F-F6:** diff.rs uses `sig::hex`.
- **T-F6:** bolero now does a byte-identical re-render, and its signature
  anchor comes from `split().body().len()`.
- **T-F7:** `sign_refused` snapshots the whole ledger tree.
- **T-F8:** the fixture uses `reason=RolledBack`.
- **T-F9 — Accepted:** the narrowing is recorded as D-24.
  - Anti-Deferral check: the facts are the reference TPM's own behaviour.
  - Worst case: a TPM that accepts a one-signature delete would let one
    operator delete the indices.
  - Likelihood: low. Delete authorization is enforced by the TPM, and the
    nv fixtures exercise both the two-key delete and the refusal without
    the keys end to end.
  - Cost to fix: one swtpm interop test per fact. It would re-test swtpm,
    not Kozane.
- **T-F10:** the comment is corrected.

## Round 2 (751e95b..6aeafc7)

Round 2 reviewed only the round-1 fixes. All round-1 findings were
confirmed resolved, except T-F3 (the Kani counts, still open) and T-F6
(partial, continued below as T2-9).

### Findings
- **Functionality:**
  - F2-1 Major = S2-1 Minor: the approver head lagged one version, so the
    newest signed version had no truncation protection (R43, a narrowing
    the round-1 fix introduced).
  - F2-2 Minor: usage header. F2-3 Minor: a stale "1 s drain" comment.
    F2-4 Minor: `head_path` was an `Option` that is always `Some`.
  - F2-5 Minor: the diff format was neither versioned nor pinned; there
    was an unreachable branch.
  - F2-6 Minor: a probe cited from the git-ignored build/.
- **Security:**
  - S2-2 Minor: `contents` behind `render` was a token-less slot reader
    that P27 did not pin.
  - S2-3 Minor: a roster change was shown only as a digest.
  - S2-A1 Minor (Adjacent): P31 could be evaded by using `sign` as a
    value.
- **Testing:**
  - T2-1 Major: no injection during a checkpoint signature.
  - T2-2 Major: `rp-digest` and the diff `approve` prints were untested.
  - T2-4 Major: the nv deny after a power cycle did not check that the NV
    indices were unchanged.
  - Minors:
    - T2-3: lemma (d)'s cover could be met by a refresh.
    - T2-5: no restart-only deny.
    - T2-6: P31's window edge was not pinned.
    - T2-7: the note was never asserted absent.
    - T2-8: the rejected `version=` was unasserted.
    - T2-9: the bolero header was constant.
    - T2-10: a misplaced doc and a missing cover.
    - T2-11: the fork tolerated a missing head.
    - T2-12: the "stale" digest case was not stale; the snapshot had no
      red-proof.

### Round 2 Resolution Status
- **F2-1 / S2-1 (approver head and truncation):**
  - The head file holds the verified ledger head and the last approval.
  - `approve` and `ledger restore` refuse a ledger that lacks the
    approved version, unless the approver hands back that approval with
    `--supersede`.
  - Fixtures: an abandoned draft is superseded explicitly; without
    `--supersede` it is refused; a truncated replica is refused;
    supersede with someone else's approval is refused; restore below an
    approved version is refused; restore with the approval superseded
    succeeds.
  - Red-proved: with both checks disabled, 5 cases failed.
  - Runbook and D-24 are updated.
- **S2-2:** `Contents`/`contents` are behind `verifier` (P27).
- **S2-3:** a runbook step: check `policy roster-digest` of the new
  roster and read every entry.
- **S2-A1:** P31 counts every `sign` token but the definition. New
  fixture: `sign` used as a value.
- **F2-2, F2-3, F2-4:** fixed.
- **F2-5:** the unreachable branch is removed. A golden-text unit test
  (`diff_text_is_pinned`) pins the format, and diff.rs documents why.
- **F2-6:** D-24 quotes the probe's output.
- **T2-1:**
  - Inject B now goes in right after `hs: ready`, before the ready
    checkpoint, and logs whether its record came before or after the
    checkpoint.
  - Inject A still goes in after the checkpoint.
  - The interval still uses poll time. That is within the 5× margin, so
    no change.
- **T2-2:** new case "rp-digest prints the rp= that diff and approve
  show": the digest equals diff's `rp=`, a short file is refused, and
  `approve`'s stdout carries the peer line.
- **T2-4:** the nv deny snapshots both indices' public areas and the
  logical version, and requires them unchanged.
- **T2-5:** new case "record on a TPM restarted since its Clear".
  Red-proved with a reset-only mutant.
- **T2-6:** the fixture now sits at arm+4, just past the edge, and the
  comment says "within three lines".
- **T2-7:** the needle pins `seq=12;`, and a resumed-boot case asserts
  the note is absent.
- **T2-8:** the rolled-back case requires `rejected slot=A … version=0`
  and `slot=B … version=1`.
- **T2-9:** version, min_release, prev, roster and both signatures now
  vary with the input.
- **T2-10:** the stale doc is removed, and the Done(Verified) arm has a
  cover.
- **T2-11:** strict head copy, now that `approve` always writes a head.
- **T2-12:**
  - The stale case uses the same draft's diff against an older copy of
    the ledger.
  - `entries()` is renamed `ledger_snapshot()`.
  - Red-proved: a mutant `sign` leaving a stray file in the ledger made
    17 refusal cases fail.
- **T2-3:** the cover is tightened to a replaced tuple. It is proved
  with the inner-core gate run.

## Round 3 (6aeafc7..f5937f1)

### Findings
- **Security:**
  - S3-1 Major = F3-1 Major = T3-2a: in `ledger restore`, `--head` and
    `--supersede` were in the restore operator's hands. Any approval of
    the signed version (all of them are public in a replica) stood in for
    the head's owner, so a truncated copy restored (R49, R48).
  - S3-2 Minor: a fork at the approved version passed with only a note.
  - S3-3 Minor: the approval was written before the head, and the head
    write was not atomic.
  - S3-A1 Minor (Adjacent): P31 could be evaded with a `//` inside a
    string or a second source file.
  - S3-A2 Minor (Adjacent): P27's Cargo.toml check was line-based.
- **Functionality:**
  - F3-2 Minor: re-approving the identical draft needed `--supersede`.
  - F3-3 Minor: the runbook's lost-ledger text was stale.
  - F3-4 Minor: an unneeded or invalid `--supersede` was accepted
    silently.
  - F3-5 Minor: an inverted error message.
- **Testing:**
  - T3-1 Major: the new refused-`approve` cases did not check for no
    record and an unchanged head.
  - T3-2 Major: the restore supersede was untested on the deny side.
  - T3-3 Minor: the regime print overclaimed, and a D-23 sentence was
    stale.
  - T3-4 Minor: supersede was denied only on approver_id.
  - T3-5 Minor: "Restart" should have read "Resume".

### Round 3 Resolution Status
- **S3-1 / F3-1 / T3-2a / T3-2 (head checks on the approver's own
  device):**
  - `check_head` is shared by `approve` and `ledger approve-restore`.
    `approve-restore` now requires `--head` and takes `--supersede`,
    bound to the approver's own id, version and body.
  - `restore` keeps only the ledger-head check for heads passed to it,
    and no longer takes `--supersede`.
  - Fixtures (on approve-restore):
    - a copy below an approved version is refused;
    - with her own approval superseded, the copy is approved;
    - with someone else's approval, it is refused.
  - Red-proved with the approve-restore check disabled.
- **S3-2:** a different body at the approved version also requires
  `--supersede` ("this ledger is forked").
- **S3-3:** the head is written via a temporary file, sync and rename,
  before the approval exists. An existing `--out` is refused first.
- **F3-2:** the identical draft approved again needs nothing. There is a
  fixture, red-proved.
- **F3-4:** an unneeded `--supersede` is refused, with a fixture,
  red-proved. An unreadable or invalid file fails with its own error.
- **F3-3, F3-5:** fixed.
- **T3-1:**
  - All new refused-`approve` cases use `approve_refused`: no record, head
    byte-identical.
  - Red-proved: a mutant writing the head before the check made seven
    cases fail.
- **T3-4:** new case: carol's own approval of another body is refused.
- **T3-3:** the print says "before/after the ready checkpoint line", and
  D-23 is reworded.
- **T3-5:** the comment is fixed.
- **S3-A1:**
  - P31 uses `strip_rust_comments` and `unterminated`, and refuses any
    other source file under crates/pds/audit/src.
  - Fixtures: `sign` after a `//` inside a string; a second source file.
- **S3-A2:**
  - P27 parses each Cargo.toml (`tomllib`): dependency tables, target
    tables, renamed packages (`package =`) and `[features]` entries.
  - Fixture: a target dependency table renamed `pw`, enabling
    `verifier`.

## Round 4 (f5937f1..4c8a59c)

### Findings
- **Security:**
  - S4-1 Major: `restore` had lost the approved-version check of the heads
    given to it (an R43 narrowing). Restore approvers who had not
    approved the newest version could restore a copy missing it.
  - S4-2 Minor = F4-3: a missing head file silently disabled
    `approve-restore`'s checks.
  - S4-3 Minor = F4-1 Major: P27 missed `[workspace.dependencies]`,
    inherited and renamed dependencies, policy-wire's own features and the
    Makefile's `features_<pd>` (R1/R48: P16 already resolved inheritance).
  - S4-4 = A-1 Minor: P31 could be evaded with `#[path]` or `include!`.
- **Functionality:**
  - F4-2 Minor: `--supersede` verifies under the current roster, so it is
    refused after a key rotation.
  - F4-4 Minor: a superseded restore approval left the head as it was.
  - F4-5 Minor: the head moved before the approval file existed.
  - F4-6 Minor: the runbook's approve step was stale.
- **Testing:**
  - T4-1 Major: the forked-at-approved-version branch was untested.
  - T4-2 Major: approve-restore was never tested with a satisfied head.
  - T4-3 Major: no fixture pinned that an existing `--out` is refused
    before the head moves.
  - T4-4 Minor: `case_unneeded_supersede` did not use `approve_refused`.
    The round-3 count of "seven" cases was right, but the claim that
    "all" new refused cases used it was not: six cases use it.
  - T4-5 Minor: P27's parse paths were untested.
  - T4-6 Minor: the flake note misread the 12 bytes; the harness dropped
    the body.

### Round 4 Resolution Status
- **S4-1:**
  - `restore` checks both halves of every given head, fail-closed with no
    `--supersede`.
  - A satisfied or superseding `approve-restore` rewrites the approver's
    own head to the copy's head (F4-4).
  - Fixtures:
    - restore refuses bob's head (approved v1) under carol and alice's
      blank-head restore approvals;
    - the superseded allow case now goes on to restore with carol's
      rewritten head.
  - Red-proved.
  - Residual recorded in D-24: the operator picks which heads reach
    `restore`.
- **S4-2 / F4-3:** `approve-restore` refuses a missing head file. The
  fixtures use explicit blank heads. Fixture: approve-restore needs a head
  file. Red-proved.
- **S4-3 / F4-1:**
  - `dependency_entries` (check-pins) is now the one dependency walker for
    P16 and P27: workspace dependencies, target tables, both spellings,
    and inherited keys resolved to their package.
  - P27 also refuses policy-wire's own features that include `verifier`,
    and `features_<pd>` assignments naming it.
  - Fixtures:
    - deny: a workspace dependency; an inherited renamed key through
      `[features]` `pw?/verifier`; policy-wire's own `default`; Makefile
      `features_hs`; an invalid manifest;
    - allow: a renamed policy-wire without `verifier`.
- **S4-4 / A-1:** P31 refuses `#[path]` and `include!` in audit's
  main.rs, with a fixture.
- **F4-2 — Accepted:** recorded as a D-24 residual.
  - Anti-Deferral check: picking a roster from the copy would trust
    files that no chain link vouches for.
  - Worst case: an approver who rotated their key after a fork is refused
    and needs a fresh approval round. This is fail-closed.
  - Likelihood: low.
- **F4-5:** `write_reserved` creates `--out` (O_EXCL), then moves the
  head, then writes the record. A failed head write removes the
  reservation.
- **F4-6:** the runbook's approve and lost-ledger text matches
  `check_head`.
- **T4-1:** fixtures for the forked ledger through `approve-restore` and
  through `approve`, each denied and then allowed with `--supersede`.
  Red-proved with `held.is_some()`.
- **T4-2:** fixture: approve-restore with a satisfied head. It also
  checks that the head is rewritten.
- **T4-3:** fixture: approve to an existing `--out`, with the head
  unchanged. It was first red-proof-vacuous (the same draft wrote an
  identical head), so it now starts from a v0 head. Red-proved with a
  head-before-reservation mutant.
- **T4-4:** `case_unneeded_supersede` now uses `approve_refused`.
- **T4-5:** see S4-3.
- **T4-6:** the note names the legs (a 502 from tls-core on the backend
  leg; a client connect timeout). On a mismatch, release boot now
  reports the body prefix and tls's backend audit lines.

## Round 5 (4c8a59c..81a91d8)

### Findings
- **Security:**
  - S5-1 Minor = F5-1 Major: approve-restore moved the approver's head to
    an operator-supplied copy that was checked without bundle signatures
    and might never be restored. An approver could be wedged with no reset
    (R38, R48).
  - S5-2 Minor: a head recording nothing was accepted as a head.
  - S5-3 Minor = A5-1: P31 missed `include![..]`, `include !`, and
    `cfg_attr(.., path)` / split `#[path]` modules.
  - S5-4 Minor: P27's Makefile regex missed indirection; inherited keys
    without a declaration fell back to their own name.
- **Functionality:**
  - F5-2 Minor: a failed record write left a partial approval file.
  - F5-3 Minor: the runbook did not say a wiped approver cannot approve a
    restore.
  - F5-4 Minor: the release-boot diagnostic regex matched only
    `BackendUnavailable`.
- **Testing:**
  - T5-1 Major: restore's forked, missing-head and satisfied-head branches
    had no fixtures.
  - T5-2 Major: write_reserved's cleanup was unproven.
  - T5-3 Minor: P31's `include!` had no fixture.
  - T5-4 Minor: the underscore dependency spellings were untested.
  - T5-5 Minor: a wrong docstring.
  - T5-6 Minor: refused approve-restore cases did not check the head.
  - T5-7 Minor: nothing recorded the run behind the new KANI-* lines.

### Round 5 Resolution Status
- **S5-1 / F5-1:**
  - `approve-restore` takes `--keys-pub` and checks the copy with
    `verify_chain`, as `restore` does.
  - It no longer moves the ledger half of the head; it clears only a
    handed-back approval.
  - Fixtures: approve-restore verifies the copy's signatures (a flipped
    ML-DSA byte, head unchanged); with a satisfied head, the head is
    unchanged.
  - Red-proved (verify unsigned; head moved to the copy).
- **S5-2:**
  - A head recording nothing is refused ("no head recorded").
  - The fixtures' restore heads are real (`approver_head`: an `approve`
    of v0's draft against that ledger).
  - Fixture: approve-restore refuses a blank head. Red-proved.
- **S5-3 / A5-1:**
  - P31 refuses every out-of-line `mod x;`, whatever attribute names its
    file, and `include` followed by `!` with any spacing or delimiter.
  - Fixtures: `include ! [..]`; a `cfg_attr` path module.
- **S5-4:**
  - An inherited key with no workspace declaration is reported, not
    guessed. P16 keeps its fallback to the key.
  - Accepted, Minor: other workspaces' inheritance and Makefile
    indirection.
    - Every PD builds in the root workspace, where resolution is right.
      `features_<pd>` assignments are literal today.
    - P27 is a declared tripwire. The adjudicating controls are the laws'
      read-only slot MR and `open`'s token (P27 text).
    - Worst case: a host tool in another workspace enables `verifier`,
      which affects no device build.
- **F5-2:** a failed record write removes the partial file and says to
  approve the same draft again.
- **F5-3:** the runbook and D-24 say a restore needs two approvers whose
  head files survived, and what a two-member roster does otherwise.
- **F5-4:** the regex also matches `TlsClosed(Backend*)` and
  `TlsTimeout(BackendConnect)`, after a short settle.
- **T5-1:** fixtures:
  - restore refuses a given head forked at its approval;
  - restore refuses a missing head file;
  - restore with a satisfied given head (allow).

  Red-proved with the reviewer's combined mutant.
- **T5-2:** fixture: approve whose head cannot be written (no such
  directory) leaves no approval. Red-proved with the cleanup removed.
- **T5-3:** see S5-3.
- **T5-4:** fixture: an underscore `dev_dependencies` table.
- **T5-5:** the docstring is fixed, and it says the heads are checked
  before the approvals.
- **T5-6:** the refused approve-restore cases check the head is
  unchanged.
- **T5-7, and T-F3 from round 1, closed:**
  - The KANI-* lines come from the full `make kani` on z1mn: at 751e95b
    (17299 s, rc 0), then at f5937f1 (1356 s, rc 0). The second run
    re-proved inner-core in full and took the rest from the cache. It
    reported 164 harnesses, and every crate verified.
  - No crate under Kani changed after f5937f1; round 4 and round 5 touched
    tools/ and tests/ only.
  - The cache was copied to gx10 for the final `make check`.

## Round 6 (81a91d8..661bb66)

### Findings
- **Security:**
  - S6-1 Major: restore approvals never expired, so approvals stored with
    one restore were a permanent token. Replayed onto a copy cut back to
    that height, with no `--head`, they restored it with no approver
    involved.
  - S6-2 Minor = F6-3 = T6-2 (Major, testing): P31's `mod` rule ran per
    line, so split or raw-identifier declarations and macro-made modules
    slipped through, and the old `#[path]` arm was dropped.
  - S6-3 Minor = F6-1: superseding a genesis approval wrote a blank head,
    which approve-restore then refused.
  - S6-A1 Minor: the provenance of `--keys-pub` was not documented.
- **Functionality:** F6-2 Minor: the record-write retry hint was wrong for
  approve-restore.
- **Testing:**
  - T6-1 Major: a head-move mutant on the `--supersede` path survived.
  - T6-3 Minor: the inherited-undeclared branches had no fixtures.
  - T6-4 Minor: some head-unchanged assertions could not fail.
  - T6-5 Minor: a head file name collided.
  - T6-A1 Minor: a stale comment.

### Round 6 Resolution Status
- **S6-1:**
  - A restore approval is good for `RESTORE_APPROVAL_MAX_AGE_S` (24 h),
    with `RESTORE_APPROVAL_SKEW_S` (300 s) of clock skew
    (`approval::restore_approval_fresh`).
  - `restore`'s approval checks moved into `check_restore_approvals`,
    which takes `now`.
  - Unit tests: freshness boundaries; stale approvals refused by
    `check_restore_approvals` while fresh ones pass.
  - Red-proved: with the call removed, the stale test failed.
  - The runbook and D-24 are updated.
- **S6-2 / F6-3 / T6-2:**
  - P31 runs over the whole stripped text and refuses any `mod` token,
    `include` followed by `!` (newlines allowed), and any attribute with a
    `path` key.
  - Fixtures: a split raw-identifier `mod` with `#[path]`; a
    macro-generated module; `include` and `!` on separate lines. The two
    earlier forms are kept.
  - No inline-`mod` allow case: audit has no modules, and the rule is
    deliberately "none".
- **S6-3 / F6-1:**
  - Superseding a genesis approval keeps the copy's v0 as the ledger
    half. Every copy of the fleet shares v0.
  - Fixture: superseding a genesis approval leaves a usable head (a second
    approve-restore succeeds). Red-proved.
- **S6-A1:** the runbook says `--keys-pub` is the approver's own trusted
  copy.
- **F6-2:** each caller passes its own retry hint to `write_reserved`.
- **T6-1:**
  - The forked case asserts that after `--supersede` the ledger half is
    unchanged and `approved_version=-`.
  - Red-proved: the reviewer's mutant (the head moved to the copy on
    supersede) made the case fail.
- **T6-3:** fixtures: a P27 inherited `policy-wire` the workspace does
  not declare, with `verifier`; a P16 inherited `sha3` it does not
  declare, with features.
- **T6-4 — Accepted:** the head-unchanged checks in refused cases without
  `--supersede` are regression guards against a future head move before
  the refusal. The one that can fail today is the supersede-with-another's
  approval case.
- **T6-5:** `restore_with_heads` uses `{who}-restore.head`.
- **T6-A1:** the comment is fixed.

## Round 7 (661bb66..ac791c3)

### Findings
- **Functionality:**
  - F7-1 Minor: "every copy shares v0" holds per ledger, not per pin.
  - F7-2 Minor: the runbook omitted the 300 s future-skew refusal.
- **Security:**
  - S7-1 Minor: freshness runs on the restore host's clock. Within 24 h,
    or with the clock set back, stored approvals still replay, so D-24
    overstated it.
  - S7-2 Minor: P31 missed an aliased `include` (`use core::include as
    x;`).
- **Testing:**
  - T7-1 Major: every P31 `mod` fixture also carried a `path` attribute
    and vice versa, so neither arm was pinned.
  - T7-2 Major: the genesis-supersede fixture ran on a ledger at v0, so
    "v0" and "the copy's head" were indistinguishable.
  - T7-3 Minor: a temp dir leaked if setup panicked.

### Round 7 Resolution Status
- **F7-1:** D-24, the comment and the runbook say "every copy of this
  ledger" and give the recovery: remove the head file, and the next
  `approve` starts it again.
- **F7-2:** the runbook names the 5-minute skew and asks for synced
  clocks.
- **S7-1 — Accepted, with the docs made honest:**
  - D-24 and the runbook now say what the window does and does not stop.
    `restore` is no stronger than copying the files. What holds is each
    approver's head at their next `approve`, and every node's counter.
  - The residual's "roster of four or more" now applies only to fresh
    approvals.
  - Anti-Deferral check: a code control would still rest on files the
    operator supplies.
- **S7-2:** P31 refuses any `include` token. Fixture: include through an
  alias.
- **T7-1:**
  - The mod fixtures (split raw-identifier, macro-made) no longer carry a
    `path` attribute.
  - New fixture: a `path` attribute with no `mod`.
  - Red-proved arm by arm with a direct `check_audit_call` run on the
    real audit source plus each fixture text. Without the mod arm,
    split raw and macro go silent. Without the include arm, alias and
    newline go silent. Without the path arm, path-only goes silent.
- **T7-2:** the fixture signs v1 before the supersede and asserts that
  the head records `version=0` and `approved_version=-`. Red-proved with
  the copy-head mutant.
- **T7-3:** the test's temp dir is removed by a drop guard.

## Round 8 (ac791c3..1cf00ad)

### Findings
- **Functionality:**
  - F8-1 Minor: the "remove the head file" recovery shut that approver out
    of the pending restore, and the runbook did not say so.
  - F8-2 Minor: the docs said each approver's head catches a cut-back
    ledger; only the heads of the dropped versions' approvers do (and any
    later ledger head).
- **Security:**
  - S8-1 Minor: a nightly `${concat(..)}` builds `include` or `sign` from
    parts no token rule sees (rustc-confirmed).
  - S8-2 Minor: the recovery had no check to tell the F7-1 mix-up from a
    real fork.
- **Testing:** no findings. All round-7 red-proofs reproduced
  independently, and the counts and the `make test` skip are sound.

### Round 8 Resolution Status
- **F8-1 / S8-2:**
  - The runbook has the approver save the head file before a genesis
    supersede and put it back.
  - The head file is removed only after two checks: the head's v0 is the
    wrong copy's, and the ledger's v0 is the fleet's known genesis.
    Otherwise the refusal is treated as a fork and escalated.
  - It states that an approver without a head cannot approve the pending
    restore.
- **F8-2:** D-24 and the runbook name the heads that catch it: the
  dropped versions' approvers and later ledger heads, unless the approval
  is handed back.
- **S8-1:**
  - P31 refuses the mechanism: any metavariable expression (`${`) and any
    `#![feature]` in audit (audit uses neither).
  - Fixtures: a metavariable concat; a crate feature gate.
  - Red-proved arm by arm.
