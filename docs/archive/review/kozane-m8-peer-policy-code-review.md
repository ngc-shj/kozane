# Code Review: kozane-m8-peer-policy
Date: 2026-11-01
Review round: 3

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
