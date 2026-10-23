# Plan Review: secureos-m5-measured-release
Date: 2026-10-23
Review round: 1

## Changes from Previous Round

Initial review. Local LLM pre-screening raised three Minors (C9 priority
direction, C10 ECDH wording, C11 envelope size before C8), fixed before
round 1. During the round the orchestrator ran the C8 boot probe (U-Boot
`go` → Microkit loader at EL2, swtpm PCR 8 extend/read), recorded in C8.

## Functionality Findings

- **F1 Major design** — U-Boot `go` may drop to EL1 (Microkit manual,
  ZCU102 note on `do_go_exec`). **Resolved by execution:** the probe's
  loader printed `CurrentEL=EL2` on QEMU virt; recorded in C8, board
  question left to M7.
- **F2 Major design** — `tools/package`'s per-device image diff
  (`check_images`, which requires the image to differ) is incompatible with
  U-Boot assembling envelopes at boot. **Resolved:** C8 states the
  packaging model change; the published image is never modified per
  device; `check_images` is replaced by an assembled-image check through
  the shared assembly helper.
- **F3 Major design** — C5's member-set grep returns six crates
  (`verus_syn`, `verus_prettyplease` too), C1 provisions four.
  **Resolved:** C1 and C5 list all six.
- **F4 Major design** — `perms="w"` alone is refused by Microkit.
  **Resolved:** `rw`; no-RX is no IRQ + no RX code.
- **F5 Minor prose** — `Ready(pd)` suggests a producer field the record
  lacks. **Resolved:** per-channel codes, closed reason code.
- **F6-A Minor (Adjacent → Testing)** — A7 proxy feasibility has no
  criterion. **Resolved:** criterion in C14 (allow boot through the proxy
  first).

## Security Findings

- **S1 Major design** — the boot command copies at descriptor-supplied
  ranges without an on-device bounds check. **Resolved:** C8 checks ranges
  on-device before any copy.
- **S2 Major design** — what bounds a hostile `tpm` PD is unstated and
  untested. **Resolved:** C9 states the argument (ciphertext relay, no
  session key, nonces, per-client AEAD) and C10 adds a fake-TPM swap test.
- **S3 Minor design** — debug-print scans miss inline asm / wrappers.
  **Resolved:** C6 declares the release kernel as the boundary and the
  scans as tripwires with listed bypasses.
- **S4 Major design** — `Class:` missing on C1, C2, C6, C7, C9–C13.
  **Resolved:** every contract declares its class.
- **S5 Minor design** — TPM payloads vs PPC size. **Resolved:** C9 bounds
  every message to one 960-byte IPC (compile-time assertion) or chunks; no
  new MR.
- **S6 Minor design** — KEK zeroization in `tpm`. **Not applicable, with
  reason in C10:** `tpm` only relays parameter-encrypted ciphertext and
  never holds the KEK or session keys.
- **S7 Critical design, escalate: true** — HMAC tag compare not required to
  be constant-time. **Resolved:** I10.1 requires constant-time compare;
  mutation added. Escalation: round 2's security re-check runs on Opus with
  S7 in its input.
- **S8-A Minor (Adjacent → Functionality)** — C4 profiles differ in MIR
  optimisation. **Resolved:** both dumps at `-Zmir-opt-level=0`.

## Testing Findings

- **T1 Critical design** — I8.2 has no deny fixtures. **Resolved:** four
  deny + one allow fixture in C8.
- **T2 Critical design** — I10.3 has no mutation. **Resolved:** the
  envelope-open path joins the residue harness; a strip-the-wipe selftest
  case.
- **T3 Critical design** — the TPM command allowlist is untested.
  **Resolved:** core crate, Kani deny over arbitrary codes, allow for the
  nine.
- **T4 Major design** — post-cap Unseal refusal untested. **Resolved:**
  unit + Kani over call sequences.
- **T5 Critical design** — twin drift between expected-PCR tool, harness
  cap check and the U-Boot variant. **Resolved:** one extend helper, KAT
  fixture, harness variant generated from the shipped fragment.
- **T6 Major design** — swtpm isolation granularity. **Resolved:** state
  per boot, teardown checked.
- **T7 Major design** — C2's serialisation test has no red side.
  **Resolved:** paired run with the lock bypassed, race-free by
  construction.
- **T8 Minor design** — C13 lacks an allow fixture. **Resolved.**
- **T1-A, T3-A (Adjacent → Security)** — merged into S1 and C9's class
  statement.

## Adjacent Findings

F6-A (to Testing), S8-A (to Functionality), T1-A and T3-A (to Security):
all resolved as above.

## Quality Warnings

None. Merge was manual (json indices joined); no finding lacked evidence.

## Recurring Issue Check

### Functionality expert
- R1–R2, R5–R11, R13–R17, R19–R24, R26–R28, R30–R31, R33, R35–R37, R43, R45–R47, R51, R53–R54, R56–R57: N/A — plan-level document review, no code diff these checks apply to.
- R3 (Pattern propagation): Checked — C6 member-set grep reproduced exactly, no undercount.
- R4 (Event dispatch gaps) / R12 (Enum coverage): Checked — see F5 (wording only, no dispatch gap found).
- R16 (Dev/CI parity): Checked — confirmed gx10/z1mn are both aarch64 via `docker exec ... uname -m`.
- R18 (Allowlist sync): Checked — C9's TPM command allowlist is explicit and closed; no issue.
- R25 (Persist/hydrate symmetry): Checked — plaintext→sealed format is a hard cutover (no dual-read), consistent with "no downgrade."
- R29 (Citation/derived-claim accuracy): Checked — re-ran every quantitative claim cited above (Cargo.lock greps, debug-print grep, `uname -m`, `seL4_MsgMaxLength`, manual quotes) by execution; see F1, F3, F4 for the ones that disagreed with the plan text.
- R32 (Runtime-shape boot test): Checked — C6's readiness migration (console text → audit lines) preserves run.py's existing need for a readiness signal; no gap.
- R34 (Adjacent pre-existing bug deferred): Checked — see F6-A.
- R38 (Async state machine): Checked — `tpm`'s per-client {Fresh→Unsealing→Done|Failed} plus permanent post-cap refusal has an explicit terminal state; no fail-open gap.
- R39 (Zeroization): Checked — I10.3/I11.1 cover it; no functional gap (crypto-strength judgment is Security's lane).
- R40 (Cross-boundary serialization): Checked — see F5; also confirmed TPM PPC messages (CreatePrimary/Import/Unseal etc.) fit comfortably under seL4's 120-word (960-byte) `seL4_MsgMaxLength`.
- R41 (Declared capability without backing path): Checked — see F2.
- R42 (Member-set derivation): Checked — both C6's and C5's grep re-run; C5's disagreed with the prose list (F3).
- R44 (Gate exit status): N/A this round — no gate-script diff reviewed, only read for context.
- R48 (Parallel adjudicators): Checked — `tpm`'s allowlist is the single verdict point before any command reaches the device; no issue.
- R49 (Control class declared): Checked — every contract already states its class (gate / enforceable-boundary-under-stated-assumption / detection-only); C8 is explicit about this. No issue.
- R50 (Verification preconditions): Checked — see F1, F3 (claims re-derived from actual toolchain/repo state, not assumed).
- R52 (Control reach extended): Checked — C9's new `tpm` role will need the `laws.toml` "device"-MR-kind owner restriction (currently `driver`/`timer` only) and the `[priority] below` table extended; this is schema-mechanical, not a functional gap, so no separate finding.
- R55 (In-band sentinel collision): Checked — `tools/package`'s `check_blob` already rejects a blob carrying another kind's magic; no collision.

### Security expert
- R1 Shared utility reimplementation — no finding (plan reuses secret-blob, key-core, existing crypto helpers)
- R2 Constants hardcoded in multiple places — no finding observed in plan text
- R3 Incomplete pattern propagation — see S3 (debug-print pattern coverage)
- R4 Event/notification dispatch gaps — no finding; audit/tpm channel wiring as described is closed-set
- R5 Missing transaction wrapping — N/A (no DB transactions in scope)
- R6 Cascade delete orphans — N/A
- R7 E2E selector breakage — N/A (not UI)
- R8 UI pattern inconsistency — N/A
- R9 Transaction boundary fire-and-forget — N/A
- R10 Circular module dependency — no finding
- R11 Display group ≠ subscription group — N/A
- R12 Enum/action group coverage gap — no finding; Caller→label tables remain closed and exhaustive as described
- R13 Re-entrant dispatch loop — no finding
- R14 DB role grant completeness — N/A
- R15 Hardcoded environment-specific values in migrations — N/A
- R16 Dev/CI environment parity — N/A (no CI, SC9, pre-existing and accepted)
- R17 Helper adoption coverage — see S3 (grep-based migration list vs wrapper paths)
- R18 Config allowlist/safelist synchronization — no finding; policy/laws.toml amendments are mechanically checked (C7)
- R19 Test mock alignment — N/A (no new mocks introduced)
- R20 Multi-statement preservation in mechanical edits — N/A
- R21 Subagent completion vs verification — N/A (process rule, not code)
- R22 Perspective inversion for established helpers — no finding
- R23 Mid-stroke input mutation in UI controls — N/A
- R24 Single migration mixing additive + strict constraint — N/A
- R25 Persist/hydrate symmetry + access scope — no finding; MR access scope (L1/L2) is symmetric and checked
- R26 Disabled-state UI without visible cue — N/A
- R27 Numeric range hardcoded in user-facing strings — N/A
- R28 Grammatical inconsistency in toggle labels — N/A
- R29 Citation/derived-claim accuracy — plan's TPM 2.0 Part 1 / SP 800-108 KDFa/KDFe citations are internally consistent with standard TPM semantics; not independently verified against primary spec text — citation unverified
- R30 Markdown autolink footguns in citations — no finding
- R31 Destructive operations without confirmation — no finding; tools/package's staging/atomic-rename/signal handling (pre-existing) is sound and unaffected by M5 changes
- R32 New long-running runtime artifact without boot smoke test — covered by C14's integration cases
- R33 CI config duplication — N/A (no CI, SC9)
- R34 Pre-existing bug deferred without justification — the z1mn-only TCG timing flake is explicitly acknowledged with reasoning in the M4 deviation log; not silently deferred
- R35 Production-deployed component without manual test plan — covered by C14 + "User operation scenarios"
- R36 Suppression/markerless weakening as substitute for fix — no finding
- R37 Internal jargon in user-facing strings — N/A
- R38 Async/persisted state machine fail-open/wedge — tpm's per-client state machine fails closed (Unavailable) on fault, consistent with I11.1; no fail-open path found
- R39 Lifecycle secret/metadata zeroization — see S6 (tpm-side KEK zeroization not stated; client-side is, per I10.3/L12)
- R40 Cross-boundary serialization shape vs strict consumer — no finding; C10's response parsing is explicitly strict ("every length checked")
- R41 Declared capability without working backing path — no finding; SC31 (explicit TPM2_Quote) is correctly scoped as unavailable, not overclaimed
- R42 Class-membership derivation — see S3 (C6's grep-based member set is surface-form, not derived from the defining primitive; mitigated by the separate ELF-symbol check and the kernel-level backstop)
- R43 Fix-induced security-boundary widening — the L1/L5/L13 amendments widen what key-role PDs may do (new channel to tpm); appropriately re-bounded by tpm's own declared untainted/channel-restricted status in the same law text — no uncompensated widening found
- R44 Gate exit status read through lossy channel — no finding; carried-over check-selftest mechanism (pre-existing, unchanged by M5) already adjudicates via unpiped exit status
- R45 Repo-wide gate scaling super-linearly — no finding; C4/C5's member sets are bounded by Cargo.lock/dependency-closure size
- R46 Scope-blind binding resolution in a security analyzer — no finding; C7's laws checker fixtures are stated per amendment clause
- R47 Surface-form adjudication where an interpreter defines meaning — see S3 (debug-print detection should defer to the kernel's CONFIG_PRINTING as the authoritative interpreter, which it already does structurally, but the PD-level scan doesn't frame itself that way)
- R48 Parallel adjudicators, different semantics — no finding
- R49 Undeclared control class / claim stronger than implementation — see S4 (missing Class: declarations on C1/C2/C6/C7/C9/C10/C11/C12/C13)
- R50 Verification preconditions unverified — no finding; I8.3's "computable from public release files alone" is a real (non-proxy) predicate
- R51 Decision bound to a name, not the object — no finding; SRK pinning is by TPM "name" (a content-committing hash), which correctly binds to the object, not a label
- R52 Control reach extended without re-auditing the control — no finding
- R53 Numeric gate threshold set without headroom measurement — no finding; M5 doesn't set new tainted-PD budget ratios (tpm is untainted, exempt from the cap)
- R54 Control suspension via ambient context state — no finding
- R55 In-band sentinel colliding with legitimate value — no finding; the PCR8 "cap" is a hash-chain extend, not a sentinel-matchable value
- R56 Progress-marker heal direction — N/A
- R57 Ordering/cursor key without total order — N/A
- RS1 Timing-safe comparison — see S7 (HMAC verification constant-time requirement not stated)
- RS2 Rate limiter on new routes — no finding; tpm/key/pqkey already use CNTPCT token buckets per existing pattern (not newly introduced, but consistent)
- RS3 Input validation at boundaries — no finding; C10's response parsing is explicitly bounds-checked, no bare type-assertion pattern present
- RS4 Personal-identifying data in committed artifacts — no finding
- RS5 Untrusted external security parameter without floor/whitelist — no finding; TPM command allowlist, fixed PCR selection, pinned SRK template all act as whitelists; no externally-negotiated weak parameter found
- RS6 Incomplete sanitization / escape-character ordering — N/A (no string-escaping logic in scope)

### Testing expert
- R1–R57: not applicable — this is a prose test-strategy plan, not an implementation diff; none of the code-duplication/UI/migration/DB-role/CI-config patterns R1–R57 target have code to inspect yet. No findings.
- RT1 (mock-reality divergence): no mocks/doubles described in the plan's test strategy; swtpm and the real crate are used directly (C10 interop) — no finding.
- RT2 (testability verification): checked before every recommendation above (T1–T8); all target existing unit/Kani/package-fixture/selftest/integration infra already in this repo.
- RT3 (shared constant in tests): `run.py` already has precedent (`rust_const()`) for reading protocol constants from source rather than hardcoding; plan doesn't say whether TPM constants (cap separator, SRK template, allowlist codes) will follow suit — soft note only, not elevated to a finding.
- RT4 (race-test vacuous-pass guard): overlaps T7 — C2's serialization test lacks a stated red mutation.
- RT5 (test call-path includes the production primitive): good overall — C10's interop test drives swtpm "the way the PD would," C8/C14 exercise the real U-Boot/TPM path, C9's Kani harness covers the real TIS state machine. No new finding beyond T1–T4 (which are about missing coverage, not bypassed primitives).
- RT6 (new exports without test diff): not applicable — plan stage, no diff.
- RT7 (new guard/gate must be proven able to fail): T1, T2, T3, T7 above.
- RT8 (vacuous denial-path test): checked — C14's deny cases (wrong image, tampered descriptor, foreign TPM, A7 proxy) all assert both the status (`KeyUnavailable`) and the absence of the guarded effect (no handshake); no vacuous pattern found.
- RT9 (twin drift): T5 above (expected-PCR host tool vs. harness-only U-Boot variant vs. Python cap computation).
- RT10 (deny-only guard, no allow pairing): T3 (zero coverage), T4 (allow-only, deny untested), T8 (allow fixture not counted). Elsewhere (C1, C3, C4, C14) pairing is explicit and good.
- RT11 (fixture outlives its run / cleanup skipped on failure): T6 above (swtpm state isolation/teardown granularity).

---

# Round 2
Date: 2026-10-23

## Changes from Previous Round

All round-1 findings applied to the plan (see round 1 resolutions).
Functionality and Testing re-checked incrementally (Sonnet); Security
re-ran on Opus as the S7 escalation tier.

## Functionality Findings

- F1–F5, F6-A: verified resolved (F1's constant recomputed; C4's member
  count and `-Zmir-opt-level` checked on the pinned nightly).
- **F7 (new in round 2) Minor prose** — the L6 amendment rewrote only the
  hashing clause. **Resolved:** C8 replaces the whole L6 sentence.

## Security Findings (Opus)

- **S7** — settled **Minor** (escalate: false): the expected tag is
  per-boot and the client stops after one failure, so no timing oracle
  accumulates; the constant-time requirement stays as hardening.
  `ct_eq` is `wg_core::crypto::ct_eq` (C10 now names it; no third copy).
- S1, S3, S5, S8-A, T1-A, T3-A: verified sound. S4: classes present; C9
  and C10 overclaimed (→ S9, S11). S2 resolution was wrong (→ S9). S6
  holds only for an honest `tpm` (→ S9).
- **S9 (new in round 2) Critical design** — an active A7 or hostile `tpm`
  can obtain the plaintext KEK: own session under a PCR-only policy, TPM
  reset + replay of public extends, or in-flow rewrite of an un-HMACed
  session. **Resolved:** authPolicy adds PolicyAuthValue (TPM checks the
  command HMAC, closing in-flow rewrite); C9/C10 claims restated
  (integrity against active A7, confidentiality against passive A7 only);
  RM5-5 recorded with worst case, likelihood and closure (SC32, M7);
  swtpm relay deny/allow/red tests and an own-session documentation test.
- **S10 (new in round 2) Minor prose** — "no downgrade" rationale wrong.
  **Resolved:** reason restated, A6 envelope substitution accepted under VE6.
- **S11 (new in round 2) Major design** — `tpm` is a shared callee across
  the L2 key domains with no handle ownership. **Resolved:** per-client
  handle ownership, refuse-all after Done/Failed, PCR_Extend never
  forwarded, flush before Done, Kani deny/allow/red; class restated.
- **S12 (new in round 2) Minor** — on-device range check wrap.
  **Resolved:** no-wrap form and boundary stated; wrap fixture.
- **S13 (new in round 2) Minor** — AEAD nonce / KEK freshness.
  **Resolved:** fresh KEK per envelope; host check.
- **S14 (new in round 2) Minor** — taint seed and L5 vs new device roles.
  **Resolved:** exemptions keyed to pinned phys ranges; fixtures.
- **S15 (new in round 2) Minor** — verifier policy-digest source.
  **Resolved:** from the object public; deny fixture.

## Testing Findings

- T1, T3–T6, T8: verified resolved. T2 resolved, completed by T10. T7
  partially (→ T9).
- **T9 (new in round 2) Major design** — C2's red side was timing-
  dependent though claimed race-free. **Resolved:** redesigned; the green
  outcome only errs toward "blocked", the red side has a stated 30 s
  margin and fails loudly.
- **T10 (new in round 2) Major design** — the KEK residue reach was not
  tied to ct-shape identity. **Resolved:** the envelope-open closure joins
  `policy/ct-shape.toml`.
- **T11 (new in round 2) Minor prose** — swtpm stop vs cap read order.
  **Resolved.**
- **T12-A (Adjacent → Security)** — `ct_eq` tripwire is surface-form.
  Settled by the Opus tier under S7 as proportionate at Minor.

## Recurring Issue Check (round 2)

### Functionality expert
- R1–R2, R5–R11, R13–R17, R19–R24, R26–R28, R30–R31, R33, R35–R37, R43, R45–R47, R51, R53–R54, R56–R57: N/A — unchanged from round 1 (plan-level document review).
- R3: Checked — no change needed this round.
- R4/R12: Checked — F5's resolution confirmed consistent with every other multi-producer `AuditEvent` code.
- R16: N/A this round.
- R18: Checked — C9's allowlist unchanged and still closed.
- R25: Checked — unchanged, still a hard cutover.
- R29: Checked — re-verified `sha256(0^32‖0^32)`, the seven-crate `debug_assert` grep, the `-Zmir-opt-level` flag, and the exact L6 quote (F7).
- R32: Checked — C14's per-boot swtpm lifecycle doesn't change the readiness-wait mechanism.
- R34: N/A this round.
- R38: Checked — no fail-open path found.
- R39: N/A this round.
- R40: Checked — C9's message-size rule is consistent with I10.1.
- R41: Checked — F2's resolution gives the backing path.
- R42: Checked — C4's seven-crate set accurate under the union formula.
- R44: N/A. R48: N/A. R52: N/A. R55: N/A.
- R49: Checked — every contract carries a `Class:` line.
- R50: Checked — evidence re-derived from primary sources.

### Security expert (Opus)
- R1: S7 note: ct_eq has two copies already; C10 must pick one.
- R2: Checked, no issue. R3: S11. R4–R9: N/A. R10: Checked. R11: N/A. R12: Checked. R13–R16: N/A. R17: Checked. R18: S11. R19–R21: N/A. R22: Checked. R23–R24: N/A. R25: Checked. R26–R28: N/A.
- R29: S7 (ct_eq location), S10 (rationale); TPM Part 1 §19.6 in S9 is "citation unverified".
- R30–R31: N/A. R32: Checked. R33: N/A. R34: S10. R35–R36: Checked. R37: N/A.
- R38: S11. R39: S6 holds for an honest tpm only (S9). R40: Checked. R41: S9. R42: S11. R43: S11. R44: N/A. R45–R46: Checked. R47: S7 tripwire proportionate at Minor. R48: Checked. R49: S9, S11. R50: Checked. R51: Checked; S9 fix binds the object name via cpHash. R52: S14. R53–R54: N/A. R55: Checked. R56: N/A. R57: S12.
- RS1: S7 settled Minor; ct_eq required. RS2: N/A. RS3: Checked. RS4: Checked. RS5: S15; S9. RS6: N/A.

### Testing expert
- R1–R57: still not applicable — plan-level document review.
- RT1: no finding. RT2: checked. RT3: unchanged soft note. RT4: T9. RT5: good. RT6: N/A. RT7: T1–T4, T8 closed; T9. RT8: no new finding. RT9: T5 model resolution; T10. RT10: pairs present. RT11: T6 resolved; T11.

---

# Rounds 3–4 (targeted re-checks)
Date: 2026-10-23

Per the project's stopping rule, only new Critical/Major findings were
re-checked, each by the expert who raised it.

## Security (Opus)

- **S9 closed** (round 3): claims restated, PolicyAuthValue makes the TPM
  check the command HMAC (stripped `encrypt` or unsalted rewrite fails at
  the TPM), RM5-5 names the own-session / reset-replay residual.
- **S11 closed** (round 3): handle ownership, refuse-all after Done, PCR_Extend
  never forwarded.
- **S16 (new in round 3) Major** — PolicyAuthValue missing from the allowlist
  and the ownership set, so the S9 fix could not run. **Closed** (round 4).
- **S17 (new in round 3) Minor** — client derives the object Name from its
  envelope. Resolved.
- **S18 (new in round 3) Minor** — unseal flow runs in `init`; tainted input
  cannot reach Import. Resolved.
- **S19 (new in round 3) Minor** — CreatePrimary ownership, parent check,
  entry removal on flush. Resolved.
- Round-4 note (Functionality-side, not a finding): Done is entered by an
  explicit message after the client's flushes. Applied to C9.

## Testing

- **T9, T10 closed** (round 3); T11 confirmed.
- **T13 (new in round 3) Major** — fresh-KEK check had no red-proof.
  **Closed** (round 4): mutation list entry with a failure-only needle.
- C8 wrap fixture paired with an allow case at the boundary.

## Saturation call (round 4)

- Rounds completed: 4 (round 1 full, round 2 incremental, rounds 3–4
  targeted).
- Open Critical/Major: none in any category.
- Open findings against the design: none.
- Remaining Minors: none open; every Minor was resolved in the plan.
- Accepted residuals live in the plan (RM5-1 to RM5-5, SC30–SC33), each with
  worst case, likelihood and closing owner.
- Go/No-Go: C1–C14 locked.
