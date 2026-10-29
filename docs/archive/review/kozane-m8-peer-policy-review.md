# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 1

## Changes from Previous Round
Initial review. The local-LLM pre-screen (R2 bound ownership, constant
homes, `key` changes, canonical sort, C8 wording) was applied before it.

## Resolution (round 1 → plan v2)
Every Critical and Major finding is reflected in the plan; the plan cites
each by ID where it acts on it. Highlights:
- T1, T2, T4, T14 → C6 deny with a live peer; C13 split into named cases
  with per-case swtpm state, host counter reads, per-run fixtures.
- T3 → `fi_policy` variant; P1 covers non-orderly stops.
- S1, S4, F10, F11 → C3 attributes, two-signature delete policy,
  wrapping base, Names compiled from `[policy]`, provisioning `v0` from a
  verified bundle.
- S2, S3, S8, F12, F13 → C2 ledger, pinned roster, total diff, genesis,
  fleet file.
- F1, F2, S6, S11 → D7 `auditkey` PD; unsigned checkpoint form; boot ID
  and reset/restart counts fixed by the signer.
- S5 → D5 narrowed (drivers RM8-8), Clear performed by `tools/provision`.
- S7, F5 → D9 flow table; `TunnelPacket` record.
- F3, F4, F15 → C10/C11 enumerations; F6 → rosenpass slice API;
  F7 → `policy_finished` and DONE/FAILED on every path; F8 → exact
  `BUNDLE_MAX` media; F9, T8 → C4 file and self-test lists.
- T5, T6, T7, F16 → generic Kani harness; nondeterministic ADVANCE;
  `limits` bounds and `policy-wire` without libcrux; `release-seq` leaf.
- T9–T13, T15–T19, F14, F17, S9, S10, S12 → applied as written.
No finding was skipped.

## Merged Findings

### Critical

| # | Severity | Problem | Impact | Recommended Action | Flagged By |
|---|----------|---------|--------|-------------------|------------|
| T1 | Critical | C6 deny test is vacuous: "both slots invalid → no handshake" passes without a barrier because no peer list exists, so the assertion is trivially true. | A broken or missing peer-validation barrier would go undetected; an attacker with a validly signed but policy-refused slot could open a tunnel. | Use validly signed slots refused for a non-crypto reason (RolledBack / BelowFloor) holding a real peer; send initiation, assert no reply; inject LAN frame, assert backend count 0; verify selftest injection `hs` ignores Unavailable. | Testing |
| T2 | Critical | C13 deny rows do not assert the policy counter is unchanged after a refused boot; the revocation row lacks a positive control proving the counter *does* advance on acceptance. | A silent counter regression (e.g., counter not persisted, or always returning 0) would pass the test suite, defeating anti-rollback. | Read `NV_POLICY_CTR` from host after each boot; add positive control: revoked peer succeeds under v0 earlier, non-revoked peer succeeds under v1 with counter advanced. | Testing |

### Major

| # | Severity | Problem | Impact | Recommended Action | Flagged By |
|---|----------|---------|--------|-------------------|------------|
| M1 (F1+S6) | Major | `audit→key` PPC violates the "key PD has at most one pp caller" law (check.rs:529–543) because audit is tainted; checkpoint signing also creates an oracle: a compromised audit can request signatures that reveal key material. | PPC law violation blocks build; security oracle allows key extraction if audit is compromised. | Amend L2 or separate key-role PD with audit as only caller. Key draws `boot_id` itself, binds signatures to it, uses strictly increasing seq, rate-limits requests; drop `audit→rng`; host zeroizes `audit_sk` after package. | Functionality, Security |
| F2 | Major | Checkpoint signing blocks audit during key init (cap barrier up to 330 s); no checkpoint form exists when key/rng is unavailable. | Audit is stalled for up to 5.5 minutes during provisioning; no observable record if key is missing. | No PPC until ready; provide unsigned checkpoint form; rng fallback path. | Functionality |
| F3 | Major | C11 omits: Policy taint exemption for 5 tainted callers, priority below entries, tpm-role channel rule, prefill-only-on-secrets exception, slot MR kind, policy audit channel. | Incomplete design checklist leads to implementation gaps in channel/priority/taint rules. | Amend C11 with all six missing items. | Functionality |
| F4 | Major | Policy has no audit ring; new event codes, record encoding `(a,b)` for version/slot/release_seq, and shared `POLICY_UNAVAILABLE` halt code are all undefined. | No observability into policy decisions; halt code ambiguity prevents correct upstream handling. | Define audit ring, event codes, record encoding, and halt code in policy-core. | Functionality |
| F5 | Major | `data→inner` carries raw IPv4 without `msgs` framing with peer identity; reverse owner lookup duplicates data routing logic. | No peer attribution on data frames; duplicated routing logic creates divergence risk. | Add `msgs` framing with peer; eliminate reverse owner lookup or derive it from the routing table. | Functionality |
| F6 | Major | Rosenpass `Responder<const P>` takes compile-time peer count; API change to slice + count needed for dynamic peer sets. | Cannot express variable peer count; blocks fleet scaling. | Change API to `&[Peer]` + count; update all callers. | Functionality |
| F7 | Major | `DONE` is emitted on every policy exit path; gate `CLIENTS=3`, Busy rule, `BUSY_TIMEOUT_NS` and `CAP_BARRIER_TIMEOUT_NS` are re-derived rather than measured; P2 not measured under real contention including PCR9 hashing. | Timeout values may be too tight under load; DONE spam pollutes audit. | Gate CLIENTS=3 with concrete fix; derive timeouts from measurement; P2 must be measured under real contention incl. PCR9 hashing. | Functionality |
| F8 | Major | Slot media shorter than `BUNDLE_MAX` leave a non-zero tail (uninit DRAM, 0xFF on flash) causing valid bundles to be rejected. | Provisioning fails on media with non-zero fill; false-negative bundle validation. | Require media exactly `BUNDLE_MAX` zero-padded, or document that U-Boot zero-fills. | Functionality |
| F9 | Major | Descriptor v3 conflicts with `measure.py` COUNT/DESC_LEN/pairs/ENVELOPE_ROOM, `boot.cmd` hard-coded ranges, `run.py` Package.media, `tools/package`, `release.py` check_placeholder; slot addresses below 0x6fb00000. | Build/packaging pipeline breaks; measure.py produces wrong counts. | Reconcile all six tools with Descriptor v3 layout. | Functionality |
| F10 | Major | NV Name depends on per-deployment `authPolicy` (delete policy digest); config `[policy]` must carry it; attributes unspecified; `phEnableNV` dependency undocumented. | Provisioning cannot derive Name without deployment-specific config; missing attributes cause TPM errors. | Specify `[policy]` section carrying authPolicy digest; document all NV attributes; state `phEnableNV` SET requirement. | Functionality |
| F11 | Major | `MAX_PROVISION_STEPS` blocks re-provision as fleet version grows (counter increments each provision). | Fleet cannot re-provision after ~MAX_PROVISION_STEPS releases; operational lockout. | Use wrapping base, no per-step increments; counter reflects release version only. | Functionality |
| F12 | Major | No genesis rule for first bundle. | First provisioning has no predecessor to verify against; undefined behavior. | Define genesis rule (e.g., `prev = 0` accepted only when counter is 0). | Functionality |
| F13 | Major | Device validates per-node overlaps (inside prefix, gateway, neighbours) that the fleet-wide signer cannot see; `render`/`sign` must take every node config. | Signer cannot detect prefix/gateway conflicts; device rejects valid fleet-level decisions. | Extend `render`/`sign` input to include all node configs; move overlap checks to signer or document as device-side residual. | Functionality |
| F15 | Major | Missing files: supervisor-core CHILDREN, tools/supervisor-allowlist, tpm2 envelope KEY_MAX_PEERS/KEY_BLOB_PER_PEER, tools/package v2 parser, run.py build deployments B/C and gateway.toml peer checks, pq GATEWAY_RP_HASH/PEER_RP_HASH halts, layout::policy and channel ids, KANI-POLICY-CORE, CASES_FOR_GATE, tests/tools/test_config_build.py, run.py audit regexes with seq=. | Multiple build/test/verification paths reference non-existent artifacts; CI cannot pass. | Create or stub all listed files with correct interfaces. | Functionality |
| S1 | Major | Anti-rollback rests entirely on the delete policy; re-provision with operator-chosen `initial_version` or base redefinition (same Name) is a single-person rollback. | A single compromised operator can roll back the entire fleet. | Make delete policy M-of-N (two PolicySigned + PolicyCommandCode(NV_UndefineSpaceSpecial)); provision takes `initial_version` only from a verified bundle + C2 approvals; C3 states boundary = counter + delete policy. | Security |
| S2 | Major | Signer has no ledger: stale `--prev` or a second body per version re-admits a revoked peer. | Revoked peers can be re-admitted by replaying an old signing session. | Persisted append-only per-fleet ledger; sign refuses `prev != head` and a second body per version. | Security |
| S3 | Major | Roster is supplied by the signing operator; `ts` field is unchecked. | Operator can substitute a malicious roster; timestamp spoofing undetected. | Pin roster (compiled digest or two-person-signed); distinct keys and ids; make `ts` informational or bounded. | Security |
| S4 | Major | NV attributes unspecified: must forbid ORDERLY and CLEAR_STCLEAR, set AUTHWRITE/AUTHREAD with empty authValue, set WRITELOCKED in base Name constant; P1 tests Name after lock and forced reset; RM8-4 requires `phEnableNV` SET. | TPM may allow destructive operations (Clear, orderly shutdown) on policy NV; tests don't verify lock enforcement. | Specify all attributes explicitly; add P1 test cases for post-lock Name and forced reset; document `phEnableNV` SET. | Security |
| S5 | Major | Release floor leaves eth drivers exposed (they enable receive before Verified); `tls` also links to inner; nothing detects a skipped Clear. | Traffic may be processed before policy verification; undetected stale TPM state. | Drivers enable receive only after Verified (or narrow claim + residual); fix `tls` sentence; `tools/provision` performs Clear or refuses when SRK Name equals pre-M8. | Security |
| S7 | Major | Stateless reverse authz admits unsolicited LAN→peer traffic. | Any LAN host can inject traffic into a peer tunnel without an established flow. | Bounded flow state in inner: LAN→tunnel only for peer-opened flows; or declare and document as residual. | Security |
| T3 | Major | Crash-after-ADVANCE has no deterministic trigger; the test cannot reliably reproduce the "counter advanced but bundle not written" state. | The most dangerous crash window (counter bumped, bundle lost) is untested. | Fault-inject variant `fi_policy` printing marker after confirmed ADVANCE and stopping; host reads counter; then normal boot same TPM state expects accepted v2; keep variant out of release; P1 add counter survives non-orderly stop. | Testing |
| T4 | Major | C13 uses one stateful chain; row 3 is contradictory; Swtpm lifecycle unspecified. | Rows depend on prior row state, making failures hard to isolate; contradictory row produces false pass/fail. | Each row its own case from fresh provisioning at chosen `initial_version`; state slot contents per row; specify swtpm lifecycle; keep dir-removed check. | Testing |
| T5 | Major | Kani I1.1 is unbounded over ~4.2 MB `BUNDLE_MAX` (SPK_LEN 524160); proof exceeds `CASE_TIMEOUT_S`. | Kani proof will time out; property test is non-functional. | Use generic/`cfg(kani)` small sizes or stub key bytes; unwind bounds for I8.1, I5.3. | Testing |
| T6 | Major | I5.1 pure-step framing leaves ADVANCE glue unproved; the step state machine does not model the nondeterministic ADVANCE outcome. | The critical counter-advance logic is not covered by the formal model. | Model ADVANCE outcome nondeterministic in step state machine; PD glue single match pinned by check-pins; unit fixtures for ADVANCE refused / wrong value / counter<base. | Testing |
| T7 | Major | `policy-core` deps (libcrux, rosenpass-core→mce460896) couple ingress-core/inner-core Kani keys; ingress-core re-proof exceeds `CASE_TIMEOUT_S`. | Kani proofs are intractable due to transitive dependencies. | Bounds in dependency-free crate; add policy-core to `kani_crates`, KANI-POLICY-CORE; host split. | Testing |
| T8 | Major | C4 red-proofs: 10 disjoint pairs vs 3 measure-pair cases, wrap anchors change, PCR9 twin case missing, `read_pcrs` PCR9 selection untested. | Red-proof coverage is insufficient; PCR9 selection bugs undetected. | Add remaining measure-pair cases, PCR9 twin, and `read_pcrs` selection tests. | Testing |
| T9 | Major | C7 broken needles not listed: key-wipe anchor, `check_harness_matches_config` reads `cfg["peers"]`, `test_peer_binding` (deployment c), pq/hs anchors (integration-pq-residue, c7-rndr-fault, integration-residue); UNIT-* count decreases vs raise-only manifest. | Broken test references cause silent skips; manifest drift undetected. | List all broken needles; reconcile UNIT-* count with manifest policy. | Testing |
| T10 | Major | Forbidden patterns are assigned to `laws` which has no source grep capability; should use `check-pins check_forbidden` with fixtures. | Forbidden pattern checks silently pass (no enforcement). | Move to `check-pins check_forbidden` with concrete fixtures. | Testing |
| T11 | Major | Boot time vs `BOOT_TIMEOUT_S=60` and 4 h integration-count not reconciled; P2/P3 pass criterion unclear. | Tests may time out or pass with insufficient headroom. | Define P2/P3 pass = pq ready with headroom; baseline `make test` wall clock; reconcile with `BOOT_TIMEOUT_S`. | Testing |
| T12 | Major | `audit-verify` tests use fixtures only; no integration capture verified with packaged key; tail = N unverified lines; fixtures for lost>0, cross-boot replayed checkpoint, wrong device key missing. | Real audit verification path untested; key mismatch and cross-boot replay undetected. | Add integration capture verified with packaged key; fixtures for lost>0, cross-boot replayed checkpoint, wrong device key. | Testing |
| T13 | Major | C2 matrix gaps: forged approval sig, wrong approval domain, prev not verifying, one key under two roster IDs, version == prev / < prev, check-pins rule fixtures; C1 each signature half bad. | Signing verification logic has untested edge cases; equivocation and domain-confusion undetected. | Add all listed cases to C2/C1 matrices. | Testing |
| T14 | Major | Integration bundle/key provenance unspecified: per-run keys and roster in tmp, compiled into image; bundles via approve/sign; slots in per-boot copies; wrong-Name state as test-only provisioning fixture. | Integration tests may use stale keys or ambiguous slot state; non-reproducible. | Specify: per-run keys/roster in tmp compiled into image; bundles via approve/sign; slots in per-boot copies; wrong-Name as test-only provisioning fixture. | Testing |
| T15 | Major | C8 deny needs positive control (tunnel up), listener on Q, audit names peer+reason; reverse direction cases missing; no-matching-rule fixture missing. | Deny path may pass vacuously; audit output format unverified. | Add positive control; listener on Q; assert audit names peer+reason; add reverse direction and no-matching-rule cases. | Testing |

### Minor

| # | Severity | Problem | Impact | Recommended Action | Flagged By |
|---|----------|---------|--------|-------------------|------------|
| F14 | Minor | Selection: identical bodies tie-break undefined, `u32::MAX` overflow, reason precedence; C13 rows 3 and 5 inconsistent. | Edge-case selection may panic or produce inconsistent results. | Define tie-break, handle overflow, state reason precedence; fix C13 inconsistency. | Functionality |
| F16 | Minor | `RELEASE_SEQ` in policy-core invalidates Kani keys each release; leaf crate. | Kani proof invalidation cascade on every release; increased CI cost. | Consider removing `RELEASE_SEQ` from policy-core or isolating in leaf crate. | Functionality |
| F17 | Minor | "~4 MB leave pq" (one peer today ~0.5 MB); "ingress/inner drop every frame" (they block in init; frames queue in driver rings). | Prose misleads implementors about memory and frame handling. | Correct both statements to match actual behavior. | Functionality |
| S8 | Minor | Canonical diff must be total over body fields (property test). | Partial diff may miss field-level changes. | Add property test asserting diff covers all body fields. | Security |
| S9 | Minor | `policy_client::open` contradicts I1.2; Verified carries body sha256, `open` re-hashes and parses via token-requiring constructor. | API inconsistency; potential confusion in implementation. | Reconcile `open` with I1.2; document re-hash and token-requiring constructor. | Security |
| S10 | Minor | Media attacker can suppress updates; revocation at node is detection + RM8-3; runbook blocks direct access to non-compliant node. | Undocumented residual risk. | Document as residual; reference RM8-3; add runbook entry. | Security |
| S11 | Minor | No cross-boot linkage in audit; TPM `resetCount`/`restartCount` and policy version not in h0 or boot line; audit-verify doesn't flag gaps. | Gaps in audit chain undetected. | Include `resetCount`/`restartCount` and policy version in h0 and boot line; audit-verify flags gaps. | Security |
| S12 | Minor | C3 NV grep is surface-form; label tripwire; real control is gate allowlist + Kani I3.3 listing refused codes (NV_UndefineSpaceSpecial, NV_WriteLock, Clear, HierarchyChangeAuth). | Grep-based check may be bypassed; actual control is elsewhere. | Relabel as tripwire; point to gate allowlist + Kani I3.3 as real control. | Security |
| T16 | Minor | Manifest counters / gate wiring not enumerated. | Gate wiring changes may be missed during refactoring. | Enumerate manifest counters and gate wiring. | Testing |
| T17 | Minor | C9 boundary `min_release < RELEASE_SEQ`; duplicate BelowFloor row. | Redundant test row; boundary condition untested. | Add boundary case; remove duplicate. | Testing |
| T18 | Minor | New-gate selftest injections not listed (PCR9 check removed, ADVANCE before verify, Name check skipped, cap not waiting, authorize default Allow, equivocation bypass). | Selftest coverage incomplete for new gate logic. | List all injection points for new gate. | Testing |
| T19 | Minor | VE20 classification missing. | Verification evidence for VE20 cannot be mapped to a test. | Add VE20 classification. | Testing |

---

## Quality Warnings

| Finding | Flag | Reason |
|---------|------|--------|
| F12 | [VAGUE] | "No genesis rule for first bundle" provides no file/line reference and no concrete fix (only a generic suggestion). Needs: where the genesis rule should live, what the acceptance condition is, and which test covers it. |
| T16 | [VAGUE] | "Manifest counters / gate wiring not enumerated" has no specific file path or example of what is missing. Needs: the manifest file path and the specific counters/gates that are absent. |
| T19 | [VAGUE] | "VE20 classification missing" has no file reference and no description of what VE20 covers. Needs: the VE20 requirement text and where the classification should appear. |

## Recurring Issue Check
### Functionality expert
R1 F5. R2 Checked. R3 F9,F15. R4 F4. R5-R11 N/A. R12 F4,F15. R13 Checked. R14-R15 N/A. R16 Checked. R17 N/A. R18 F3. R19-R28 N/A. R29 F17. R30 N/A. R31 Checked. R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 F11. R39 N/A. R40 F5. R41 F2. R42 Checked. R43 F1. R44-R47 N/A. R48 F13. R49 Checked. R50 Checked. R51 Checked. R52 F3. R53 F7. R54 N/A. R55 F8. R56-R57 N/A.
### Security expert
Fired: R3 (S8), R14 (S3), R29 (S1,S4), R38 (S2), R42 (S5), R43 (S6), R47 (S12), R48/R51 (S9,S2), R49 (S1,S3,S5,S6,S7,S10), R55 (S4), R57 (S11).
Checked OK: R1, R2, R12, R18, R25, R31, R36, R39, R40, R44, R50, R52, R53, R56; RS1, RS3, RS5.
N/A: R4-R11, R13, R15-R17, R19-R24, R26-R28, R30, R32-R35, R37, R41, R45, R46, R54, RS2, RS4, RS6.
### Testing expert
R1 OK. R2 T7. R3 T9. R4-R6 N/A. R7 T9. R8-R15 N/A. R16 OK. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 T10. R30-R31 N/A. R32 OK. R33 N/A. R34 OK. R35 OK. R36-R37 N/A. R38 T3/T6. R39 N/A. R40 T12. R41 T10. R42 T1. R43-R48 N/A. R49 T6. R50 T10/T11. R51-R52 N/A. R53 T11. R54-R55 N/A. R56 T3. R57 T12.
RT1 OK. RT2 T12. RT3 OK. RT4 N/A. RT5 T12/T14. RT6 T16. RT7 T3/T8/T18. RT8 T1/T2/T15. RT9 T12. RT10 T13. RT11 T4/T14.

---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 2

## Changes from Previous Round
Plan v2 applied every round-1 finding (see round 1's Resolution). Round 2
reviewed v2 incrementally. No Critical findings. Majors: F18–F22, F24,
F25, F27; S13–S15; T20–T24, T26–T29. Most are fallout from v2's
additions (`auditkey`, the flow table, the ledger).

## Resolution (round 2 → plan v3)
All findings applied; none skipped.
- F18, S19 → four raw clients, CLIENTS/BUSY/cap timeouts re-derived,
  per-client ReadClock row, I3.2 extended.
- F19 → `auditkey` has no ring; status via PPC replies.
- F20 → six descriptor ranges, 12 new pair cases.
- F21 → constant h0; boot identity only in signed checkpoints.
- F22, F23, S16 → per-peer flow quota, FIN both ways + linger, RST in a
  valid direction, ICMP echo only, constants in `limits`; RM8-10.
- F24 → device `prev_sha256` check (`PrevMismatch`); C13 row.
- F25 → fleet file from the same renderer, digests compared.
- F26, S17 → `open` returns Result; no re-hash, VE3/R2 stated.
- F27, T28 → ` seq=<n>` trailer stripped in one function.
- F28, T20, T30, T31 → forked-ledger fixtures; C13 table rebuilt
  (rolled-back is the C6 deny with an allow twin; genesis merged).
- F29, S14 → provisioning `v0` = verified ledger head + two-operator
  re-provision record; existing indices handled.
- F30, S20 → seq rule with one ready exemption; `auditkey-core`.
- S13 → PolicySigned bound to nonceTPM, cpHashA, no tickets, fixed
  policyRef, distinct dedicated keys.
- S15 → D11: ledger = signed history re-verified; genesis roster pinned;
  approver heads.
- S18 → Clear failure aborts; SRK Name changes; reset-0 epochs need a
  provisioning record; lockout custody in RM8-4.
- T21 → provision once, seal once, start versions by host NV_Increment.
- T22 → `TpmProxy` replaces the U-Boot variant.
- T23 → `fi_policy` envelopes, kill at marker, release check over all
  variants.
- T24 → injection parses slot A without a token; needle on the WG
  response.
- T25 → counter read after kill, password session.
- T26, T27 → flow-table and `auditkey` tests, bounded Kani.
- T29 → injection-to-case map; cap ordering caught by Kani I3.1.
- T32–T35 → manifest list, I5.1 crate, host scheduling, `finally` cleanup.

## Functionality expert (round 2)
Resolved: F1-F6, F8, F10-F14, F16, F17 (with F18-F21 from D7). F7 partly (F18). F9 regressed (F20). F15 partly (F27). R29 figures verified except "7".
F18 Major (design, R3/R53) auditkey = 4th raw tpm client: CLIENTS=3 asserts (gate.rs:46, tpm main.rs:42), BUSY_TIMEOUT 240->360 s, cap 330->450 s; ReadClock not allowlisted; contradicts C3 wording.
F19 Major (design, R42) Key PD maps only its secrets MR (laws check.rs:473-490): auditkey cannot have an audit ring; drop it or amend.
F20 Major (design, R3/R29) Descriptor v3 misses audit envelope: 6 ranges, 12 new pairs (9 slot, 3 audit envelope), not 7.
F21 Major (design) h0 needs boot_id before auditkey ready; make h0 constant, bind boot/reset/restart in signed checkpoints.
F22 Major (design, R38) Flow table: FIN expiry breaks half-close; oldest eviction across peers; per-peer quota, FIN both ways + linger.
F23 Minor (design) MAX_FLOWS, idle timeout, home crate, clock, stack, ICMP errors, ICMP rule ports unspecified.
F24 Major (design, R41/R49) prev_sha256 claimed as device counterpart but C5 never checks it.
F25 Major (design, R48) Fleet file vs compiled NodeConfig can drift; generate from same sources, compare digests.
F26 Minor (design, R51) open infallible yet parses; re-hash dropped silently; NodeConfig owner crate.
F27 Major (design, R3/R40) seq= suffix breaks run.py READY_LINE and other regexes.
F28 Minor (prose) C13 equivocation row unbuildable under ledger; rolled-back row mislabelled as C6 deny.
F29 Minor (design) provision (Python) v0 verification path via tools/policy verify; behaviour when indices already exist.
F30 Minor (design) Ready checkpoint vs auditkey rate rule; state as seq >= last + CHECKPOINT_EVERY with one exception.
## Recurring Issue Check (Functionality r2)
R1 Checked. R2 F23. R3 F18,F20,F27. R4 Checked. R5-R11 N/A. R12 Checked. R13 Checked. R14-R17 N/A. R18 F19. R19-R28 N/A. R29 F20. R30 N/A. R31 Checked. R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 F22. R39 N/A. R40 F27. R41 F24. R42 F19. R43 N/A. R44-R47 N/A. R48 F25. R49 F24. R50 Checked. R51 F26. R52 F18. R53 F18. R54 N/A. R55 Checked. R56 F21. R57 Checked.

## Security expert (round 2) — no Critical
Resolved: S4, S5, S6, S8, S10, S11, S12. Partly: S1 (S13, S14), S2/S3 (S15), S7 (S16), S9 (S17). Sound: two PolicySigned in one session; POLICY_DELETE semantics; WRITEDEFINE lock survives Clear; Name includes PLATFORMCREATE; ReadClock reset/restart not obfuscated; checked_add and slot-A tie-break.
S13 Major (design, R49/R51) PolicySigned delete authorizations not bound: require nonceTPM = session nonce, cpHashA = UndefineSpaceSpecial(index), expiration >= 0 (no tickets), fixed policyRef; op1 != op2 by key and Name; dedicated keys; P1 cases replay and wrong cpHash refused.
S14 Major (design, R49) Re-provision v0 accepts any historical bundle: v0 must equal authenticated ledger head; two operators sign a re-provision record (node, v0, body_sha256) verified by provision.
S15 Major (design, R49/R25) Ledger/roster unauthenticated file: ledger = signed bundles + approval records, sign re-verifies whole chain; genesis roster digest pinned in tools/policy per fleet (check-pins); truncation detected against external head checked by approve; fixtures tampered roster, truncated ledger, re-genesis.
S16 Minor (design, R49) Flow table per-peer share, eviction within share; close only on FIN/RST in valid direction; declare LAN spoofing within a live flow.
S17 Minor (prose, R49) No-writer boundary modulo VE3/R2 DMA.
S18 Minor (design, R31/R55) Clear needs lockout/platform auth and disableClear clear; resets reset/restart counts; provision aborts on Clear failure and checks SRK Name changed; audit-verify new epoch only with provisioning record; RM8-4 lockout custody.
S19 Minor (design, R3/R52) ReadClock not in shared ALLOWED; tpm reads clock and answers auditkey via high-level IPC or per-client allowlist; extend I3.2.
S20 Minor (design) auditkey rate rule: seq >= last_seq + CHECKPOINT_EVERY except one ready checkpoint, overflow refused, fixed-width fields, auditkey-core Kani-proved; audit-verify fails on a boot without signed checkpoint.
## Recurring Issue Check (Security r2)
Fired: R3 (S19), R25 (S15), R31 (S18), R49 (S13-S17), R51 (S13), R52 (S19), R55 (S18). Checked OK: R1, R2, R12, R14, R18, R29, R36, R38, R39, R40, R42, R43, R44, R47, R48, R50, R53, R56, R57; RS1, RS3, RS5. N/A: rest.

## Testing expert (round 2)
Resolved: T2, T5, T7, T8 (7 pairs verified), T9-T13, T15, T17, T19. Partly: T1 (T24, T30), T3 (T23), T4/T14 (T20, T21), T6 (T33), T16 (T32), T18 (T29). LINT-PDS 16->18 correct.
T20 Major (design, RT8/R41) Ledger refuses equivocation v2' and below-floor second v1 fixtures; fork ledger copy at head v1.
T21 Major (design, R16/RT2) Per-case provisioning with Clear changes SRK, every package needs reseal; provision once at v0=0, seal once, make v0=1 on a copy by host NV_Increment.
T22 Major (design, RT5/RT7) Test-only U-Boot variant changes PCR 0-7 so unseal fails for another reason; use TpmProxy to swallow/add a PCR 9 extend.
T23 Major (design, RT7) fi_policy: test_release_boot checks only fi_net (loop FAULT_INJECT_VARIANTS); own sealed envelopes; harness kills QEMU after marker.
T24 Major (design, RT7) C6 hs-ignores-Unavailable injection cannot make a handshake succeed; inject parse of slot A without token; needle "hs answered the initiation".
T25 Minor (prose, RT2) Counter read only after QEMU kill, before close(); NV_Read needs password session and Name check.
T26 Major (design, RT6/RT2) Flow table unit tests (eviction, FIN/RST, idle with clock input, ICMP id, cross-peer reply) and bounded Kani with small MAX_FLOWS; measure inner-core re-proof.
T27 Major (design, RT6/RT8) auditkey: integration for unsigned form (audit envelope sealed to other PCRs), ready-gating test, one-signature-per-interval and increasing seq units, distinct boot IDs across boots.
T28 Major (design, R3) seq= position vs 93 run.py audit regexes; add run.py and check-selftest regex updates.
T29 Major (design, RT7) cap-not-waiting needle ordering-dependent; use Kani I3.1 or TpmProxy delay; map each injection to its catching case.
T30 Minor (prose, RT8) C6 both-slots vs C13 rolled-back B empty; name allow twins.
T31 Minor (design) genesis duplicates advance-revoke boot 1.
T32 Minor (prose, RT6) Manifest list missing totals and per-crate counters; host_crates + policy-wire, release-seq (LINT-CRATES 35->37).
T33 Minor (design, R41) I5.1 state machine crate unnamed; must be in kani_crates.
T34 Minor (design) No solver-free host for QEMU during re-proof; say which host gives way.
T35 Minor (design, RT11) Case-scoped permall cleanup in finally.
## Recurring Issue Check (Testing r2)
R1 OK. R2 OK. R3 T28. R4-R15 N/A. R16 T21. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R31 N/A. R32 OK. R33-R40 N/A. R41 T20/T33. R42 OK. R43-R48 N/A. R49 OK. R50 T25. R51-R52 N/A. R53 OK. R54-R57 N/A. RT1 OK. RT2 T21/T25. RT3 OK. RT4 N/A. RT5 T22. RT6 T26/T27/T32. RT7 T22/T23/T24/T29. RT8 T20/T27/T30. RT9 N/A. RT10 OK. RT11 T35.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 3

## Changes from Previous Round
Plan v3 applied every round-2 finding. Round 3: no Critical. Majors F31,
F32, S21, S22, T36, T37, T38; the rest Minor.

## Resolution (round 3 → plan v4)
All applied; none skipped.
- F31 → anchor = signature-verified `current` bundle at any floor;
  provisioning writes v0 to slot A; writer rule "never the accepted
  slot"; PrevMismatch recovery; C13 `no-anchor`, `floor-lowering` rows.
- F32 → `auditkey` notifies `audit` at the end of init; C11 key rule.
- S21 → provisioning record signed after Clear, bound to the new SRK
  Name and fleet, own domain, pinned record keys; fixtures.
- S22 → approver replicas, `ledger restore`, equal-length fork fixture.
- T36 → `tpm_start_at` helper. T37 → `TpmProxy`-held Unseal as an
  event-ordered control. T38 → bad-Ed25519 boot and per-signature skip
  injections.
- F33 → policy requests interleave, no handles; cap adds policy time.
- F34, F35, T40 → fork points; equivocation at v1/v1′; twins named.
- F36 → flow quota const asserts. S23 → cpHash spelled out, tool gate
  labelled, tests. S24 → prev wording. S25 → ready checkpoint ordering,
  verifier rule, anchored strip. T39 → injection form and needle.
  T41 → raw text kept. T42 → wrong-Name fixture without Clear.

## Functionality expert (round 3)
Resolved: F18, F20 (12 pairs verified), F21-F23, F25-F27, F29, F30. Partly: F19 (F32), F24 (F31), F28 (F34). BUSY 360 s verified. All C13 rows consistent with C5 except equivocation (F35).
F31 Major (design, R38/R41) prev rule needs current anchor in other slot: fresh node with only v0+1, overwritten current slot, reflash-first bad-release recovery (anchor BelowFloor) all become PrevMismatch. Anchor = signature-verified, version == current, any floor; provisioning writes v0 to slot A; writer never overwrites accepted slot; Unavailable nodes: A gets v(current); PrevMismatch recovery documented; C13 row floor-lowering advance.
F32 Major (design, R41) Ready-gating circular (status only via PPC replies; PPC blocks until init). auditkey notifies audit at end of init; check-pins anchors on it; C11 key-role rule.
F33 Minor (design, R53) Do policy STATE/ADVANCE take gate flow ownership? State; derive CAP.
F34 Minor (design, RT2) v1' signed from fork at head v0; prev-mismatch v2 from v1' fork.
F35 Minor (design, RT7) Equivocation row only distinguishes reason; use both slots current.
F36 Minor (design, R2) const assert MAX_FLOWS % MAX_PEERS == 0 and quota >= 1 incl. cfg(kani).
## Recurring Issue Check (Functionality r3)
R1 Checked. R2 F36. R3 Checked. R4-R11 N/A. R12 Checked. R13 Checked. R14-R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31 Checked. R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 F31. R39 N/A. R40 Checked. R41 F31,F32. R42 Checked. R43-R47 N/A. R48 Checked. R49 Checked. R50 Checked. R51 Checked. R52 Checked. R53 F33. R54 N/A. R55 Checked. R56 Checked. R57 Checked.

## Security expert (round 3) — no Critical
Resolved: S16-S19, S20 (leftover S25). Partly: S13 (S23), S14 (S21), S15 (S22). Confirmed: audit is sole UART writer printing static names/integers (no injection of seq= or checkpoint lines); expiration >= 0 correct; flow quota; ReadClock row; TpmProxy realism.
S21 Major (design, R51/R49) Re-provision record replayable on fresh/replaced TPM: sign after Clear, bind to new SRK Name (or EK) + fleet_id, domain kozane-reprovision-v1\0; name/pin the operator record keys (distinct from delete keys); fixtures replayed record, other SRK.
S22 Major (design, R38/R41) Lost ledger wedges fleet: approvers keep replicas; ledger restore accepts a copy whose chain verifies and contains/extends every reachable approver head (version and digest), two approvals, no flag; wiped approver re-init; fixture equal-length fork.
S23 Minor (prose, R49/R29) PolicySigned: cpHash = CC_NV_UndefineSpaceSpecial || Name(nvIndex) || Name(RH_PLATFORM); expiration = 0 with non-empty nonceTPM; label tool gate; tests empty nonce refused by tool, TPM refuses cpHash for other index.
S24 Minor (prose, R49) Device prev_sha256 only proves slot linkage; reword C2/D11; explain why PrevMismatch refuses instead of falling back.
S25 Minor (design, R55/R57) Ready exemption needs seq > last_seq; audit-verify fails on non-increasing checkpoint seq per boot; strip anchored / seq=\d+\r?$/; state which seq is signed.
## Recurring Issue Check (Security r3)
Fired: R29 (S23), R38 (S22), R41 (S22), R49 (S21,S23,S24), R51 (S21), R55 (S25), R57 (S25). Checked OK: R1, R2, R3, R12, R14, R18, R25, R31, R36, R39, R40, R42, R43, R44, R47, R48, R50, R52, R53, R56; RS1, RS3, RS5, RS6. N/A rest.

## Testing expert (round 3)
Resolved: T22-T26, T29, T31-T35. Partly: T20 (T40), T21 (T36), T27 (T37), T28 (T41), T30 (T40). Arithmetic verified: 12 pairs, LINT-CRATES 38, LINT-PDS 18.
T36 Major (design, R16/RT2/RT11) Host NV_Increment on a permall copy needs a helper: swtpm on copy, CMD_INIT, SET_DATAFD, Startup(CLEAR), NV_ReadPublic Name check, NV_Increment k times, read back, Shutdown(CLEAR), handoff permall; P1 covers it.
T37 Major (design, RT7/RT8) auditkey ready-gating line-order assertion cannot fail; use TpmProxy holding auditkey's Unseal reply until K audit lines from other sources appear; red-prove by deleting the gate.
T38 Major (design, RT7/RT10) Ed25519-only-bad has no executor; add half-bad boot with bad Ed25519; injections "Ed25519 skipped", "ML-DSA skipped".
T39 Minor (design, RT7) ADVANCE-before-verify injection form (ADVANCE on raw parsed version before verify); needle = counter assertion failure text; per-boot expected counters.
T40 Minor (design, RT8/R41) Equivocation row refused as PrevMismatch even without the branch; use start 1, A v1, B v1'; name twins for equivocation and prev-mismatch; v1' forked at head v0.
T41 Minor (design, R3/RT9) Keep raw Console text for audit-verify; anchor strip at end of line; raw-needle self-test case.
T42 Minor (design, R16) Wrong-Name fixture without TPM2_Clear (delete with two operator signatures, redefine) on a copy.
## Recurring Issue Check (Testing r3)
R1 OK. R2 OK. R3 T41. R4-R15 N/A. R16 T36,T42. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R40 N/A. R41 T40. R42 OK. R43-R48 N/A. R49 OK. R50 OK. R51-R52 N/A. R53 OK. R54-R57 N/A. RT1 OK. RT2 T36. RT3 OK. RT4 N/A. RT5 OK. RT6 OK. RT7 T37,T38,T39. RT8 T37,T40. RT9 T41. RT10 T38. RT11 T36.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 4

## Changes from Previous Round
Plan v4 applied every round-3 finding. Round 4: no Critical. Majors: F37
and T43 (the same defect: the equivocation fixture was below the floor),
T44 (the held-Unseal ready-gating control was timing-dependent). The rest
Minor; S26 and S27 are design-labelled Minors.

## Resolution (round 4 → plan v5)
All applied; none skipped.
- F37, T43 → fixture v1″ (floor within range, different peers) for
  `equivocation`; v1′ stays for floor rows.
- T44 → ready-gating moved to a host-tested state machine in
  `audit-event` with a fake `auditkey`, red-proved; one pinned PPC site.
- S26 → record tool reads the SRK Name itself and re-checks the ledger
  head; `srk_name` in the signed checkpoint tuple; RM8-11 for blind
  signers.
- S27 → restore approvals with their own domain and bound head; tools
  refuse a copy below any recorded head; fixtures.
- S28 → raw clients' refused set includes NV_Increment/NV_Read of the
  policy indices.
- F38 → `current=` on the unavailable line; runbook reads it.
- F39, T45 → end-to-end capture from a single boot; reset continuity on
  fixtures only.
- F40, T46 → record keys in fixtures; record fixture matrix.

## Functionality expert (round 4)
Resolved: F31-F34, F36. Gate check: no conflict with gate.rs Busy/ownership. Partly: F35 (F37).
F37 Major (design, R41) equivocation row uses below-floor v1', dropped before select -> Use{A}; add v1'' with floor ok, or judge equivocation at any floor; name variants per row.
F38 Minor (design, a; R38) Unavailable line needs current=<n> (unknown on STATE refusal) for the runbook.
F39 Minor (design, b) Harness Startup(CLEAR) inspections bump resetCount between boots; reset continuity asserted on fixtures only.
F40 Minor (prose, a) C13 fixtures omit operator record keys.
## Recurring Issue Check (Functionality r4)
R1 Checked. R2 Checked. R3 Checked. R4-R11 N/A. R12 Checked. R13 Checked. R14-R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31 Checked. R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked (F38 aside). R39 N/A. R40 Checked. R41 F37. R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55-R57 Checked.

## Security expert (round 4) — no Critical, no Major
S21-S25 resolved. Checked no finding: anchor at any floor (ledger one body per version; advanced bundle still floor-checked); auditkey notify (one bit, no taint); policy requests interleaving (password auth, no handles/sessions).
S26 Minor (design, b; R49/R51) Provisioning record binding checked only by operator-run tools: record tool re-runs verify --ledger (v0, body == head); signers witness the SRK read or state blind signing as residual; bind record to something in the capture (audit public key / SRK Name boot line) and define matching in audit-verify.
S27 Minor (design, b; R38/R41) ledger restore can rewind to the lowest head among signing approvers: own domain binding restored head version+digest+fleet; each approver checks its own head; restore refuses below any recorded head; fixture restore approval under bundle domain.
S28 Minor (prose, a; R29) Add NV_Increment and NV_Read of the policy indices to I3.2's refused set for raw clients, Kani case.
## Recurring Issue Check (Security r4)
Fired: R29 (S28), R38 (S27), R41 (S27), R49 (S26), R51 (S26). Checked OK: R1, R2, R3, R12, R14, R18, R25, R31, R36, R39, R40, R42, R43, R44, R47, R48, R50, R52, R53, R55, R56, R57; RS1, RS3, RS5, RS6. N/A rest.

## Testing expert (round 4)
Resolved: T36, T38, T39, T41, T42. Partly: T40 (T43), T37 (T44).
T43 Major (design, R41/RT2/RT7) equivocation row: v1' is floor-raised so it is dropped before select; node accepts 1 regardless. Add v1'' (same version, floor ok, different body) from the v0 fork for equivocation; keep v1' for below-floor, floor-lowering, prev-mismatch.
T44 Major (design, RT7/RT8/RT11) Held-Unseal control stalls the single-threaded tpm PD, depends on a 60 s timeout, may stay green with the gate removed, cannot identify auditkey's Unseal reliably. Use K > CHECKPOINT_EVERY with eth-in-dropped frames, identify via Load inPublic, assert on proxy state; or move the gate check to a host-level audit test with a fake auditkey.
T45 Minor (design, b; R16) tpm_start_at advances resetCount; take the audit-verify capture from a start-0 single-boot case or record harness resets.
T46 Minor (prose, a; R49/R51) Provisioning-record fixtures: delete keys instead of record keys, same key twice, wrong fleet_id, wrong domain, v0/body not ledger head.
## Recurring Issue Check (Testing r4)
R1 OK. R2 OK. R3 OK. R4-R15 N/A. R16 T45. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R40 N/A. R41 T43. R42 OK. R43-R48 N/A. R49 T46. R50 OK. R51 T46. R52 N/A. R53 OK. R54-R57 N/A. RT1 OK. RT2 T43. RT3 OK. RT4 N/A. RT5 OK. RT6 OK. RT7 T43,T44. RT8 T44. RT9 OK. RT10 OK. RT11 T44.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 5

## Changes from Previous Round
Plan v5 applied every round-4 finding. Round 5: no Critical; one Major
(F41, the audit record encoding); Minors F42, S29, S30, T47–T49.

## Resolution (round 5 → plan v6)
All applied; none skipped.
- F41 → policy events carry reason/slot in code ranges, the value in
  `a`, `b` stays `lost`; `StateRefused` code instead of a sentinel.
- F42, T47 → `audit-core` crate with the ready state machine and
  `ready_input`; unit tests; check-pins fixtures; injections.
- T48 → first-boot baseline rule tied to the provisioning record.
- S29 → RM8-11 reworded (every signer trusts the host read).
- S30, T49 → restore approvals under the roster at the restored head,
  distinct approvers; fixtures.

## Functionality expert (round 5)
Resolved: F37, F39, F40; F38 intent met (encoding F41). v1'' row, srk_name source (Envelope::srk_name, client.rs:308), restore approvals checked OK.
F41 Major (design, R40/R55) Record.b is always the lost count (audit-event lib.rs:39; printers print r.b as lost=; C10 sums it). current/slot/reason cannot ride in b; current=unknown has no free value. Use code ranges (FRAME_DROPPED_BASE pattern) for reason/slot, value in a, b = lost; own code for STATE refused; Kani/unit case.
F42 Minor (design, a) Ready-gating state machine belongs in a new audit-core crate used only by pds/audit, not the shared audit-event; host_crates, LINT-CRATES, check-pins target.
## Recurring Issue Check (Functionality r5)
R1-R3 Checked. R4-R11 N/A. R12 Checked. R13 Checked. R14-R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31 Checked. R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked. R39 N/A. R40 F41. R41 Checked. R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55 F41. R56 Checked. R57 Checked.

## Security expert (round 5) — no Critical, no Major, no design finding
S26, S27, S28 resolved.
S29 Minor (prose, a; R49) RM8-11: every signer trusts the provisioning host's unauthenticated TPM read while SC31 is deferred, not only remote signers.
S30 Minor (prose, a; R41) Restore approvals verified under the roster in force at the restored head, two distinct approvers; fixtures same approver twice, approver not in roster.
## Recurring Issue Check (Security r5)
Fired: R41 (S30), R49 (S29). Checked OK: R1, R2, R3, R12, R14, R18, R25, R29, R31, R36, R38, R39, R40, R42, R43, R44, R47, R48, R50, R51, R52, R55, R56, R57; RS1, RS3, RS5, RS6. N/A rest.

## Testing expert (round 5)
Resolved: T43, T46. Partly: T44 (T47), T45 (T48).
T47 Minor (design, b; R4/RT7) PD glue mapping notification to ready input untested; ready_input(channels) keyed on layout channel in the crate with unit tests; check-pins requires channels pass only through it; injections ready-gate removed and second PPC site; PPC-site rule deny/allow fixtures.
T48 Minor (design, b; R16) First-boot resetCount baseline undefined in audit-verify; state rule + fixture; verify e2e capture with the run's provisioning record (srk_name match).
T49 Minor (prose, a; R3/RT7) Restore fixtures: single approval, same approver twice, approval bound to different head version/digest/fleet.
## Recurring Issue Check (Testing r5)
R1-R3 OK. R4 T47. R5-R15 N/A. R16 T48. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R40 N/A. R41 OK. R42 OK. R43-R48 N/A. R49-R51 OK. R52 N/A. R53 OK. R54-R57 N/A. RT1 OK. RT2 OK. RT3 T49. RT4 N/A. RT5 OK. RT6 OK. RT7 T47,T49. RT8-RT11 OK.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 6

## Changes from Previous Round
Plan v6 applied every round-5 finding. Round 6: no Critical, no Major.
Design-labelled Minors S31, F43; prose Minors F44, T50–T53.

## Resolution (round 6 → plan v7)
All applied; none skipped. S31 → baseline only at a post-Clear capture
start, otherwise `--after` chaining; baseline always printed; fixtures.
F43 → `InnerDenied` code range. F44 → runbook `StateRefused` branch.
T50–T53 → named encoding cases and fixtures.

## Functionality expert (round 6) — no Critical, no Major
F41, F42 resolved (encoding fits Coalescer::record; audit-core scoped; LINT-CRATES 39 verified). Baseline rule and restore approvals checked OK.
F43 Minor (design, b; R3/R40) InnerDenied{peer, reason} has no code range; specify INNER_DENIED_BASE + peer x INNER_REASONS + reason, coalesced, a = total, b = lost; same range tests.
F44 Minor (prose, a; R12) Runbook branch for StateRefused (current=unknown): no slot write, TPM/NV diagnosis or re-provision.
## Recurring Issue Check (Functionality r6)
R1-R2 Checked. R3 F43. R4 Checked. R5-R11 N/A. R12 F44. R13 Checked. R14-R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31-R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked. R39 N/A. R40 F43. R41-R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55-R57 Checked.

## Security expert (round 6) — no Critical, no Major
S29, S30 resolved. Encoding (u16 code ranges), audit-core gating, restore approvals checked OK.
S31 Minor (design, b; R16/RS6) First-boot baseline accepts any reset with a record, so boot gaps at capture boundaries go unreported. Always print the baseline; --after <last signed checkpoint> chains continuity; silent baseline only for a capture starting at the post-Clear boot; fixtures for a gap between chained captures and a reset>0 first boot.
## Recurring Issue Check (Security r6)
Fired: R16, RS6 (S31). Checked OK: R1-R4, R12, R14, R18, R29, R31, R36, R38-R42, R44, R47-R52, R55-R57; RS1, RS3, RS5. N/A rest.

## Testing expert (round 6) — no Critical, no Major, prose only
T47-T49 resolved; LINT-CRATES 35->39 verified.
T50 Minor (prose, a; RT3/RT7/R55) Name encoding cases: ranges in the disjointness test; last code decodes and last+1 is Unknown; out-of-range reason clamps without aliasing into the other slot; StateRefused prints current=unknown whatever a holds.
T51 Minor (prose, a; RT2) Deny fixture for the PD comparing the auditkey channel directly, bypassing ready_input.
T52 Minor (prose, a; RT7) First-boot baseline fixture with a record whose srk_name does not match.
T53 Minor (prose, a; RT7) Restore fixture: approver removed by a roster change before the restored head.
## Recurring Issue Check (Testing r6)
R1-R3 OK. R4-R15 N/A. R16 OK. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R39 N/A. R40-R42 OK. R43-R48 N/A. R49 T52. R50 OK. R51 T52. R52 N/A. R53 OK. R54 N/A. R55 T50. R56-R57 N/A. RT1 OK. RT2 T51. RT3 T50. RT4 N/A. RT5 OK. RT6 OK. RT7 T50,T52,T53. RT8-RT11 OK.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 7

## Changes from Previous Round
Plan v7 applied every round-6 finding. Round 7: no Critical, no Major.
Design Minors F45, F46, S32; prose Minors S33, T54, T55.

## Resolution (round 7 → plan v8)
All applied; none skipped. F46, S32, T54 converged on one predicate the
verifier could not check ("the capture starts at the post-Clear boot").
v8 removes it rather than adding more conditions: every capture chains
with `--after`, except the first after provisioning, which needs an
explicit `--from-provisioning` custodian assertion (RM8-12) plus
`restart = 0` and a ready first checkpoint. S33, T55 → the `--after`
anchor is verified; fixtures. F45 → every code range reserves an
`Unknown` code; out-of-range peers map outside the range.

## Functionality expert (round 7) — no Critical, no Major
F43, F44 resolved.
F45 Minor (design, b; R3/R55) Clamp has no Unknown slot: INNER_REASONS = real count + 1 (last = Unknown) or INNER_DENIED_UNKNOWN outside the range; same for peer >= MAX_PEERS.
F46 Minor (design, b; R3/R16) Verifier cannot recognise the post-Clear start: provisioning record carries expected first-boot reset/restart (or boot ID); fixture record matches but first boot is later.
## Recurring Issue Check (Functionality r7)
R1-R2 Checked. R3 F45,F46. R4 Checked. R5-R11 N/A. R12-R13 Checked. R14-R15 N/A. R16 F46. R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31-R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked. R39 N/A. R40-R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55 F45. R56-R57 Checked.

## Security expert (round 7) — no Critical, no Major
S31 resolved in intent; InnerDenied range and runbook StateRefused branch OK.
S32 Minor (design, b; R16/RS6) Verifier cannot check "capture starts at post-Clear boot"; state the signal: explicit --from-provisioning custodian assertion with restart=0 and first checkpoint = ready, or --after mandatory; fixture record present, reset>0, no flag -> fail.
S33 Minor (prose, a; R41) --after checkpoint must be verified (signature with device key, srk_name match, reset/seq follow); forged --after fixture.
## Recurring Issue Check (Security r7)
Fired: R16, RS6 (S32); R41 (S33). Checked OK: R1-R4, R12, R14, R18, R29, R31, R36, R38-R40, R42, R44, R47-R52, R55-R57; RS1, RS3, RS5. N/A rest.

## Testing expert (round 7) — no Critical, no Major, prose only
T50-T53 resolved.
T54 Minor (prose, a; RT7/R55) Baseline conjunction not red-proved: fixture with a matching record but a capture not starting at the post-Clear boot and no --after must fail; state how the verifier recognises the post-Clear start.
T55 Minor (prose, a; RT7/RT2) --after as untrusted input: deny fixtures forged and wrong-key --after checkpoint; chained allow fixture; assert the printed baseline line.
## Recurring Issue Check (Testing r7)
R1-R3 OK. R4-R15 N/A. R16 OK. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R39 N/A. R40-R42 OK. R43-R48 N/A. R49-R51 OK. R52 N/A. R53 OK. R54 N/A. R55 T54. R56-R57 N/A. RT1 OK. RT2 T55. RT3 OK. RT4 N/A. RT5-RT6 OK. RT7 T54,T55. RT8-RT11 OK.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 8

## Changes from Previous Round
Plan v8 applied every round-7 finding. Round 8: no Critical, no Major.
Design Minors S34, F48 (both in `audit-verify`'s continuity rule); prose
Minors F47, F49, T56.

## Resolution (round 8 → plan v9)
All applied; none skipped. S34 → the provisioning record carries
`reset_at_provision`; the first boot must be `reset_at_provision + 1`,
`restart = 0`, ready checkpoint (P1 confirms the +1, else RM8-12 alone).
F48 → three named successor cases, anything else a gap; fixtures.
F47, T56 → encoding test wording. F49 → fixtures described by what
they catch.

## Functionality expert (round 8) — no Critical, no Major
F45, F46 resolved.
F47 Minor (prose, a; R55) Encoding test wording: last real reason decodes; the reserved last code is Unknown.
F48 Minor (design, b; R3/R16) --after successor undefined: split inside one boot (same boot_id, higher seq), TPM Restart (same reset, restart+1), boot_id; state cases + fixtures.
F49 Minor (prose, a; R35) "flag on a later boot" fixture only catches mid-boot / post-Restart starts; describe and point to RM8-12.
## Recurring Issue Check (Functionality r8)
R1-R2 Checked. R3 F48. R4 Checked. R5-R11 N/A. R12-R13 Checked. R14-R15 N/A. R16 F48. R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31-R32 Checked. R33-R34 N/A. R35 F49. R36-R37 N/A. R38 Checked. R39 N/A. R40-R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55 F47. R56-R57 Checked.

## Security expert (round 8) — no Critical, no Major
S32, S33 resolved.
S34 Minor (design, b; R16/RS6) --from-provisioning checks restart = 0, which holds on every cold boot; a later power-cycled boot passes. Require a first-boot property only the post-provisioning boot has; fixture reset > 0, restart = 0, ready first checkpoint, with the flag -> fail.
## Recurring Issue Check (Security r8)
Fired: R16, RS6 (S34). Checked OK: R1-R4, R12, R14, R18, R29, R31, R36, R38-R42, R44, R47-R52, R55-R57; RS1, RS3, RS5. N/A rest.

## Testing expert (round 8) — no Critical, no Major, prose only
T54, T55 resolved.
T56 Minor (prose, a; RT7/R55) Restate encoding cases: last real reason decodes as itself; reserved last code decodes as Unknown; out-of-range reason encodes to the reserved code; INNER_DENIED_UNKNOWN joins the disjointness test.
## Recurring Issue Check (Testing r8)
R1-R3 OK. R4-R15 N/A. R16 OK. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R39 N/A. R40-R42 OK. R43-R48 N/A. R49-R51 OK. R52 N/A. R53 OK. R54 N/A. R55 T56. R56-R57 N/A. RT1-RT3 OK. RT4 N/A. RT5-RT6 OK. RT7 T56. RT8-RT11 OK.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 9

## Changes from Previous Round
Plan v9 applied every round-8 finding. Round 9: no Critical, no Major;
security: no findings. Design Minor F50; prose Minors T57, T58.

## Resolution (round 9 → plan v10)
All applied. F50 → split capture resumes the chain from the anchor at
`seq + 1`; deny fixture. T57 → the stale "reset = 0" rule and fixture
replaced by the continuity rule. T58 → the "+1" fact added to P1 with
its fallback.

## Functionality expert (round 9) — no Critical, no Major
F47-F49 resolved.
F50 Minor (design, b; R3) Split-capture successor (case 1): chain must resume from the anchor's chain value and the first line's seq must be anchor seq + 1; deny fixture with a line deleted just after the anchor.
## Recurring Issue Check (Functionality r9)
R1-R2 Checked. R3 F50. R4 Checked. R5-R11 N/A. R12-R13 Checked. R14-R15 N/A. R16 Checked. R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31-R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked. R39 N/A. R40-R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55-R57 Checked.

## Security expert (round 9) — No findings
S34 resolved. TPM Reset/Restart/Resume/Clear counter semantics checked against the three successor cases and the reset_at_provision rule: every case matches or fails closed.
## Recurring Issue Check (Security r9)
Checked: R1-R4, R12, R14, R16, R18, R29, R31, R36, R38-R42, R44, R47-R52, R55-R57; RS1, RS3, RS5, RS6. N/A rest.

## Testing expert (round 9) — no Critical, no Major, prose only
T56 resolved.
T57 Minor (prose, a; RT7/R55) Stale pre-v9 reset = 0 rule and fixture contradict v9; reword to first boot reset = reset_at_provision + 1 with matching record (allow) / without (deny).
T58 Minor (prose, a; RT7/R16) Add the "+1" fact to P1's row and state that if it fails the S34 fixture is dropped and RM8-12 covers it.
## Recurring Issue Check (Testing r9)
R1-R3 OK. R4-R15 N/A. R16 T58. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R39 N/A. R40-R42 OK. R43-R48 N/A. R49-R51 OK. R52 N/A. R53 OK. R54 N/A. R55 T57. R56-R57 N/A. RT1-RT3 OK. RT4 N/A. RT5-RT6 OK. RT7 T57,T58. RT8-RT11 OK.


---

# Plan Review: kozane-m8-peer-policy
Date: 2026-10-29
Review round: 10

## Changes from Previous Round
Plan v10 applied every round-9 finding. Round 10: no Critical, no Major,
no design finding. Testing: no findings. F51 and S35 (the same issue):
prose Minor of kind (b).

## Resolution and exit
F51/S35 applied in plan v11 (the split capture resumes from
`SHA-256(anchor.chain ‖ anchor line)`). No finding remains open, so the
plan has no Carried-Forward section.

## Saturation call (round 10)
The saturation exit holds for round 10:
1. Ten rounds completed.
2. No Critical or Major finding is open in any category.
3. No round-10 finding is against the design (experts' labels: F51 prose,
   S35 prose; testing none).
4. The only Minor (F51 = S35) is prose, kind (b), and is applied.
Character of the last rounds: from round 6 on, every finding was a
Minor inside the C10 `audit-verify` continuity rule, each against the
previous round's wording (rounds 6–9 one design Minor each, round 10
prose only). Every contract in the Go/No-Go gate is `locked`.

## Functionality expert (round 10) — no Critical, no Major
F50 resolved; T57/T58 edits introduce no defects.
F51 Minor (prose, b; R3) Checkpoint chain=<h> is the hash before the checkpoint line; resume from SHA-256(anchor.chain || anchor line), or state checkpoint lines are outside the chain.
## Recurring Issue Check (Functionality r10)
R1-R2 Checked. R3 F51. R4 Checked. R5-R11 N/A. R12-R13 Checked. R14-R15 N/A. R16 Checked. R17 N/A. R18 Checked. R19-R28 N/A. R29 Checked. R30 N/A. R31-R32 Checked. R33-R34 N/A. R35 Checked. R36-R37 N/A. R38 Checked. R39 N/A. R40-R42 Checked. R43-R47 N/A. R48-R53 Checked. R54 N/A. R55-R57 Checked.

## Security expert (round 10) — no Critical, no Major
S35 Minor (prose, b; R29/R40) Same as F51: resume from SHA-256(chain || anchor line); allow fixture pins it.
## Recurring Issue Check (Security r10)
Checked: R1-R4, R12, R14, R16, R18, R29 (S35), R31, R36, R38-R42 (R40 S35), R44, R47-R52, R55-R57; RS1, RS3, RS5, RS6. N/A rest.

## Testing expert (round 10) — No findings
T57, T58 resolved; v10 edits checked.
## Recurring Issue Check (Testing r10)
R1-R3 OK. R4-R15 N/A. R16 OK. R17-R20 N/A. R21 OK. R22-R28 N/A. R29 OK. R30-R39 N/A. R40-R42 OK. R43-R48 N/A. R49-R51 OK. R52 N/A. R53 OK. R54 N/A. R55 OK. R56-R57 N/A. RT1-RT3 OK. RT4 N/A. RT5-RT11 OK.

