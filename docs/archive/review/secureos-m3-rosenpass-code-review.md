# Code Review: secureos-m3-rosenpass
Date: 2026-10-20
Review round: 4
Branch: feature/m3-rosenpass, `5b406c4..ab933ee` (M3 base is the M2.5 tip; `main` is several milestones behind)

## Changes from Previous Round
Initial review. Phase 2 Step 2-5 had already run a focused R-check (recorded in the deviation log), so this round was incremental verification. The local-LLM seed generation was skipped because the diff (~14k lines) exceeds the local model's context (HTTP 400). All three experts did full-diff review.

## Functionality Findings (Round 1)
Seed Finding Disposition: Seed unavailable — no dispositions to record.
F1 [Major] C8 McEliece assurance spike deliverables missing while SC3 marked closed — plan.md:553-564, 658, 701.
F2 [Minor] Go/No-Go rows MCE-COST and GUARD still pending — plan.md:702-703.
F3 [Minor] Per-source InitHello meter keyed by IP: >6 peers behind one NAT go stale under L8 — ingress-core/src/lib.rs:683, 775.
F4 [Minor] pq defers notifies and audit flush to end of a multi-second pass; comment inaccurate — pds/pq/src/main.rs:42-45, 372-375.
F5 [Minor] RpCostHighWater lost on a full audit ring still advances the mark — audit-event/src/lib.rs:560, pds/pq/src/main.rs:296.
F6 [Adjacent][Minor] hs drains the pq link unbounded before ih — pds/hs/src/main.rs:156.
## Recurring Issue Check (Functionality expert)
R1-R3 clean; R4 clean (timing F4); R5-R11 N/A; R12 clean; R13-R28 N/A; R29 fired (F4); R30-R31 N/A; R32 clean; R33-R34 N/A; R35 clean; R36-R37 N/A; R38 clean; R39 N/A; R40 clean; R41 clean; R42-R48 N/A; R49 fired (F4, F5); R50-R52 N/A; R53 clean; R54 N/A; R55 clean; R56-R57 N/A.
```json
[{"id":"F1","severity":"Major","title":"C8 spike deliverables missing while SC3 marked closed","file":"docs/archive/review/secureos-m3-rosenpass-plan.md","line":553,"adjacent":false,"escalate":null},
{"id":"F2","severity":"Minor","title":"Go/No-Go MCE-COST and GUARD still pending","file":"docs/archive/review/secureos-m3-rosenpass-plan.md","line":702,"adjacent":false,"escalate":null},
{"id":"F3","severity":"Minor","title":"Per-source InitHello meter keyed by IP","file":"crates/ingress-core/src/lib.rs","line":775,"adjacent":false,"escalate":null},
{"id":"F4","severity":"Minor","title":"pq defers notifies/audit flush to end of a multi-second pass","file":"crates/pds/pq/src/main.rs","line":45,"adjacent":false,"escalate":null},
{"id":"F5","severity":"Minor","title":"Lost RpCostHighWater still advances the mark","file":"crates/audit-event/src/lib.rs","line":560,"adjacent":false,"escalate":null},
{"id":"F6","severity":"Minor","title":"hs drains pq link unbounded before ih","file":"crates/pds/hs/src/main.rs","line":156,"adjacent":true,"escalate":null}]
```

## Security Findings (Round 1)
Seed Finding Disposition: Seed unavailable — no dispositions to record.
No Critical or Major findings.

S-1 [Minor] SC23 waiver binding matches one exact cmr version string and is not enforced at packaging — tools/check-pins:187, tools/waivers.py:40, tools/package:275, Makefile:86. A cmr bump to 2.0.3 releases P6; `make package` without `make check` with SC23 removed/emptied waivers.toml passes. Masked today by SC20. Fix: P6 matches any classic-mceliece-rust by name; shared `required_open(lock)` predicate in waivers.py used by check-pins and tools/package; package refuses on unreadable Cargo.lock; deny/allow pairs red-proved separately.

S-2 [Minor] Secret arrays copied by value outside Secret/Key32 — rosenpass-core/src/responder.rs:437 (`Secret::from_bytes(*ck)`), kem.rs:128 (`Secret::from_bytes(*ss.as_array())`), hs-core/src/lib.rs:159 (`Key32::from_bytes(*osk)`), :176 (`Key32::from_bytes(*osk.as_bytes())`). Unwiped stack temporaries in pq/hs. Fix: copy-in constructors (`copy_from(&[u8;N])`) for Secret and Key32 used at all four sites; tripwire grep `from_bytes\(\*` declared as tripwire.

S-3 [Minor] InitHello starvation needs no flood — ingress-core/src/lib.rs:579-584, :616 (meters keyed on IP), :768. A spoofed mac-valid InitHello as peer P every 20 s (~0.05 pkt/s) spends P's single per-source token; ~0.1-1 pkt/s takes the global meter; fakes filling RP_IN_FLIGHT make InitConfs RingReserved. Within SC26/R6 residual but the waiver understates the rate. Fix: record rates in SC26/plan residual; M3b acceptance: spoofed-per-20 s deny/allow pair, InitConf reserve in the ring, cookie gate triggered by meter refusals not volume.

S-4 [Adjacent][Minor] pq's hedged RNG has no unit tests — pds/pq/src/main.rs:99-120. Fix: move Hedged behind an Hw trait into rosenpass-core (like hs-core's HedgedEntropy); deny: RNDR failure → Err and tick drops both keys; allow: successive draws with identical RNDR differ.

## Recurring Issue Check (Security expert)
R1 checked (accepted copies); R2 checked; R3 fired (S-2); R4 OK; R5-R9 N/A; R10 checked; R11 N/A; R12 OK; R13-R15 N/A; R16 OK; R17 OK; R18 OK; R19-R28 N/A; R29 checked; R30-R31 N/A; R32 OK; R33 N/A; R34 none; R35 OK; R36 OK; R37 N/A; R38 OK; R39 fired (S-2); R40 OK; R41 OK; R42 fired (S-1); R43 checked; R44 OK; R45-R46 N/A; R47 fired (S-1); R48 checked; R49 OK; R50 OK; R51 OK; R52 OK; R53 OK; R54 N/A; R55 OK; R56-R57 N/A.
RS1 OK; RS2 OK (S-3 economics); RS3 OK; RS4 OK; RS5-RS6 N/A.

```json
[
 {"id":"S-1","severity":"Minor","title":"SC23 waiver binding matches one exact cmr version and is not enforced when packaging","file":"tools/check-pins","line":187,"adjacent":false,"escalate":false},
 {"id":"S-2","severity":"Minor","title":"Secret arrays copied by value outside Secret/Key32 (ck, shk, OSK)","file":"crates/rosenpass-core/src/responder.rs","line":437,"adjacent":false,"escalate":false},
 {"id":"S-3","severity":"Minor","title":"InitHello starvation needs no flood; InitConf has no reserved link share","file":"crates/ingress-core/src/lib.rs","line":616,"adjacent":false,"escalate":false},
 {"id":"S-4","severity":"Minor","title":"pq's hedged RNG has no unit tests","file":"crates/pds/pq/src/main.rs","line":104,"adjacent":true,"escalate":false}
]
```

## Testing Findings (Round 1)
Seed Finding Disposition: Seed unavailable — no dispositions to record.
Phase-2 testing fixes 1-7 verified (needles audited against all green logs; counts consistent).

T1 [Major] Bucket deny replay window equals the cost bound; flaky under TCG load — tests/integration/run.py:1968-1977. Replay sent after the genuine RespHello; fails if that took >= 20 s (= PQ_HANDSHAKE_COST_NS; quiet-window accepts up to 25 s). Fix: send the replay immediately after the genuine bytes; require exactly one RespHello within 2x cost; keep the >=2-global-token precondition; red-prove with integration-rp-src-meter (two replies) and always-true RpMac; tie: a replay at exactly sent+interval is admitted.
T2 [Minor] Expiry allow side ~48 s from boundary (key_out mtime precedes install by ~38 s) — run.py:996-997, 1015. Fix: lower bound = send time of the last failed installed() attempt.
T3 [Minor] HandshakePskStale total=1 needle can misattribute if prelude PSK went stale during rotation — run.py:1121. Fix: assert no stale line since prelude before taking the mark.
T4 [Adjacent][Minor] wireguard-go never handshakes under a rotated PSK — run.py:1094-1112. Fix: ping until wg latest-handshake advances, or record residual.
T5 [Minor] package-waiver selftest injects nothing — tools/check-selftest:328. Fix: case removing check_waivers from tools/package, gate pins, failure-only needle from test_package.py.
T6 [Minor] "Not red-proved: rotation, expiry, reboot" without reasoning — deviation.md:348. Fix: per-case reasoning; run expiry and rotation mutants on scratch.
T7 [Minor] Kani forward harness doesn't assert source-meter spend; no TypeDropped cover — ingress-core/src/proofs.rs:481-525.
T8 [Minor] pq blob layout literals in tools/package not cross-checked in pins — tools/package:70-71.
T9 [Minor] Supersession test checks only the deny half — hs-core/src/tests.rs:604-618.
T10 [Minor] 0x81 hard-coded in sniffed_init_hello — run.py:1916.
T11 [Minor] Selftest time not recorded — plan.md:629.

## Recurring Issue Check (Testing expert)
R1 N/A; R2 fired (T8); R3 fired (T10); R4-R6 N/A; R7 checked; R8-R15 N/A; R16 checked; R17-R18 N/A; R19 checked; R20 checked; R21 checked; R22-R28 N/A; R29 checked (T2 overstatement); R30-R31 N/A; R32 checked; R33-R34 N/A; R35 checked; R36-R48 N/A; R49 checked; R50 checked; R51-R52 N/A; R53 fired (T1); R54-R57 N/A.
RT1 checked; RT2 checked; RT3 fired (T8, T10); RT4 checked; RT5 checked; RT6 checked; RT7 fired (T5, T6, T7); RT8 checked; RT9 checked; RT10 fired (T2, T9); RT11 checked.

```json
[
{"id":"T1","severity":"Major","title":"Bucket deny replay window equals the cost bound; flaky under TCG load","file":"tests/integration/run.py","line":1968,"adjacent":false,"escalate":null},
{"id":"T2","severity":"Minor","title":"Expiry allow side is ~48 s from the boundary","file":"tests/integration/run.py","line":1015,"adjacent":false,"escalate":null},
{"id":"T3","severity":"Minor","title":"Hidden 180 s budget makes the stale needle misattribute","file":"tests/integration/run.py","line":1121,"adjacent":false,"escalate":null},
{"id":"T4","severity":"Minor","title":"wireguard-go never handshakes under a rotated PSK","file":"tests/integration/run.py","line":1106,"adjacent":true,"escalate":null},
{"id":"T5","severity":"Minor","title":"package-waiver selftest injects nothing","file":"tools/check-selftest","line":328,"adjacent":false,"escalate":null},
{"id":"T6","severity":"Minor","title":"Not red-proved rotation/expiry/reboot without reasoning","file":"docs/archive/review/secureos-m3-rosenpass-deviation.md","line":348,"adjacent":false,"escalate":null},
{"id":"T7","severity":"Minor","title":"Kani forward harness lacks source-meter assert and TypeDropped cover","file":"crates/ingress-core/src/proofs.rs","line":500,"adjacent":false,"escalate":null},
{"id":"T8","severity":"Minor","title":"pq blob layout hard-coded in tools/package","file":"tools/package","line":71,"adjacent":false,"escalate":null},
{"id":"T9","severity":"Minor","title":"Supersession test checks only the deny half","file":"crates/hs-core/src/tests.rs","line":617,"adjacent":false,"escalate":null},
{"id":"T10","severity":"Minor","title":"0x81 hard-coded in sniffed_init_hello","file":"tests/integration/run.py","line":1916,"adjacent":false,"escalate":null},
{"id":"T11","severity":"Minor","title":"Selftest time not recorded","file":"docs/archive/review/secureos-m3-rosenpass-plan.md","line":629,"adjacent":false,"escalate":null}
]
```

## Adjacent Findings
- **S-4** (Security → Testing): pq's hedged RNG had no unit tests. Fixed (see Resolution Status).
- **T4** (Testing → Functionality): wireguard-go never handshakes under a rotated PSK. Accepted (see Resolution Status).
- **F6** (Functionality → Security): hs drained the pq link without a bound. Fixed.

## Quality Warnings
None. Every finding cites a file:line with evidence.

## Environment Verification Report
- **MCE-COST and GUARD**, the Phase-1 constraint entries (plan Go/No-Go): `verified-local`.
  - TCG measurements and the Microkit source reading are recorded in the deviation log (Batch F).
  - Both rows are now `locked`.
- **C8 constant-time spike**: `verified-local` on a non-target host.
  - The dudect run was on a GB10-class aarch64 host with the cmr opt-level 3 build.
  - The PD ELF and QEMU TCG were not timed (deviation log, "C8 McEliece assurance spike").
- **Manual test** (`secureos-m3-rosenpass-manual-test.md`): its steps are a subset of the integration suite, which ran green in `make check`.

## Resolution Status
### F1 [Major] C8 spike deliverables missing while SC3 marked closed — Fixed
- **Action:** the spike was run.
  - **Code review:** a constant-time review of cmr 2.0.2's decapsulation path, at source and machine-code level, in the PD ELF and in an opt-level 3 host build.
  - **Timing test:** a dudect smoke test with three runs, 1.5·10⁴ samples per class, threshold |t| > 4.5. No leakage was detected at this N, which is not a claim of constant time.
  - **Recommendation:** accept for dev images; SC23 stays open; replace in M4.
- **Finding:** the compiler turns the Berlekamp-Massey masked select into a secret-dependent load address in the PD ELF (F1 of the spike).
- **Plan updates:** SC3 now reads "spike done; carried by SC23 with M4 requirements" (value barriers, a ctgrind-style test, a pinned disassembly check).
- **Modified files:**
  - docs/archive/review/secureos-m3-rosenpass-deviation.md ("C8 McEliece assurance spike")
  - docs/archive/review/secureos-m3-rosenpass-plan.md (SC3 row)

### F2 [Minor] Go/No-Go MCE-COST and GUARD still pending — Fixed
- **Action:** both rows are `locked`, citing the deviation log and f667217.
- **Modified file:** plan.md, Go/No-Go table.

### F3 [Minor] Per-source InitHello meter keyed by IP — Accepted
- **Anti-Deferral check:** acceptable risk.
- **Justification:** keying by endpoint would let one non-spoofing host take a token per source port. That empties the per-source meter of its purpose against single-host abusers, and the global meter (12 per 120 s) would be the only bound. The IP key is the narrower boundary, and security wins by default (cross-perspective protocol).
  - **Worst case:** with seven or eight configured peers behind one NAT address, one or two of them cannot keep a fresh PSK. L8 then refuses their WireGuard until another peer's token frees up. This is an availability loss, not a confidentiality one.
  - **Likelihood:** low in this deployment. Remote-access clients behind one NAT seldom exceed 6 of the 8 peer slots. The integration topology (all slirp peers on 10.0.2.2) runs at most two exchanges at once.
  - **Cost to fix properly:** this belongs with the M3b cookie gate. A cookie-proven endpoint can safely get its own per-source token. That is a design change to the meter (per-source table, Kani proofs), not a constant change.
- **Tracking:** recorded in the plan's SC26 row (M3b). TODO(secureos-m3b): per-endpoint InitHello tokens behind the cookie gate.
- **Orchestrator sign-off:** the acceptable-risk exception is satisfied with all three values; the item is tracked under SC26.

### F4 [Minor] pq defers notifies and audit flush to the end of a multi-second pass — Fixed
- **Action:** `PASS_MSGS` is 1, so every answer, PskInstall notify and audit flush leaves after its own message. The comment now states the measured cost.
- **Modified file:** crates/pds/pq/src/main.rs:42-46.
- **Verification:** PD-level timing; `make test` passes (see Verification).

### F5 [Minor] A lost RpCostHighWater still advanced the mark — Fixed
- **Action:**
  - `CostHighWater::observe_with(us, deliver)` moves the mark only when the record reached the ring.
  - `pdkit::Audit::record_delivered` reports delivery.
  - pq uses both.
- **Tests:**
  - `a_lost_cost_record_is_offered_again_at_the_same_cost` (allow);
  - `a_delivered_cost_record_moves_the_mark` (deny, below +1/8).
  - Boundary unchanged: `8·us == 9·last` fires.
- **Red-proof:** on a scratch copy, advancing the mark regardless of delivery fails the allow test.
- **Modified files:** crates/audit-event/src/lib.rs, crates/pdkit/src/lib.rs, crates/pds/pq/src/main.rs, crates/audit-event/src/tests.rs.

### F6 [Minor] hs drained the pq link without a bound — Fixed
- **Action:** `drain_pq` takes at most `layout::NET_BUFFERS` messages per wakeup, so `poll` on `ih` is always reached. The rest waits for pq's notify or the 1 Hz tick. pq-first ordering (F8) is preserved.
- **Modified file:** crates/pds/hs/src/main.rs:154-170.
- **Not red-proved:** a flooding compromised pq cannot be produced from the harness. The bound is a fixed-count loop, reviewable by reading.

### S-1 [Minor] SC23 binding matched one cmr version and was not enforced at packaging — Fixed
- **Action:**
  - `waivers.required_open(lock_text)` binds SC23 to any `classic-mceliece-rust`, by name.
  - check-pins P6 and the new `tools/package` `check_bindings` both use it.
  - `check_bindings` runs for every kernel, and an unreadable Cargo.lock refuses.
- **Fixtures:**
  - P6: cmr at another version with SC23 absent → deny.
  - package:
    - SC23 closed with cmr locked (any version) → refuse;
    - empty waiver file → refuse;
    - SC23 closed without cmr → allow;
    - Cargo.lock missing → refuse.
- **Red-proofs:** each clause on a scratch copy, each failing its own fixture:
  - version-only matching;
  - `check_bindings` removed from main;
  - an unreadable lock allowed.
- **Modified files:** tools/waivers.py, tools/check-pins, tools/package, tests/tools/test_check_pins.py, tests/tools/test_package.py.

### S-2 [Minor] Secret arrays copied by value — Fixed
- **Action:** `Secret::copy_from(&[u8; N])` and `Key32::copy_from(&[u8; 32])` copy in place. They are used at the four reported sites, and at three more found by the cross-cutting grep:
  - key-core: the static private key, twice;
  - data-core: the session keys.
- **New check-pins rule P10:** a declared tripwire that flags `from_bytes(*` in the secret crates plus hs-core, key-core, data-core and wg-core. Fixtures: two deny, two allow.
- **Modified files:**
  - crates/rosenpass-core/src/{secret.rs, responder.rs, kem.rs}
  - crates/wg-core/src/crypto.rs
  - crates/hs-core/src/lib.rs
  - crates/key-core/src/lib.rs
  - crates/data-core/src/lib.rs
  - tools/check-pins
  - tests/tools/test_check_pins.py

### S-3 [Minor] InitHello starvation needs no flood — Fixed (documentation) / tracked (M3b)
- **Action:** the plan's SC26 row now records the actual starvation rates and the M3b obligations:
  - the rates: one spoofed InitHello per 20 s per peer, or about 0.1 pkt/s for the global meter;
  - the obligations: the cookie gate must engage on Rosenpass meter refusals, and InitConf needs a reserved share of the ingress→pq link.
- **Tracking:** TODO(secureos-m3b): an InitConf reserve in `RpGate`, plus the spoofed-per-20 s deny/allow pair.

### S-4 [Adjacent][Minor] pq's hedged RNG untested — Fixed
- **Action:** `Hedged<H: HedgeHw>` moved from pds/pq into rosenpass-core. pq supplies `Cpu` (RNDR, CNTPCT).
- **Tests:**
  - a failed RNDR fails the draw (deny);
  - two blocks of one draw, and two draws, differ with identical RNDR and counter;
  - the output depends on the boot seed.
- **Existing coverage:** `a_failed_rotation_refuses_hello_and_conf_until_a_good_rotation` already covers the tick dropping keys on an RNG failure.
- **Modified files:** crates/rosenpass-core/src/{kem.rs, lib.rs, tests.rs}, crates/pds/pq/src/main.rs.

### T1 [Major] Bucket deny was flaky by design — Fixed
- **Action:** the genuine InitHello and its replay are sent back to back, so both land inside the source interval by construction.
  - **Allow side:** one RespHello arrives.
  - **Deny side:** none more arrives within 2 × `PQ_HANDSHAKE_COST_NS`.
  - The ≥2-global-token precondition stays.
  - **Tie:** a replay arriving at exactly the source interval would be admitted again.
- **Red-proof:** `integration-rp-src-meter` (see Verification).
- **Modified file:** tests/integration/run.py, `rp_deny_cases`.

### T2 [Minor] Expiry allow side was about 48 s from the boundary — Fixed
- **Action:**
  - `installed()` records the send time of the last attempt that did not open. hs handled that attempt without the PSK, so it is a lower bound on the install.
  - The allow side is now `max(that, key_out mtime) + 170 s`.
  - The two bounds are `PSK_RETRY_S` plus one exchange apart.
- **Modified file:** tests/integration/run.py, `installed`, L8 pair and the expiry probe.

### T3 [Minor] The stale needle could misattribute — Fixed
- **Action:** before waiting for `HandshakePskStale total=1`, the case fails with a named precondition if a stale line was already printed earlier in the boot.
- **Modified file:** tests/integration/run.py, expiry.

### T4 [Adjacent][Minor] wireguard-go never handshakes under a rotated PSK — Accepted
- **Anti-Deferral check:** acceptable risk.
- **Justification:** each link of the chain is covered separately.
  - hs accepts the new PSK: the forced Python handshake with the new key_out opens.
  - wireguard-go holds the new key: `wg show` after the watcher.
  - Pings continue across the rotation, so the old session is unaffected.
  - What is not exercised is wireguard-go's own use of a preshared key set through `wg set`. That is upstream behaviour, not gateway code.
  - **Worst case:** a regression in the key_out watcher's `wg set` call that leaves wireguard-go on the old PSK. Its next rekey would then fail after 180 s, until the watcher reapplies it. The `wg show` check catches a watcher that never applies the key.
  - **Likelihood:** low. The watcher is checked by `wg show` in the same case.
  - **Cost to fix:** about +2–3 min per suite run, waiting for wireguard-go's REKEY_AFTER_TIME (120 s) under TCG. It would also add another timing-sensitive wait to the suite, which T1 just removed one of.
- **Orchestrator sign-off:** the acceptable-risk exception is satisfied with all three values.

### T5 [Minor] package-waiver injected nothing — Fixed
- **Action:**
  - New selftest case `package-waiver-removed` (gate `pins`) removes `check_waivers` from `tools/package`'s main. Its needle is the failure-only line "FAIL SC20 stubbed: an open waiver refuses and names itself".
  - `package-waiver` stays as the allow/regression twin.
- **Verified:** both `ok`.

### T6 [Minor] Rotation, expiry and reboot were not red-proved — Fixed
- **Action:** new integration selftest cases.
  - `integration-rotation`: hs ignores a superseding install on a Live entry.
  - `integration-expiry`: hs refuses PSKs 20 s early.
- **Reboot needs no mutant:** the PSK table is in PD RAM and cannot survive `system_reset`. There is no realistic mutant short of persisting the table, which no code path does.
- **Recorded in:** the deviation log.

### T7 [Minor] Kani forward harness lacked a source-meter assertion and a TypeDropped cover — Fixed
- **Action:**
  - `rp_forward_spends_its_own_meters_once` asserts that the type's per-source table changed.
  - `rp_refusals_before_admission_spend_nothing` covers `TypeDropped`.
- **Verification:**
  - Kani on ingress-core: 13 harnesses, all covers satisfied.
  - Red-proof on a scratch copy: removing the per-source InitHello meter fails `assertion failed: gate.hello_src != before.hello_src`.
- **Modified file:** crates/ingress-core/src/proofs.rs.

### T8 [Minor] pq blob layout hard-coded in tools/package — Fixed
- **Action:** new secret-blob unit test `tools_package_mirrors_both_blob_layouts`. It checks that `tools/package` declares both `BlobKind`s with the crates' magic, version, region size and checksum offset.
- **Red-proof:** on a scratch copy, changing `13904` to `13905` fails it.
- **Modified file:** crates/secret-blob/src/tests.rs.

### T9 [Minor] Supersession test checked only the deny half — Fixed
- **Action:** the new PSK must key a handshake (allow), and the old one must not (deny). There is one handshake per side, because `finish` consumes the initiator.
- **Modified file:** crates/hs-core/src/tests.rs.

### T10 [Minor] 0x81 hard-coded — Fixed
- **Action:** `sniffed_init_hello` reads `MSG_INIT_HELLO` from rosenpass-wire.

### T11 [Minor] Selftest time not recorded — Fixed
- **Action:** the full `check-selftest` wall time is measured and recorded in the deviation log (see Verification).

### Verification (Round 1 fixes)
- **`make check`:** exit 0 in 619 s. UNIT-TESTS 652, CHECK-PINS-RULES 10, CHECK-PINS-FIXTURES 69, PACKAGE-FIXTURES 89, KANI-HARNESSES 48, INTEGRATION-CASES 22.
- **New and reworked selftest cases:** each fails with its failure-only needle.
  - `integration-rp-src-meter`
  - `integration-rotation`: it went red, but Round 2 (testing N1) showed the explanation recorded here was wrong. The harness tries only the current key_out, never the old PSK. The needle fired only when the 180 s expiry and the 120 s client rekey happened to line up. The case was reworked in Round 2.
  - `integration-expiry`
  - `package-waiver-removed`
  - `rp-mac-always`

# Round 2

## Functionality Findings (Round 2)
F1-F6, S-1..S-4: resolved; F3/T4 Accepted reasoning sound.
N1 [Minor] policy/waivers.toml:7-8 and plan Packaging row (plan.md:285) still describe the SC23 binding as cmr 2.0.2 only.
N2 [Minor] required_open skips malformed package entries (isinstance filter) — Round 1 failed closed via AttributeError; check-pins misses UnicodeDecodeError — tools/waivers.py:83. (overlaps S-5)
N3 [Adjacent][Minor] by-value secret copies outside P10 (kem.rs:104,106; pds/key/src/main.rs:59). (overlaps S-7)
N4 [Adjacent][Minor] T3 precondition excludes stale lines only before the mark; a concurrent post-mark stale line still satisfies the needle — run.py:1130-1135.
```json
[{"id":"N1","severity":"Minor","title":"waivers.toml and plan Packaging row still say cmr 2.0.2","file":"policy/waivers.toml","line":8,"adjacent":false,"escalate":null},
{"id":"N2","severity":"Minor","title":"required_open skips malformed lock entries; check-pins misses UnicodeDecodeError","file":"tools/waivers.py","line":83,"adjacent":false,"escalate":null},
{"id":"N3","severity":"Minor","title":"By-value secret copies outside P10","file":"crates/rosenpass-core/src/kem.rs","line":106,"adjacent":true,"escalate":null},
{"id":"N4","severity":"Minor","title":"T3 precondition only excludes pre-mark stale lines","file":"tests/integration/run.py","line":1133,"adjacent":true,"escalate":null}]
```

## Security Findings (Round 2)
S-1..S-4: resolved. Regressions F4/F5/F6/T1-T3: none. R43: no widening.
S-5 [Minor] check_bindings/required_open pass on a structurally empty lock (""/"version = 4"/no [[package]] array) and delegate an unusable waiver file to check_waivers — tools/waivers.py:76-84, tools/package:102-116. Fail-open only when tools/package is run directly on prebuilt ELFs (cargo --locked rejects such a lock on the make path).
S-6 [Minor] SC23 binding is a crate-name deny-list on Cargo.lock, not tied to the packaged ELFs — tools/waivers.py:25.
S-7 [Minor] Residual by-value secret copies — rosenpass-core/src/kem.rs:105-106 (kyber `*r.expose()`, `Secret::from_bytes(ss)`), pds/key/src/main.rs:59 (`Key32::from_bytes(seed)`, seed not zeroized), hs-core/src/index.rs:34; pds/key, pds/hs, pds/data not in P10's crate list.
S-8 [Minor] C8 dev-only acceptance omits the co-resident L1D channel amplified by pqkey's MCS budget slicing (R3) — deviation log, C8 §3.
[Adjacent] P6 does not catch UnicodeDecodeError on Cargo.lock (fails closed via traceback).
```json
[{"id":"S-5","severity":"Minor","title":"check_bindings passes on structurally empty lock; delegates unusable waiver file","file":"tools/waivers.py","line":76,"adjacent":false,"escalate":false},
{"id":"S-6","severity":"Minor","title":"SC23 binding is a crate-name deny-list, not bound to packaged ELFs","file":"tools/waivers.py","line":25,"adjacent":false,"escalate":false},
{"id":"S-7","severity":"Minor","title":"Residual by-value secret copies outside P10","file":"crates/rosenpass-core/src/kem.rs","line":105,"adjacent":false,"escalate":false},
{"id":"S-8","severity":"Minor","title":"C8 acceptance omits co-resident L1D channel (R3)","file":"docs/archive/review/secureos-m3-rosenpass-deviation.md","line":null,"adjacent":false,"escalate":false}]
```

## Testing Findings (Round 2)
T1, T3, T5, T7–T11, F5, S-1 and S-2 resolved. T2 partial (N3). S-4 partial (N2). T6 rotation continuing (N1).
N1 [Major] The integration-rotation red-proof depended on timing, and its mechanism was misdescribed — tools/check-selftest:166-173, run.py:1108-1114.
N2 [Major] The Hedged tests did not pin the RNDR/counter mixing — rosenpass-core/src/tests.rs:342-383.
N3 [Minor] `refused_at`, judged by a 2 s timeout, was not a proven lower bound; the None case let the expiry mutant survive — run.py:951-956.
N4 [Minor] The Kani `!=` assertion on the per-source table could be satisfied by inserting a slot without a spend — ingress-core/src/proofs.rs:514.
N5 [Minor] `pdkit::Audit::record_delivered` was untested — pdkit/src/lib.rs:87.
N6 [Minor] `check_bindings` had no fixture on a release kernel — test_package.py.
```json
[{"id":"N1","severity":"Major","title":"integration-rotation red-proof timing-dependent","file":"tools/check-selftest","line":166,"adjacent":false,"escalate":null},
{"id":"N2","severity":"Major","title":"Hedged tests do not pin RNDR/counter mixing","file":"crates/rosenpass-core/src/tests.rs","line":342,"adjacent":false,"escalate":null},
{"id":"N3","severity":"Minor","title":"refused_at not a proven lower bound","file":"tests/integration/run.py","line":951,"adjacent":false,"escalate":null},
{"id":"N4","severity":"Minor","title":"Kani src != satisfiable without a spend","file":"crates/ingress-core/src/proofs.rs","line":514,"adjacent":false,"escalate":null},
{"id":"N5","severity":"Minor","title":"record_delivered untested","file":"crates/pdkit/src/lib.rs","line":87,"adjacent":false,"escalate":null},
{"id":"N6","severity":"Minor","title":"check_bindings lacks a release fixture","file":"tests/tools/test_package.py","line":718,"adjacent":false,"escalate":null}]
```

## Resolution Status (Round 2)

### Rotation red-proof and Hedged mixing (testing N1, N2 — Major)
- **N1 — Fixed.**
  - Precondition: before the restart, a forced handshake with the current key_out must open, so hs holds a Live entry installed within one 120 s client rekey interval.
  - The rotation then tries only the restart's first key, so it must supersede that Live entry.
  - Failure messages: "rotation: the current key did not open before the restart" / "rotation: hs did not accept the restart's first key".
  - check-selftest now accepts a tuple of failure-only needles; `integration-rotation` uses both. Under the mutant one of them fires, depending on whether a rekey happened since the prelude.
- **N2 — Fixed.** New tests:
  - `hedged_output_depends_on_rndr`
  - `hedged_output_depends_on_the_counter`
  - `hedged_fails_the_whole_draw_when_rndr_fails_on_a_later_block`
  - Red-proved: dropping RNDR, or the counter, from the hash fails its test.

### Waiver binding (security S-5, S-6; functionality N1, N2; testing N6 — Minor)
- **S-5 / N2 — Fixed.**
  - `required_open` raises `WaiverError` unless `package` is a non-empty array of tables with string names, so a malformed lock refuses. This restores Round 1's fail-closed behaviour; the Round 1 `isinstance` filter had failed open.
  - check-pins P6 also catches `UnicodeDecodeError`.
  - Fixtures:
    - package: an empty lock, and `[package]` as a single table, each refuse;
    - P6: a lock without `[[package]]`.
  - Red-proved by restoring the lenient filter.
  - Kept: `check_bindings` still leaves an unusable waiver file to `check_waivers`. The two always run together in `tools/package` main, so the refusal is present; the docstring says so (functionality R2 found this sound).
- **N6 — Fixed.**
  - Fixture: SC20 stubbed, a non-debug kernel, SC23 closed with cmr locked → `SC23_BOUND`.
  - Red-proved by making `check_bindings` debug-only.
- **S-6 — Fixed (declared).** The crate-name binding's known bypass (a vendored or renamed McEliece) is declared in waivers.py. SC23 closes only through M4's disassembly check, not through this rule.
- **N1 (functionality) — Fixed.** `policy/waivers.toml` and the plan's Packaging row now describe the binding as any `classic-mceliece-rust`, enforced by P6 and `check_bindings`.

### Remaining by-value copies (security S-7, functionality N3 — Minor) — Fixed
- **Sites:**
  - `kem.rs`: Kyber `ss` now uses `copy_from`.
  - `pds/key`: the boot seed is copied in place and zeroed.
  - `hs-core/index.rs`: the index key's hash is copied in place and zeroed.
  - libcrux's by-value randomness argument is documented inline as dependency residue.
- **P10:** its scope gains pds/key, pds/hs and pds/data. Its declared bypasses include `from_bytes(local)` and dependency-forced copies.

### Co-resident channel in the C8 acceptance (security S-8 — Minor) — Fixed
- The deviation log's "C8 addendum" covers it:
  - the L1D prime+probe path through pqkey's MCS budget slicing, under R3;
  - the dudect result's irrelevance to that path;
  - M4 requirements (b) and (c) widened to secret-dependent addresses.
- The plan's SC3 row is updated.

### Test bounds (testing N3, N4, N5; functionality N4 — Minor)
- **N3 — Fixed.**
  - `installed()` judges a refusal by `REPLY_TIMEOUT_S`, the suite's reply budget, not the 2 s retry.
  - The expiry case requires the install window [max(last refused send, key_out mtime), accepted] to be narrower than EXPIRY_ALLOW_S (10 s), and otherwise fails with a named precondition. Failing when the first attempt opened was tried first, but it failed clean runs. Since the Round 1 meters, the install follows key_out within milliseconds, so key_out's mtime is itself a tight lower bound.
- **N4 (testing) — Fixed.** The Kani harness asserts that the source's own slot level fell by exactly one interval, through `spec_src_level`, where a new source counts as full.
- **N5 — Fixed.**
  - `Coalescer::record_delivered` returns (offered, delivered) and is host-tested for a delivered record, a full ring, and an event coalesced away.
  - pdkit only calls it.
  - Red-proved: an always-true variant fails the test.
- **N4 (functionality) — Accepted with reasoning in code.**
  - Anti-Deferral check: acceptable risk.
  - Worst case: a stale line from another case after the mark satisfies the needle. The probe's own no-response deny check still holds.
  - Likelihood: none in the current suite. Only the probe uses peer 1, and peer 0's freshness is shown by the rotation precondition.
  - Cost to fix: a per-peer stale event, which is not in the audit schema.

### Found while fixing: PD clippy was not gated
- `cargo clippy -D warnings` on each PD found `wrong_self_convention` in pds/ingress (`to_peer`, `from_*`, partly from M2.5) and in pds/inner (`from_lan`, `from_tunnel`). They were renamed `send_to_peer` / `drain_*`.
- **New gate `lint-pds`:** clippy on each PD as it is built, one invocation per PD. It is counted as `LINT-PDS 11`, runs in `make check`, and has selftest case `lint-pds`.

### Verification (Round 2 fixes)
- **`make check`:** exit 0 in 635 s. UNIT-TESTS 656, LINT-PDS 11, CHECK-PINS-FIXTURES 70, PACKAGE-FIXTURES 92, INTEGRATION-CASES 22.
- **Selftest cases:** `integration-rotation`, `integration-expiry` and `lint-pds` each fail with their failure-only needles.
- **Scratch red-proofs:** lenient lock, debug-only bindings, Hedged without RNDR or counter, and always-true `record_delivered`. Each fails its own test.

# Round 3

## Findings (Round 3)
- **Security:** S-5..S-8 resolved; no R43 widening.
  - S-9 [Minor][Adjacent]: the `required_open` name clause and P6's `UnicodeDecodeError` catch had no fixture that ran them.
- **Functionality:** N1..N3 resolved; N4's acceptance holds; no R43 widening.
  - F1 [Minor]: the rotation precondition's bound was misstated (the client re-keys every 130 s, plus an exchange).
  - F2 [Minor]: `rp0.osk()` could return None into `initiator()`.
  - F3 [Minor]: the `required_open` docstring was stale.
  - F4 [Minor][Adjacent]: `.fill(0)` on dead locals could be elided.
- **Testing:** N2..N6 resolved; N1 partial.
  - R3-T1 [Major]: the lint-pds red-proof was caught by rustc's dead_code warning, not by clippy.
  - R3-T2 [Major]: the integration-rotation mutant could still escape through expiry, or fail earlier cases outside the needles.
  - R3-T3 [Minor]: the rotation precondition was single-shot.
  - R3-T4 [Minor]: same as S-9.

```json
[{"id":"S-9","severity":"Minor","title":"name clause and P6 decode catch lack fixtures","file":"tools/waivers.py","line":94,"adjacent":true,"escalate":false},
{"id":"F1","severity":"Minor","title":"rotation precondition bound misstated","file":"tests/integration/run.py","line":1116,"adjacent":true,"escalate":null},
{"id":"F2","severity":"Minor","title":"osk() None into initiator()","file":"tests/integration/run.py","line":1119,"adjacent":false,"escalate":null},
{"id":"F3","severity":"Minor","title":"required_open docstring stale","file":"tools/waivers.py","line":84,"adjacent":false,"escalate":null},
{"id":"F4","severity":"Minor","title":"fill(0) on dead locals may be elided","file":"crates/hs-core/src/index.rs","line":36,"adjacent":true,"escalate":null},
{"id":"R3-T1","severity":"Major","title":"lint-pds red-proof caught by rustc dead_code, not clippy","file":"tools/check-selftest","line":150,"adjacent":false,"escalate":null},
{"id":"R3-T2","severity":"Major","title":"integration-rotation mutant can still escape","file":"tests/integration/run.py","line":1116,"adjacent":false,"escalate":null},
{"id":"R3-T3","severity":"Minor","title":"rotation precondition single-shot","file":"tests/integration/run.py","line":1119,"adjacent":false,"escalate":null},
{"id":"R3-T4","severity":"Minor","title":"same as S-9","file":"tools/waivers.py","line":93,"adjacent":false,"escalate":null}]
```

## Resolution Status (Round 3)

### R3-T2 / F1 / F2 / R3-T3: rotation red-proof — Fixed (redesigned)
- **Redesign:** rotation is now the first case after the prelude, and peer 0's rosenpass restarts twice. Each restart's first key must be accepted by hs (`installed(..., key=new)`). Failure message: "rotation: hs did not accept restart N's first key".
- **Precondition:** before restart 2's key is tried, it must be written less than `REJECT_AFTER_TIME − EXPIRY_SLACK_S` after restart 1's key was written. Restart 1's install is no earlier than that write, so restart 1's entry is provably Live when restart 2's key arrives.
- **Why the mutant is always caught:** an hs that ignores supersession of a Live entry refuses restart 1's key (the prelude's entry is Live, only seconds after the prelude). Failing that, it refuses restart 2's key. Moving the case first also removes the path where earlier cases fail under the mutant (R3-T2 b).
- **Removed:** the single-shot "current key" precondition, and with it F2's None path.
- **Needle:** a single failure-only string, "rotation: hs did not accept restart". The tuple-needle support stays for future use.

### R3-T1: lint-pds red-proof — Fixed
- **Injection:** `#[allow(dead_code)] fn selftest_lint_pd(x: u8) -> bool { x == x }`.
  - `clippy::eq_op` is deny-by-default in clippy and unknown to rustc.
  - The needle is `clippy::eq_op`.
- **Verified on scratch copies:**
  - Clippy on: `make lint-pds` exits 2, and the log names `clippy::eq_op`.
  - Lints off (`-A clippy::all`): it exits 0, so only clippy running on the PD catches it.

### S-9 / R3-T4: fixtures for the new fail-closed clauses — Fixed
- **package:** a `[[package]]` entry without a name → "...entry without a string name".
- **P6:** a lock with a non-UTF-8 byte, and a nameless entry.
- **Red-proofs:** removing either clause makes its fixture runner fail. The package run crashes with a traceback; test_check_pins stops on "exit status disagrees with output". Either way the gate goes red.
- **Counts:** PACKAGE-FIXTURES 93, CHECK-PINS-FIXTURES 72.

### F3 — Fixed
The `required_open` docstring now names the structural `WaiverError`.

### F4 — Fixed
`zeroize::Zeroize::zeroize` (volatile) replaces `.fill(0)` on the dead locals: `pds/key` seed and samples, `hs-core/index.rs` hash. hs-core and pds/key gain the pinned `zeroize =1.8.1`, which was already in Cargo.lock.

### Verification (Round 3 fixes)
- `make check` exit 0. INTEGRATION-CASES 22, PACKAGE-FIXTURES 93, CHECK-PINS-FIXTURES 72, LINT-PDS 11.
- Selftest cases `integration-rotation` (needle "rotation: hs did not accept restart"), `integration-expiry` and `lint-pds` each fail with their failure-only needles.

# Round 4

## Findings (Round 4)
- **Security:** No findings. S-9 and F4 are verified, with no R43 widening.
  - Noted, not filed: the hash-function internals keep by-value copies, which is the dependency residue P10 already declares.
- **Functionality:** F1–F4 resolved.
  - F5 [Major]: moving the rotation before Case 2 broke Case 2's latest-handshake baseline once the rotation exceeded REKEY_AFTER_TIME.
  - F6 [Minor]: the rotation precondition bounded restart 2's key_out write, not its install.
  - F7 [Minor]: the expiry comment's freshness reason was wrong.
- **Testing:** R3-T1, R3-T3 and R3-T4 resolved; R3-T2 partial.
  - R4-T1 [Major]: the same as F5.
  - R4-T2 [Minor]: the same as F6. In addition, `k1_at` was read after `installed()`, and a slow clean run hard-failed instead of retrying.

```json
[{"id":"F5","severity":"Major","title":"Case 2 baseline invalidated by rotation placement","file":"tests/integration/run.py","line":1014,"adjacent":false,"escalate":null},
{"id":"F6","severity":"Minor","title":"rotation precondition bounds write not install","file":"tests/integration/run.py","line":980,"adjacent":false,"escalate":null},
{"id":"F7","severity":"Minor","title":"expiry comment reason wrong","file":"tests/integration/run.py","line":1153,"adjacent":false,"escalate":null},
{"id":"R4-T1","severity":"Major","title":"same as F5","file":"tests/integration/run.py","line":1014,"adjacent":false,"escalate":null},
{"id":"R4-T2","severity":"Minor","title":"same as F6; k1_at late; no retry","file":"tests/integration/run.py","line":980,"adjacent":false,"escalate":null}]
```

## Resolution Status (Round 4)

### F5 / R4-T1 — Fixed
- **Action:** the rotation now runs after Cases 2 and 3 and before the L8 pair.
  - Cases 2 and 3 take seconds and install nothing over peer 0's entry, so the prelude entry is still Live at restart 1.
  - Cases 2 and 3 also pass under the mutant, so no earlier case fails outside the needle.
  - Case 2's baseline is again taken seconds after Case 1.

### F6 / R4-T2 — Fixed
- **New precondition:** a restart's key must be accepted less than `REJECT_AFTER_TIME − EXPIRY_SLACK_S` after the previous accepted restart's key was written.
  - The acceptance time is an upper bound on the new install, and the write time is a lower bound on the previous one. So the previous entry is provably Live.
  - The write time is captured right after `wait_key`.
- **Retries:** if a pair is too far apart, the client restarts again, up to `ROTATION_RESTARTS = 4`. A slow clean run stays green.
  - A mutant can only escape by every consecutive gap exceeding the bound. It then ends at the named precondition failure, not the needle, so the selftest goes red loudly.
- **Verification:**
  - `make test`: 22 cases, 0 of 46 pings lost.
  - `integration-rotation`: ok.

### F7 — Fixed
The comment now gives the actual reason: nothing initiates for peer 0 between the mark and the join.
- `make check` exit 0 on the commit that records this entry.
