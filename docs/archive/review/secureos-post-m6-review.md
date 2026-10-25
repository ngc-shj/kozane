# Plan Review: secureos-post-m6

## Round 1 (2026-10-26)

Three experts reviewed the first draft.

| Expert | Critical | Major | Minor |
|---|---|---|---|
| Functionality | 1 | 4 | 6 |
| Security | 0 | 2 | 6 |
| Testing | 0 | 12 | 6 |

### Critical and Major findings, by contract

**P3**
- F-C1, S1: `tpm` has no audit channel, and L1 forbids one. A halt inside the passive `tpm` hangs only the last caller, so the other domains keep serving. A bus attacker bypasses `tpm` anyway, so RM5-5 is not narrowed.
- T10: the claim that the integration case is not available under swtpm is false. `TpmProxy` can inject a failure.

**P1**
- S2: total occupancy holds load on cookied work, which locks out legacy clients.
- F-M1: the transitions happen at `sent` and `retire`, `sent` has no `now_ns`, and a credit read only at transitions misses a long busy period.
- F-M2, T5: the Kani harnesses encode the trigger set, and a fold that writes state breaks the equality harnesses.
- F-M3, T4: legitimate 8 peers come to 57 %, above θ, and the cited 8-peer rekey case does not exist.
- F-M4, T1, T2, T3: the integration case is a wall-clock bound that depends on host speed. It can pass through the old triggers. Console and sniffer ordering get mixed.

**P2**
- T7: the instrumentation leaves out the leading hypothesis (load clears while the console lags).
- T8: both boots have other wall-clock verdicts.

**The long run**
- T9: QEMU cases would run on loaded hosts.

**P4**
- T12: the selftest-split merge and classification are underspecified, and other hosts lack the counts and proof caches.
- T14: the guard's red-proof depends on timing.

**P7**
- T16: renamed paths break selftest injection anchors, and nothing would show it until the long run.

### Minor findings
- S3 to S8;
- F-m1 to F-m6;
- T6, T11, T13, T15, T17, T18.

### Resolution
All findings are resolved in the plan's revision, and each change cites its finding inline. The main changes:

- **P1:**
  - occupancy of uncookied, unproven InitHellos;
  - `sent(kind, src, now_ns)` records whether a forward counts;
  - the credit is a pure read at `now_ns`;
  - `pq_dead` counts as idle;
  - an 80 s credit;
  - its own `RpOccupancyLoad` event;
  - the residual restated as narrowed;
  - named Kani spec changes, plus a split-invariance proof;
  - a count-based integration verdict from the sniffer with a vacuity precondition, the spoofer slower than the refill, and attribution.
- **P2:** load-clear edges and totals instrumented; the leading hypothesis stated; one run next to a capped Kani; a wall-clock verdict audit of both boots; the memory rule retired for those two only.
- **P3:**
  - a non-OK Done goes to `TpmUnavailable` and the caller's existing halt;
  - a cap-status barrier on the existing channel, so L1 is unchanged;
  - a pure attempt-sequence function behind a transport trait;
  - a `TpmProxy` PCR_Extend failure boot case;
  - RM5-5 unchanged.
- **P4:**
  - (a) is already done in M5; the variable rename moves into P7;
  - selftest-split classifies with `CASES` and `closure()`, has serial QEMU, solver and PD-building partitions, copies the counts and caches, and checks completeness, uniqueness and the commit;
  - `edit()` failures are contained per case;
  - the guard's decision function gets fixture tests and a fake-cbmc red-proof.
- **P5:** `make unit` gates; the QEMU result on x86_64 is recorded only.
- **P6:** the README contract is complete.
- **P7:**
  - a negative test for the old release domain;
  - KAT labels only through the pinned oracle;
  - legacy variables fail;
  - the pd_target path is treated as a digest change;
  - a dry pass of every injection as a slice gate;
  - a needle check;
  - a committed leftover allowlist.
- **The long run:** QEMU on an idle host, solvers on the other.

## Round 2 (2026-10-26, one verifier, all perspectives)

Every round 1 Critical and Major finding is resolved, except F-M4/T1–T3, which continue as N3.

New findings:

- **N1 (Major): the proven exclusion keys on an unauthenticated source endpoint.** A spoof that claims a proven peer's endpoint escapes the meter.
  - Resolved: every uncookied InitHello is counted, and its busy time is refunded only on completion, through `replied(Conf)` with a matched `awaited` entry (`conf_seen`).
  - Added: a Kani harness proving refund only on completion, unit tests for a spoofed proven endpoint, and a refund-without-completion mutation.
- **N2 (Major): the cap barrier spec was wrong in three ways.**
  - (a) `REQ_CAP_STATUS` was placed in the command allowlist, so every boot would halt.
  - (b) The wait bound ignored the other clients' flows.
  - (c) There was no distinct error code.
  - Resolved:
    - a new `layout::tpm` label, and `Gate::cap_status` for Done clients only, with a separate confirmed/failed bit;
    - a const-asserted timeout of at least `BUSY_TIMEOUT_NS` plus the cap's worst case;
    - `UnsealError::CapFailed` with its own `BootError` code;
    - a Kani harness that `cap_status` is pure and never Confirmed early.
- **N3 (Major): the rotating-spoof verdict was not deterministic.** A fixed period lets `RingReserved` fire, and the sniffed latency biased the model.
  - Resolved: a closed-loop spoofer with one spoof in flight and gap constraints, a one-sided generous bound ⌈1.5 × N_model⌉ + 2 with a latency allowance, and a liveness timeout sized from it.

## Round 3 (2026-10-26, one verifier)

Resolved from round 2:
- N3;
- N2 (a) and (c).

P1 also refuses refunds correctly when no RespHello arrives. Farming refunds is impossible, because a refund needs a peer index, which only pq's EmptyData supplies after real Rosenpass crypto.

New findings:

- **R3-1 (Major): double refund, and no link between entries.** With 2 in flight, served in order, a queued entry accrued the served one's busy time. Nothing linked the in-flight entry to its awaited entry.
  - Resolved:
    - busy time is attributed only to the oldest counted entry in flight;
    - `complete()` snapshots it, `Completion::Reply` carries it, and `replied(Hello)` stores it;
    - a Kani invariant bounds the stored total by the total drained;
    - a unit test covers an exchange queued behind a spoof.
- **R3-2 (Major): the proven-spoof test passed without the fix.** The per-IP meter refuses the second spoof as RateLimited.
  - Resolved: the spoofs rotate over 8 proven endpoints with distinct IPs, each within the per-IP meter. The test asserts `RpOccupancyLoad`, with no refusals before it.
- **R3-3 (Major): the barrier timeout undercounted the TIS waits, and its constants were private to the tpm PD.**
  - Resolved: each cap attempt gets one overall deadline, `CAP_ATTEMPT_DEADLINE_NS`, shared from tpm2-wire with `CAP_ATTEMPTS`. The timeout is `BUSY_TIMEOUT_NS` + `CAP_ATTEMPTS` × that deadline.

## Round 4 (2026-10-26, one verifier)

Resolved from round 3:
- **R3-2 and R3-3.** The per-attempt deadline is implementable with `cpu::now_ns()` and `min(default, remaining)` waits, and tpm2 already sees tpm2-wire's constants.
- **R3-1's design.** The queue is FIFO. Misattribution is harmless or conservative: a cookied InitHello served ahead charges a counted entry that is either refunded on completion or a spoof that triggers earlier. Missing links only lose refunds.

New finding:
- **R4-1 (Major).** The "no double refund" invariant (stored sum ≤ total drained) misses a double refund across refund steps: a retransmitted InitConf re-matches a live awaited entry. "Total drained" was also undefined at saturation.
  - Resolved:
    - the invariant is `stored_sum + refunded_total ≤ busy_integral`, over ghost fields, unsaturated and pre-cap;
    - the harness runs multi-step sequences with a repeated `replied(Conf)`;
    - a refund zeroes the entry's stored busy time.
  - The Minor notes are folded in: `sent` gains the cookied flag, and `complete` gains `now_ns`.

## Round 5 (2026-10-26, one verifier, scoped to round 4's change)

- **Confirmed sound.** Zeroing on refund (redundant with `replied(Conf)` clearing the entry, and harmless), the signatures, and a repeated-Conf multi-step harness is feasible and cheap.
- **One Major.** The invariant was not inductive from `any_rp_gate`: busy time on an in-flight counted entry could move into `stored_sum` without new busy time.
  - The verifier's exact fix is applied:
    - the invariant becomes `inflight_attributed + stored_sum + refunded_total ≤ busy_integral`;
    - `complete` moves the busy time instead of copying it;
    - `any_rp_gate` assumes the invariant.
  - This tightens the proof statement only, with no behaviour change, inside round 4's fix scope.

## Saturation call (2026-10-26)

No Critical or Major finding is open after five rounds.

- **Rounds 1 and 2** found real design defects:
  - P3 could not be built, and halting in the passive `tpm` stopped nothing;
  - P1 locked out legacy clients;
  - P1's proven exclusion could be spoofed;
  - the cap barrier's placement.
- **Rounds 3 to 5** converged on P1's refund accounting and its Kani statement, each change scoped to the previous one.

The plan is locked for implementation.
