# Plan: secureos-post-m6

The fix batch between M6 (closed at 2f9a942) and the redefinition of M7.
It ends with the Kozane rename and one combined long run. Scope comes from:
- the owner (2026-10-26);
- the project memory;
- an external static review of m3b–m6 (2026-10-25);
- the M6 session's findings.

Review findings are cited by ID: F*, S*, T* in round 1, N* in round 2,
R3-* in round 3 and R4-* in round 4, recorded in `secureos-post-m6-review.md`.

Process: contract-first, risk-tiered review, slices with fast gates, and no
long run until the last slice. The full `make check` and the full
check-selftest run once, after the rename. The rename is never run
alongside other implementation work.

## Project context

- Type: `mixed`. The project is an seL4/Microkit image (no_std Rust PDs), host tools and libraries.
- Test infrastructure: unit, Kani, Verus, bolero, ct/residue, QEMU integration and the gate self-test, all behind `make check`. There is no CI (SC9).
- Hosts:
  - gx10: arm64, 40 GB container cap;
  - z1mn: arm64, 40 GB cap;
  - mrx33: arm64, 7 GB cap, no Kani, excluded from timing gates.

  Solvers never run concurrently on one host.
- Verification environment constraints: VE1–VE11 as in M6.
  - **VE12:** TCG slows the guest CPU under host load while guest time advances. A case that judges a CPU-bound guest event against a wall-clock window is load-sensitive.
  - **VE13:** audit lines carry no guest timestamp, and the console lags under load. Ordering is therefore taken from one channel only, the sniffer, plus the cumulative `total=` counts (T3).

## Objective

- Close the external review's open items: the m3b Major, the m5 fail-closed point, and confirmation of the m6 Medium and Minor fixes.
- Make the two VPN boots that failed under load independent of it.
- Make the test tooling use all three hosts safely.
- Rename the project to Kozane before any public release.
- Run the long tests once, at the end.

## Contracts

### P1 — M3b: a load trigger that a rotating spoof cannot dodge (Critical tier)

**Problem.** The external review rated this Major; it is M3b residual R6 (7).
- **How the gate engages today:** the global InitHello meter falls below half, or a refusal fires (`RateLimited` or `RingReserved` → `refresh_load`).
- **The attack:** one mac-valid InitHello per `RP_HELLO_GLOBAL_INTERVAL_NS` (10 s), each from a fresh spoofed source. It spends only the global refill, and every source is new, so the gate never engages.
- **The cost:** each InitHello costs `pq` 8.5 s median and 16.1 s maximum of wall time at its budget (MCE-COST, TCG). The attacker holds `pq` at about 85 %.

**Decision.** Add a load trigger based on the occupancy of `pq` by **uncookied InitHellos whose exchange does not complete** (round 1 S2, F-M3; round 2 N1).
- **Every uncookied InitHello counts while in flight.** Its busy time is refunded only when its exchange completes: the matched InitConf proves the endpoint (`replied(Conf)` through a matched `awaited` entry with `conf_seen`).
- **Why completion, not the claimed source.** An uncookied source is unauthenticated, so a spoof could claim a proven peer's endpoint. A spoof can never complete an exchange, so it always drains the credit, whatever source it claims. A legitimate rekey or boot exchange completes, so it nets at most the drain of the exchanges in flight (the in-flight cap is 2).
- **Why cookied forwards are excluded.** Cookied work never drains, so load can still clear and the legacy probe still runs. M3b residual (6) stays true, with no lockout of 0.2.3 clients.

**The meter.**
- **Recording.** `RpGate::sent(kind, src, now_ns)` gains `now_ns`, and marks an uncookied InitHello entry as counted.
  - The callers that change are the ingress PD, proofs.rs and the unit tests.
  - `retire` (in `sync_pq`, which already has `now_ns`) pops it.
- **Attribution (round 3 R3-1).** `pq` serves its queue in order, so busy time is attributed only to the **oldest** counted InitHello in flight. That is the one being served. An entry queued behind it accrues nothing until it becomes the oldest.
- **The link (round 3 R3-1).** `sync_pq` runs `complete` and `replied(Hello)` before `retire`. So `complete()` **moves** the entry's attributed busy time (it zeroes it on the entry, round 5), `Completion::Reply` carries it, and `replied(Hello)` stores it in the `awaited` entry it creates. Busy time between the record and the retire goes unrefunded, which errs on the safe side.
- **The refund.** On `replied(Conf)` through a matched `awaited` entry, that stored busy time is credited back, saturating at the cap, and the entry's stored busy time is set to 0. Rosenpass re-answers a retransmitted InitConf, so a second match must refund nothing (round 4 R4-1). Nothing else refunds.
- **Signatures (round 4).**
  - `sent(kind, src, cookied, now_ns)`: the cookied flag decides whether the entry counts.
  - `complete(.., now_ns)`: the snapshot is taken at the record's time, not at the last transition.
- **Busy.** "Busy" means at least one counted InitHello entry is in flight.
- **State.** Written only at `sent`, `complete`, `retire` and the refund: the counted-entry count, the last transition time, the credit at that time, and the per-entry busy time.
- **Reading.** `RpGate::occupancy_credit(now_ns)` is a pure read, so `observe_load` writes nothing new and the state-equality harnesses hold (F-M2, T5). It computes the credit at `now_ns` from that state:
  - while busy, the credit drains at 1 ns per ns;
  - while idle, it refills at 1 ns per ns (target occupancy θ = ½);
  - it saturates at 0 and at `RP_PQ_BUSY_CREDIT_NS`.
- **Triggering.** `observe_load` treats a credit of 0 as a trigger, just like a refusal. It is evaluated at `now`, so it also runs from `tick_if_due`: a hung exchange triggers without a new transition (S4).
- **`pq_dead`:** idle, with the trigger off (F-m1).

**Constants.**
- `RP_PQ_BUSY_CREDIT_NS` = `RP_MAX_PEERS` × `RP_HELLO_GLOBAL_INTERVAL_NS` = 80 s. It is defined in ingress-core (F-m3) and asserted in the PD against `PQ_HANDSHAKE_COST_NS`'s order.
  - At boot, all 8 peers' exchanges complete, so each is refunded. The net drain is at most two exchanges in flight, about 32 s at the 16.1 s maximum, which is within the credit.
  - The attack, at one InitHello per 12 s, drains about 5 s per cycle, so load engages after about 16 cycles (about 190 s).
- θ = ½. This is stated against the residual below.

**Audit.** The occupancy trigger has its own event, `RpOccupancyLoad`. `RpUnderLoad` keeps its meaning. Tests and operators can then tell which trigger engaged (T2, F-M4).

**Residual (restated, S3).** R6 (7) is **narrowed, not closed**.
- A rotating spoof below θ, at about one InitHello per 17–20 s at the median cost, never triggers. It holds up to θ of `pq` time ungated.
- When real unproven traffic lifts the total above θ, the trigger fires.
- A peer's extra delay stays bounded by about one exchange, because the in-flight cap of 2 refuses a third.

**Rejected.**
- **Total occupancy:** it holds load on cookied work and locks out legacy clients (S2).
- **Excluding proven endpoints by their claimed source** (round 1's revision): an uncookied source is unauthenticated, so a spoof claiming a proven endpoint escapes the meter (round 2 N1).
- **Lowering the global refill:** it cuts rekey capacity, and the attacker matches the new rate.
- **Per-prefix meters:** spoofed sources choose their prefix.
- **Triggering when both in-flight slots are taken:** the attack keeps one slot busy.
- **Always-on cookies:** 0.2.3 cannot answer a CookieReply.

**Kept.**
- I1 and I2;
- the legacy probe;
- the proven reserve and credit;
- the awaited-conf reserve;
- `pq_dead` handling.

**Kani (F-M2, T5).**
- `any_rp_gate` generates the new fields with the credit within [0, cap] and the counted-entry count consistent with the in-flight queue.
- The harnesses whose load specification gains `spec_occupancy_empty` are named: `rp_cookie_lane_spends_nothing_and_is_never_asked_off_load` (the `loaded_before` and deadline assertion). That is the only spec change, and it is reviewed as a contract change.
- The equality harness `rp_refusals_before_admission_spend_nothing` holds unchanged, because the read is pure.
- New harnesses:
  - **the meter's update:** no overflow, the credit stays in range, and empty implies the trigger;
  - **refund only on completion:** the credit rises only through a matched `awaited` entry with `conf_seen`, and by no more than that entry's stored busy time (round 2 N1);
  - **no double refund (round 3 R3-1, round 4 R4-1, round 5).** `inflight_attributed + stored_sum + refunded_total ≤ busy_integral`, where:
    - `inflight_attributed` is the busy time on counted entries still awaiting their record;
    - `stored_sum` is the busy time stored in `awaited` entries;
    - `busy_integral` is the busy time, not saturated at 0;
    - `refunded_total` is the refunds counted before the cap saturates;
    - the last two are Kani ghost fields.

    `any_rp_gate` assumes the invariant, and every step re-proves it, which makes it inductive. The multi-step harness calls `sent`, `complete`, `replied` and `retire` directly. It avoids `sync_pq`'s record buffer, which forced the sync harnesses to split, and includes a repeated `replied(Conf)` on one awaited entry.
  - **split invariance:** the credit read at t2 after a transition at t1 equals a single read at t2, for the same busy state.
- Each new or changed harness runs alone first, under the 40 GiB cap.

**Unit tests (T6).**
- The credit at its boundary: 0 means a trigger, 1 ns means none.
- Saturation at the cap.
- A long duty cycle below θ never triggers.
- Two counted InitHellos in flight drain once, not twice.
- An exchange longer than the credit triggers through `tick_if_due`.
- Load clears after the credit recovers and `RP_UNDER_LOAD_AFTER_NS` passes.
- Cookied forwards never drain.
- A completed exchange is refunded; one whose InitConf never comes is not.
- Spoofs claiming proven peers' endpoints engage load through the occupancy trigger (round 2 N1; round 3 R3-2).
  - The spoofs rotate over 8 proven endpoints with distinct IPs, each at most once per `RP_HELLO_SRC_INTERVAL_NS`, one per 12 s overall, so the per-IP meter never refuses.
  - The test asserts `RpOccupancyLoad` and no `RateLimited` or `RingReserved` before it, so it fails under round 1's exclusion-by-source design.
- A completed exchange queued behind a spoof is refunded only its own service time (round 3 R3-1).
- 8 peers rekeying and completing at the rekey rate never engage load.
- `pq_dead` means no trigger.

**Selftest.**
- Unit gate:
  - remove the trigger;
  - invert the boundary;
  - change the refill constant;
  - refund without completion (round 2 N1).
- QEMU test gate: remove the trigger. The rotating-spoof case must then go red with a needle that only that failure prints (T2).

**Integration, the new case `rp rotating spoof` (T1–T3, F-M4).**
- **Setup (round 2 N3):** the spoofer is closed-loop. It sends the next mac-valid InitHello, from a fresh source, only after the previous RespHello is sniffed, plus a gap g.
  - The gap is chosen so that the service time plus g is at least `RP_HELLO_GLOBAL_INTERVAL_NS` plus a margin, so the below-half trigger cannot fire.
  - It is also chosen so that the service time over the service time plus g is at least θ plus a margin.
  - With one spoofed InitHello in flight at a time, `RingReserved` cannot fire.
- **Judged from the sniffer and cumulative totals only (VE13):**
  1. **Precondition.** `pq`'s measured service time per spoofed InitHello (InitHello to RespHello, sniffed) gives an occupancy of at least θ plus a margin. If not, the case fails with "attack below θ: case vacuous" rather than passing.
  2. **The verdict, a one-sided generous bound (round 2 N3).** The first CookieReply to a spoofed source comes within ⌈1.5 × N_model⌉ + 2 spoofed RespHellos. N_model comes from a host-side model of the credit fed with the sniffed service intervals minus a latency allowance. The trigger-removed red-proof never engages within the liveness timeout, so the slack costs no sensitivity.
  3. **Attribution.** `RpOccupancyLoad` is audited, and the `RpRateLimited` and ring-refusal totals did not change before engagement.
  4. **Bound after engagement.** The spoofed InitHellos `pq` serves are bounded by the clearances, as the existing spoof case judges.
  5. **Liveness.** A wall-clock timeout sized from that bound only bounds the case.
- The existing rp, cookie and rekey cases still pass.
- The rp gate boot also has a credit carried over from earlier cases. It is either drained to idle before this case, or this case runs first in its boot (F-m2).

**Legitimate load (T4, F-M3).** The suite has no 8-peer rekey workload; there are 3 client ports, and fan-in's bound is derived. So "completed exchanges never engage load" is shown analytically, by the refund and the unit test above, and is labelled derived. Boot fan-in is measured with the existing 3-client fan-in case, and the 8-client figure is derived from it.

### P2 — The two load-sensitive VPN boots (Major tier)

**Evidence.**
- During M6, "rp gate boot" ("rp spoof: the spoofed endpoint got no CookieReply under load") and "cookie boot a" failed when the host also ran a solver.
- Controlled reproduction on z1mn with 2 busy-loop cores, 4479d66's tree:
  - "rp gate boot" failed 3 of 3, with the same message;
  - "cookie boot a" passed 3 of 3.

**Decision.** Diagnose, then fix where the fault is.
1. **Instrument `rp_spoof_case`'s failure path (T7).**
   - From the sniffer: each spoofed InitHello after `RpUnderLoad`, each gateway frame to the spoofed endpoint, and the victim exchange's frames.
   - From the console: the `RpLoadCleared` edges, and the `total=` counters of `RpUnderLoad`, `RpCookieReplySent` and `CookieSuppressed` at the verdict.
   - Leading hypothesis to confirm or reject: `i0` is taken after the host sees `RpUnderLoad`. Under I1 a spoof under load does not refresh load. If the console lags, the 60 s hold lapses before the judged window starts.
2. **Reproduce** under 2 busy cores, and once next to a real Kani harness (serialised, capped), since busy loops do not reproduce memory pressure.
3. **Fix where it lies.**
   - In the test: re-judge by sniffer ordering and `total=` counts (VE13).
   - In the product: fix it with its own control.
4. **Audit the wall-clock verdicts of both boots (T8).**
   - In cookie boot a: the keepalive's 10–13 s window, the `py_ping` wait and the paired flood band.
   - In rp gate boot: the fan-in budget.
   - Each one is converted to an ordering or count verdict, or recorded as a liveness timeout with its margin.

**Diagnosis (slice 1, 2026-10-26).** The cause is in the test, not the product.
- **The runs:** z1mn, 2 busy cores, the instrumented run.py, 3 of 3 failing.
- **What the sniffer shows:** after load engaged (`i0`), the victim ran the cookie path to EmptyData in 0.75 s.
- **What reached the spoofed endpoint:** no spoofed InitHello arrived in that window; the spoofer sends once a second. The only frame to the spoofed endpoint was a RespHello for a spoof forwarded before engagement, which the existing `pending` allowance accounts for.
- **Why it fails:** the verdict's window ends when the victim completes. Whenever the victim is faster than the spoof period, the window holds no spoof, so the case fails while the gate behaves correctly.
- **The fix:**
  - the window no longer ends at the victim's completion;
  - the case keeps spoofing and judges within load's hold (`RP_UNDER_LOAD_AFTER_NS` after the last trigger): a CookieReply to the spoofed endpoint must be sniffed before the console shows `RpLoadCleared` (cumulative totals, VE13);
  - it fails only if load clears without one, which would be a product fault, or if the liveness timeout expires.

**Acceptance.**
- Both boots pass 3 of 3 under 2 busy cores, and once beside a capped Kani run.
- Every verdict in them is an ordering or count, or a recorded liveness timeout.
- The memory rule "integration only on a host with no solver" is retired for these two boots only. The other boots are not qualified under load (T8).

### P3 — M5: a PCR cap failure stops every key domain (Major tier)

**Problem.** `tpm`'s `cap()` gives up silently after 3 failed attempts. The other domains keep serving with PCR 8 at its sealed value.
- `tpm` has no audit channel, and L1 (`check_tpm`) forbids non-key channels.
- A panic inside the passive `tpm` hangs only the caller of the last Done (round 1 S1, F-C1).
- A bus attacker (RM5-5) bypasses `tpm` and can unseal while the machine is powered, whatever `tpm` does.

**Decision.** Detection, then a forced stop of every serving domain. This is an integrity and availability policy, not a closed RM5-5 window, so RM5-5 stays unchanged.
1. **The failure is reported.** `tpm` answers the final `REQ_DONE` with a non-OK label when the cap is not confirmed. `tpm2::boot::unseal` maps it to a new `UnsealError::CapFailed`, with its own `BootError` code, so the audit and the integration needle are specific (round 2 N2 c). That client's PD (hs, pq or tls) audits `TpmCapFailed` and halts through its existing `KeyUnavailable` path.
2. **A cap barrier (round 2 N2 a, b).** Every key PD, after its own Done, asks `tpm` for the cap status before it releases its key.
   - **A new `layout::tpm` IPC label,** handled in `Tpm::handle` next to `REQ_DONE`. It is not a TPM command code: the gate's command allowlist refuses a Done client before it reads that list.
   - **A new `Gate::cap_status(client)`** answers Pending, Confirmed or Failed, for a client in Done only; Fresh, Unsealing, Failed and unknown clients are refused.
     - Pending is answered `RSP_BUSY`.
     - Failed is answered with a new refusal code, giving `CapFailed`.
   - **A separate bit.** The gate's `capped` is set whatever the device answers, so a separate confirmed/failed bit, set by the pure attempt function, carries the verdict.
   - **So every domain fails closed,** not only the last one. The channel set is unchanged, so L1 is not amended.
   - **The wait bound.** "Pending" lasts while other clients have not finished, plus the cap. The barrier's timeout is at least `BUSY_TIMEOUT_NS` + `CAP_ATTEMPTS` × `CAP_ATTEMPT_DEADLINE_NS` (decision 3, round 3 R3-3), stated as a const assert in tpm2's boot.rs, so a slow TCG boot does not halt every domain.
   - **A client that never sends Done** now halts every domain. That is fail-closed, and it is stated.
   - **No deadlock.** The key PDs are passive with MCS budgets, so a polling higher-priority PD cannot starve `pqkey`'s init. This is the same pattern as today's Busy wait.
3. **The decision is a pure function.** The retry loop moves behind a transport trait in tpm2-wire. A function maps each attempt sequence to confirmed or failed. Not due yet is distinct from a failed extend (T11).
   - Each cap attempt gets one overall deadline, `CAP_ATTEMPT_DEADLINE_NS`, enforced by the loop and shared from tpm2-wire, together with `CAP_ATTEMPTS`.
   - The barrier timeout is then `BUSY_TIMEOUT_NS` + `CAP_ATTEMPTS` × `CAP_ATTEMPT_DEADLINE_NS`, and the const assert in tpm2's boot.rs can see both (round 3 R3-3).
   - The TIS waits inside an attempt (locality, commandReady, each burst, Expect, valid) stay as they are, bounded by the attempt deadline.

**Acceptance.**
- **Unit sequences:**
  - fail, fail, ok → confirmed;
  - three failures → failed;
  - a transport error, a non-zero response code and a short response each count as a failure;
  - not due → no verdict.
- **Unit, tpm2 PPC tests:** a non-OK Done gives `TpmUnavailable`, and the cap-status barrier answers.
- **Kani:** `Gate::cap_status` changes no state, and is never Confirmed unless every client finished and the extend was confirmed; the existing gate harnesses still pass.
- **Integration (T10):** `TpmProxy` gains a `PCR_Extend` failure mode. In a new boot case:
  - the gateway does not serve: no WireGuard handshake response and no HTTPS;
  - `TpmCapFailed` is audited;
  - the audit line is the needle.
- **Selftest:**
  - a mutation that ignores the failure turns the boot case red (test gate);
  - a mutation that skips the barrier turns it red too;
  - a check-pins rule that the key PDs call the barrier, with a pins-gate selftest that deletes the call.

### P4 — Tooling (Minor tier)

**(a) The proof lock (F-m4).** `tools/proof-lock` already lives outside both hashed gates (M5, 1d41e68). What remains is the `SECUREOS_PROOF_LOCKED` lines inside kani-gate.sh and verus-gate.sh, which P7 renames. That invalidates every proof cache once, inside the long run.
- **Acceptance (T15):**
  - the kani-cache allow side is green after the rename;
  - two lock-wrapper runs with a stub command do not overlap;
  - `lslocks` shows no holder of the old path when it switches.

**(b) `tools/selftest-split` (T12, F-m5).**
- **Classification:** it imports check-selftest's `CASES` and its `closure()` over the Makefile, not a regex. The partitions are:
  - QEMU test-gate cases (serial);
  - solver cases, kani and verus (serial);
  - cases that build PDs (serial, because the `pd_target` under `~/.cache` is shared, T13);
  - the rest, in N parallel instances, each with its own `TMPDIR`.
- **Inputs on other hosts:** it copies `build/counts`, `build/kani-cache` and `build/verus-cache` from the `make check` host. The cache keys use relative paths, so the copies are portable.
- **The merge** checks that:
  - the cases run equal `set(CASES)`, each exactly once;
  - every instance exited and printed `SELFTEST-LAYERS`;
  - every instance ran the same commit hash.
- **check-selftest changes:**
  - It stops with a named message when `build/counts` is missing.
  - A failing `edit()` (its `SystemExit`) is caught per case and reported as that case's failure, so it does not abort the instance.
- **Fixtures:**
  - a crashed instance;
  - a duplicate case;
  - a missing case;
  - a commit mismatch;
  - a multi-line Makefile target;
  - `integration-count`, which runs the full suite.

**(c) The Kani guard and the per-harness runner (T14, F-m6).**
- The sources to promote are `build/kani-guarded.sh` and `build/wt-r2/build/hw-one.sh`. They become `tools/kani-guarded` and `tools/kani-harness`.
- The RSS decision becomes a function tested against fixture `/proc` data.
- **Red-proofs:**
  - a fake `cbmc` on PATH allocates memory and blocks; the guard's own message is the needle, and no process of the group survives;
  - a separate red-proof covers the timeout's process-group kill;
  - `--exact` runs exactly one harness.

### P5 — amd64 development image (Minor tier, T18)

- **Change:** `docker/Makefile` gains a `linux/amd64` build of the dev image.
- **Acceptance:** the image builds, and `make unit` passes in it on an x86_64 host. QEMU integration on x86_64 TCG is a new timing environment: it is run once, and its result is recorded, not gated.
- **If no x86_64 host is reachable:** the build alone is the acceptance, and the run is blocked-deferred.

### P6 — m6 external-review items (Minor tier)

- **The Medium (client-address fields):** fixed in 1e4fe75 (`X-Envoy-*` dropped, the contract stated in http-wire and plan C9). The README states the deployment requirement in full (S8):
  - the backend accepts connections only from the gateway, enforced at the network level;
  - it trusts X-Forwarded-For and X-Forwarded-Proto only on those connections;
  - it expects exactly one X-Forwarded-For, which is the proxy's, since the incoming ones are dropped;
  - it ignores every other client-address field.
- **The Minor (the test-only randomness API):** fixed in 1e4fe75 (P20 restricts `hello_keys` and `exchange_with_randomness` and catches aliases). The long run's pins gate confirms it.

### P7 — Rename to Kozane (last slice)

The specification is the owner's rename brief (memory
`rename-to-kozane-after-m7`, decided for after M6), with these round-1
additions.

**Format changes, each decided deliberately:**
- **Release domain.** `tools/release/src/sig.rs` DOMAIN becomes `b"kozane-release-v1\0"`. Nothing has shipped, so it stays at v1.
  - The verifier knows only this constant; there is no dual-domain acceptance.
  - A negative test checks that a valid-key signature over `secureos-release-v1\0` ‖ manifest is refused.
  - Every fixture is re-signed under the new domain only (S5).
  - The NUL keeps the two domains prefix-free.
- **Cookie nonce label** (`crates/rosenpass-core/src/cookie.rs`): it is our own label. Upstream draws a random nonce and sends it in the reply. So it changes; interop is unaffected.
- **rp-vectors KAT labels** (S6): regenerated only through the pinned `rosenpass-oracle` image, after confirming that only the label-dependent entries change. If the oracle cannot produce them, the labels stay, because they are test inputs, not wire format. That decision is recorded.
- **U-Boot banner and boot script, and run.py's matches:** measured values change.
- **`--remap-path-prefix`, and the `pd_target` path under `~/.cache`** (T17): both enter the reproducible digests, so both are format changes. `make repro` reruns.

**Plain renames:**
- `system/secureos.system` → `system/kozane.system`, still one file;
- `support/u-boot/secureos.config`;
- the `SECUREOS_*` variables → `KOZANE_*`. `crates/config/build.rs` and run.py fail when an old variable is set and the new one is not (S7, T17), so a stale `SECUREOS_CONFIG` or `SECUREOS_IT_BOOTS` cannot silently use defaults;
- the proof lock path, switched while nothing holds the old one;
- the mkcert CA name, with the dev certificates regenerated;
- test strings, with their needles;
- Docker names, with the containers recreated on all three hosts;
- the living docs.

**Not changed:**
- `docs/archive/` names and contents;
- the policy files' citations of archive names;
- past commit messages.

**Checks:**
- **Dry pass (T16).** A check-selftest mode applies every injection without running make, and fails on any anchor that no longer applies. It is the gate of slices 4 and 5.
- **Needle check.** No needle appears in the green `make check` logs.
- **Allowlist.** `policy/secureos-allowlist` lists every justified remaining hit, covering `secureos`, `secure_os` and `secure-os`, and check-pins verifies it.
- **After the directory move,** repro and pins rerun from the new path.

**After the commit, with the owner's confirmation:**
- the working directory moves to `.../ngc-shj/kozane`, and the memory directory is copied to the new project key first;
- the same on z1mn;
- the rename memory is updated.

## Testing strategy

- **Each slice runs its own gates:**
  - unit, lint and pins;
  - the Kani harnesses of the crates it touched, new or changed ones alone first;
  - the integration boots it affects. Once P2 has landed, the two P2 boots also run under 2 busy cores.
- **The combined long run, after P7:**
  - the full `make check`, solo on gx10;
  - check-selftest through `tools/selftest-split`. QEMU test-gate cases run serially on a host with nothing else running (z1mn, T9). Solver cases run serially on gx10 after `make check`. PD-building cases run serially. The rest run in parallel on gx10, with mrx33 taking non-QEMU, non-solver cases;
  - a QEMU measured-boot check with the new banner and pins.

## Slices

1. **P2 instrumentation and diagnosis.** In parallel: P1's unit-level meter and its Kani harnesses (no PD wiring yet).
2. **P1 wiring and integration, plus P2's fix.**
3. **P3.**
4. **P4 (b), (c), P5 and P6.** The check-selftest dry pass becomes a gate.
5. **P7, with P4 (a)'s variable rename.**
6. **The combined long run.** Then commit, with gates first.

## Residual risks added or changed

- **R6 (7), the rotating spoof:** narrowed by P1/A1. About one unfinished uncookied InitHello per `RP_UNFINISHED_INTERVAL_NS` (60 s), plus a one-off burst of `RP_UNFINISHED_BURST` − 1 from a full meter, from any claimed source, reaches `pq` ungated. A peer's extra delay stays about one exchange.
- **RM5-5:** unchanged. P3 adds detection and a forced stop of every key domain on a cap failure; it does not close the bus window.
- **RM6-11:** unchanged. Kani loop contracts remain a later candidate.

## Out of scope

- M7's redefinition under QEMU (memory `m7-virtual-not-board`), planned after this batch.
- Kani loop contracts (RM6-11).

### P1 amendment A1 (2026-10-26, after slice 2's first QEMU run; owner decision)

**Evidence.** The time-based occupancy trigger does not fire against the attack on our hosts.
- **The measurement.** The rotating-spoof case on mrx33 failed its precondition as vacuous: modelled occupancy 0.17 over 3 cycles, against the required 0.55. On idle TCG hosts `pq` serves an InitHello in about 0.7–2 s (`RpCostHighWater` ≈ 0.73 s on z1mn), not the 8.5 s that M3 measured on a host loaded by Kani.
- **Why the trigger cannot fire.** The global meter limits uncookied forwards to one per 10 s, so the attack holds `pq` at 7–20 %. That is far below θ = ½, and lower still on hardware.
- **The root cause.** Anything that measures `pq` time inherits the host's speed. The test then cannot be made non-vacuous, and the threshold means something different on every host.

**Supersedes.** A1 replaces P1's time-based paragraphs: the meter's busy and idle accounting, "Constants" (the `RP_PQ_BUSY_CREDIT_NS` credit and its order assertion against `PQ_HANDSHAKE_COST_NS`), θ, and "Residual (restated, S3)". Where they conflict, A1 governs.

**Decision (owner, 2026-10-26).** P1's trigger counts **uncookied InitHellos whose exchange did not complete**. It counts events, not time. Everything else in P1 is unchanged: the refund-on-completion idea, the exclusion of cookied work, I1/I2, the legacy probe, `pq_dead` as idle, and the separate audit event.

**The meter.** A refill meter in ns units, the same shape as `ingress-core`'s existing `Meter`: lazy refill at 1 ns per ns from its last update, saturating.
- **Constants:**
  - `RP_UNFINISHED_INTERVAL_NS` = 60 s, the cost of one unfinished InitHello;
  - `RP_UNFINISHED_BURST` = `RP_MAX_PEERS` (8), the capacity in InitHellos. The capacity is `RP_UNFINISHED_BURST` × `RP_UNFINISHED_INTERVAL_NS`.
- **Spend.** `sent(kind, src, cookied, now_ns)` spends one interval for an uncookied InitHello, saturating at 0; it never refuses. The entry is marked counted.
- **Carry.** `complete()` moves the counted mark into `Completion::Reply`. `replied(Hello)` stores it in the `awaited` entry.
- **Refund.** `replied(Conf)` through a matched `awaited` entry refunds one interval if the entry carries the mark, saturating at the capacity, and clears the mark. A repeated Conf refunds nothing. Nothing else refunds.
- **Trigger.** `observe_load` treats a credit below one interval as a trigger, by a pure read at `now`, so it also runs from `tick_if_due`. It is audited as `RpUnfinishedLoad`, which replaces the `RpOccupancyLoad` name.
- **What that gives:**
  - an attack at one spoof per 10 s spends 60 s and refills 10 s per cycle, so it engages after about 9 spoofed InitHellos (about 90 s), on any host;
  - a spoof at most one per 60 s never engages. That is the restated residual: about one unfinished uncookied InitHello per `RP_UNFINISHED_INTERVAL_NS`, plus a one-off burst of `RP_UNFINISHED_BURST` − 1 from a full meter, from any claimed source, reaches `pq` ungated;
  - legitimate exchanges complete and are refunded. Boot fan-in fits the capacity of 8. A legitimate InitHello whose exchange does not complete, such as a retransmission's twin, costs one interval each.

**Compile-time pins (A1 review).** These are const asserts in ingress-core, marked may-not-be-weakened. They replace the pqkey-core assertion on `RP_PQ_BUSY_CREDIT_NS`:
- `RP_UNFINISHED_INTERVAL_NS > RP_HELLO_GLOBAL_INTERVAL_NS`, so an attack at the global rate drains the meter and engages it;
- `RP_UNFINISHED_BURST > RP_HELLO_IN_FLIGHT`, the headroom for boot fan-in.

**Changed acceptance.**
- **Kani.** The occupancy harnesses are replaced by:
  - the meter in range, with "empty triggers";
  - the split-invariant read;
  - refund only through a matched `awaited` entry carrying the mark;
  - the inductive no-double-refund invariant `inflight_counted + awaited_marked + refunded_total ≤ spent_total` (ghost counters), with one harness per operation: `sent`, `complete` plus `replied(Hello)`, a repeated `replied(Conf)`, and `retire`;
  - the existing `rp_*` harnesses, with `spec_unfinished_empty` taking `spec_occupancy_empty`'s place.
- **Unit tests.** P1's list, restated in counts:
  - the boundary: one interval left means no trigger, less means a trigger;
  - saturation;
  - one per 60 s never triggers;
  - spoofs claiming proven endpoints, rotated within the per-IP meter, engage through `RpUnfinishedLoad`;
  - a completed exchange is refunded, one without its InitConf is not, and a repeated Conf refunds nothing;
  - 8 peers rekeying and completing never engage load;
  - `pq_dead` means no trigger.
- **Selftest (unit gate).** The mutations are: remove the trigger, invert the boundary, double the refill, refund without the mark.
- **Integration (`rp rotating spoof`).**
  - The closed-loop spoofer stays, so `RingReserved` cannot fire and the period stays at or above `RP_HELLO_GLOBAL_INTERVAL_NS` plus a margin.
  - The vacuity precondition on time occupancy is removed. There is no θ: the trigger does not depend on service time. The case instead requires the measured period to be below `RP_UNFINISHED_INTERVAL_NS`.
  - **The verdict.** The first CookieReply to a spoofed source comes within ⌈1.5 × N⌉ + 2 spoofed RespHellos, where N is computed from the constants and the measured period: spoofs until the credit falls below one interval.
  - Attribution (`RpUnfinishedLoad`, no refusals before it) and the post-engagement bound stay as they are.
- **Credit carry-over.** The case still drains to idle first. It waits for the credit to refill to its capacity, at most `RP_UNFINISHED_BURST` × `RP_UNFINISHED_INTERVAL_NS` after the last forward.
