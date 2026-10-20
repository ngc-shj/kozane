# Plan Review: secureos-m3b-cookie-gate

# Review round: 1
Date: 2026-10-20

## Changes from Previous Round

Initial review of plan rev 1.
- **Experts:** functionality, security and testing (Sonnet).
- **Escalation:** security escalated S1 to Opus, which confirmed and
  refined it.
- **Merge:** a local-LLM merge, checked by hand.
- **The result:** plan rev 2.

## Functionality Findings

| ID | Sev | Finding | Resolution (rev 2) |
|---|---|---|---|
| F1 | Major | `RP_HELLO_IN_FLIGHT = 2` regresses the 8-peer reboot fan-in, and the regression was undisclosed | Kept at 2, which bounds InitConf latency. The cost is stated: the serial bound plus one 10 s backoff. C6 case 6 measures it, as a deny/allow pair |
| F2 | Major | `Domains::v02()` has dead cookie fields on the BLAKE2b tree; `crypto.rs` was not in C1; the `KH` arity in the notation was wrong | Fields removed in C1. The `mix` chain is stated. `crypto.rs` and the vectors are added to the files |
| F3 | Minor | `RpCookieSuppressed` coalescing unstated | Coalesced (C4) |
| F4 | Minor | Trigger 4 needs a per-message input | Stated in the Design |
| F5 | Minor | Shift-on-rotate unspecified | Stated in §Cookie secret |
| F6 | Minor | 60 s hold had no rationale | Three spoof periods |
| F7 | Minor | `MSG_COOKIE_REPLY` already exists; the wire doc's claim | Noted; the doc is updated in C1 |
| F8 | Minor | SC20 is not a waivers.toml entry | Wording fixed |
| F9 | Minor | The NAT scenario omits the backoff round | Scenario 2 and §Lanes fixed |
| F10 | Minor | `sha3` versus `libcrux-sha3` undiscussed | Rationale added |
| F11 | Minor | Upstream has a poll-ratio heuristic | Cited; not adopted |
| A1 | Minor (Adjacent) | check-pins P9 misses named-type secret wrappers | The forbidden-pattern rule learns named types, with a fixture |

## Security Findings

| ID | Sev | Finding | Resolution (rev 2) |
|---|---|---|---|
| S1 | Critical | Proven markable by spoofed replay of a captured InitConf: the known-response cache is keyed by message hash, and `pq` replies to any source | **Opus refinement adopted.** The awaited entry `(E, sidi, sidr)` comes from each RespHello handed to the driver. An InitConf from E is matched only on `(sidi, sidr)`. Proven requires a `conf_seen` entry whose sidi equals the EmptyData's sid. Covered by I6, its unit pairs, C6 case 3 and selftest `rp-sid-binding`. The orchestrator's earlier fresh-flag proposal was rejected, for the reasons in the Opus output |
| S7 | Major | The proven table is a cross-peer LRU, so an insider can evict honest peers and starve them | Proven slots are keyed per configured peer, from a new `RpReply.index` (C3), with a per-slot credit (burst 2 per 120 s). The aggregate is asserted ≤ the refill |
| S2 | Major | CookieReplies share the TX half with WireGuard's | TX tiers: RP answers above `TX_RESERVE`; CookieReplies, WireGuard cookie replies and ARP above `TX_RESERVE + RP_ANSWER_SHARE` (I8). Combined flood: C6 case 7 |
| S3 | Major | Constant-time cookie compare not required | `cookie_valid` uses `ct_eq` on both secrets with no early exit, plus a check-pins tripwire |
| S8 | Minor | Awaited table size unspecified (merges first-tier S5) | Size assertion, no eviction of live entries, a per-entry budget of `RP_CONF_SRC_BURST` |
| S4 | Minor | Dead BLAKE2b cookie domains | Same as F2 |
| S9 | Minor | Compromised-`pq` residual mis-framed | Restated with the actual bound |
| S10 | Minor (Adjacent) | Reflection ratio misstated | Corrected; the rate is measured in C6 |
| S6 (first tier) | Minor | `sha3` "already locked" claim unverified | **Refuted by Opus:** `Cargo.lock:1702`, a dependency of cmr |

## Testing Findings

| ID | Sev | Finding | Resolution (rev 2) |
|---|---|---|---|
| T1 | Major | A `total=1` attribution anchor breaks in a shared boot | Every audit read is a delta since a mark (C4) |
| T2 | Major | Budgets unnamed | Derived from `RP_EXCHANGE_S`, the backoff cap, and the M2.5 `hs_deadline` |
| T3 | Major | The deny case's timing is infeasible | The spoof runs at 1/s, so the token stays at zero deterministically. The 20 s economics is a unit test. The layer's time is estimated |
| T4 | Major | A 2 GiB dump leaks on the monitor failure path | `pmem`'s `try/finally` now covers the monitor I/O. One snapshot per assertion, with one retry |
| T5 | Major | Selftest cases do not cover every invariant | One unit selftest case per invariant (I2–I6, I8), plus NAT |
| T6 | Minor | The "PSK went stale" needle is ungrounded | **Rejected:** the string exists at `run.py:2204` (`exported(..., "PSK went stale during flood: ")`) |
| T7 | Minor | The live-OSK count is only recorded | Kept, and recorded in the deviation log |

## Adjacent Findings

- **A1** (functionality → security): routed into the forbidden patterns.
- **S10** (security → functionality): prose fixed.

## Quality Warnings

The merge flagged F6, F8, F9, F10, S9, S10, T6 and T7 as [VAGUE] for
missing locations. The cause was the orchestrator's condensed
transcription. The experts' original outputs carry the locations (plan
lines 295, 12, 496, 215, 193, 481, 402 and 419), so no revision was
requested.

## Recurring Issue Check

### Functionality expert
R1 checked; R2 checked; R3 checked; R4 checked; R5-R9 N/A; R10 checked; R11 N/A; R12 fired (F3, F7); R13 N/A; R14-R16 N/A; R17 checked; R18 checked (see A1); R19-R21 N/A; R22 checked; R23-R28 N/A; R29 fired (F2, F7, F10, F11); R30-R33 N/A; R34 checked; R35 N/A; R36 checked; R37 N/A; R38 checked; R39 checked; R40 checked; R41 checked; R42 fired (F2); R43 N/A; R44-R48 N/A; R49 checked; R50 N/A; R51 checked; R52 fired (A1); R53 checked (F6); R54-R57 N/A.

### Security expert (Sonnet)
R1 N/A; R2 clean; R3 clean; R4 clean; R5-R11 N/A; R12 clean; R13-R17 N/A; R18 clean; R19-R28 N/A; R29 checked (upstream citations accurate); R30-R33 N/A; R34 fired (S4); R35-R37 N/A; R38 clean; R39 clean; R40 clean; R41 N/A; R42 clean; R43 fired (S1); R44-R47 N/A; R48 clean; R49 fired (S1); R50 N/A; R51 N/A; R52 clean; R53 checked; R54-R57 N/A.
RS1 fired (S3); RS2 clean; RS3 clean; RS4 N/A; RS5 N/A; RS6 N/A.

### Security expert (Opus escalation)
R1 OK; R2 note (sid offsets from rosenpass-wire); R3 applied (S1, S8); R4 OK; R5-R11 N/A; R12 OK; R13-R15 N/A; R16 OK; R17 flagged (ct_eq, S3); R18 N/A; R19 OK; R20-R28 N/A; R29 flagged (S10); R30-R31 N/A; R32 OK; R33 N/A; R34 OK; R35 OK; R36-R37 N/A; R38 flagged (S1); R39 OK; R40 note (S7 shape change); R41 N/A; R42 OK; R43 OK; R44-R47 N/A; R48 note (one adjudicator, no fresh flag); R49 flagged (S1); R50 N/A; R51 flagged (S1); R52 flagged (S1); R53 note; R54-R57 N/A.
RS1 flagged (S3); RS2 flagged (S2); RS3 OK; RS4 N/A; RS5 N/A; RS6 N/A.

### Testing expert
R1-R11 N/A; R12 checked; R13-R16 N/A; R17 checked; R18 N/A; R19 checked; R20-R28 N/A; R29 checked; R30-R31 N/A; R32 checked; R33-R38 N/A; R39 checked; R40-R41 N/A; R42 fired (T1, T5); R43-R44 N/A; R45 checked (T3); R46-R48 N/A; R49 checked; R50 checked; R51-R52 N/A; R53 checked (T2); R54-R57 N/A.
RT1 N/A; RT2 checked; RT3 checked; RT4 fired (T2, T3); RT5 checked; RT6 checked; RT7 fired (T5); RT8 checked; RT9 checked; RT10 fired (T5); RT11 fired (T4).

---

# Review round: 2
Date: 2026-10-20

## Changes from Previous Round

The plan went from rev 2 to rev 3.
- **Session binding:** per-peer proven slots, the TX tiers, and the
  `RpReply` record (Round 1 resolutions).
- **Round 2:**
  - reply credits (SC27 brought in, I9);
  - three named Hello tables;
  - credit arithmetic restated as refill rates;
  - Objective 4 restated as a priority, not a completion guarantee;
  - case 1 gets its own failure message;
  - cases 3, 6 and 8 are specified concretely.

## Functionality Findings

| ID | Sev | Finding | Resolution (rev 3) |
|---|---|---|---|
| F12 | Major | Proven credit 8 × 2 = 16 exceeds the refill of 12 per 120 s | Fixed during the round: the assertion compares refill rates (8 ≤ 12); the burst exceeds the meter's only once |
| F13 | Major | `RP_HELLO_SRC_*` used as both a per-IP and a per-endpoint meter, with no backing structure | Three named tables (`hello_src`, `hello_cookied_ep`, `hello_cookied_ip`); `SourceMeters` generic over the key; no carry-over between tables |
| F14 | Minor | Case 3's 4-token boundary needs a full meter | Precondition stated; the reserve is described as a floor, not a quota |

## Security Findings

| ID | Sev | Finding | Resolution (rev 3) |
|---|---|---|---|
| S11 | Major | A compromised `pq` can fabricate session state and flood tier-1 replies, holding tier 2 and WireGuard cookie replies | Reply credits: each forward grants one credit `(E, kind)`; a reply is relayed and fed to `replied` only by consuming one (I9, `rp-reply-credit`). SC27 is closed in M3b. S9's wording is corrected |
| S12 | Major | The proven-reserve sufficiency claim does not close, and it is liveness, not what I3 proves | Objective 4 is restated as a proved priority; completion is measured in C6 case 3; contention delay is R6 residual (4) |

Round 1's S1, S2, S3, S7, S8 and S10 resolutions were verified sound.

## Testing Findings

| ID | Sev | Finding | Resolution (rev 3) |
|---|---|---|---|
| T6 (reopened) | Critical | The cited needle `run.py:2204` is in M2.5's `flood_case`, unrelated to the cookie gate; the Round 1 rejection was wrong | Accepted. Case 1 has its own failure-only `Fail("rp spoof: …")` at a new call site, and its layer is red-proved by the gate mutation |
| T8 | Major | Case 6 at `--peers 3` does not measure the 8-peer bound | Kept at 3, which exercises the cap's refuse-and-retry path. The 8-peer bound is stated as derived (I4 arithmetic), not measured |
| T9 | Major | Case 3's InitHello construction unspecified | One sniffed InitHello replayed per port, with per-port cookies; no Python envelope mac |
| T10 | Minor | Case 1's sniff-then-spoof ordering | Poll-until-sniffed, then spoof |
| T11 | Major | Case 8 assumes quiescence | Explicit teardown, its own load engagement, and an `RpLoadCleared` delta since its mark |
| T12 | Minor | Reboot budget 1930 s versus the bound of 139 s | Budget from the MCE-COST maximum and `RP_SLACK_S` |
| T13 | Minor | `CHECK-SELFTEST-FIXTURES` not listed | Listed, with 10 new case names |

## Recurring Issue Check

### Functionality expert
R1-R11 N/A; R12 checked (audit code range); R13-R16 N/A; R17 checked (TX-reserve call sites verified); R18-R28 N/A; R29 fired (F12); R30-R37 N/A; R38 checked; R39 N/A; R40 checked (RpReply walkthrough); R41 fired (F13); R42 checked; R43-R47 N/A; R48 fired (F13); R49 checked; R50-R52 N/A (R52 noted under F12); R53 fired (F12); R54 N/A; R55 checked (0xFF sentinel vs MAX_PEERS); R56-R57 N/A.

### Security expert
R1 N/A; R2 checked; R3-R11 N/A; R12 clean; R13-R17 N/A; R18 clean; R19-R28 N/A; R29 checked (SID_LEN, biscuit ad, known_hash verified); R30-R33 N/A; R34 clean; R35-R38 N/A; R39 checked; R40 clean; R41-R42 N/A/clean; R43 fired (S11); R44-R48 N/A; R49 fired (S11); R50-R51 N/A; R52 fired (S11); R53 fired (S12); R54-R57 N/A.
RS1 clean; RS2 clean; RS3 clean; RS4-RS6 N/A.

### Testing expert
R1-R28 N/A; R29 fired (T6); R30-R41 N/A; R42 checked; R43-R48 N/A; R49 checked; R50-R52 N/A; R53 fired (T12); R54-R57 N/A.
RT1 checked; RT2 N/A; RT3 checked; RT4 checked; RT5 checked; RT6 checked; RT7 fired (T6); RT8 checked; RT9 checked; RT10 checked; RT11 checked.

---

# Review round: 3
Date: 2026-10-21

## Changes from Previous Round

The plan went from rev 3 to rev 4. S13 and S14 are one ownership problem,
so they were closed first as a single design fix: replies are owned by the
`InFlight` FIFO. The timed reply-credit design is withdrawn. F15 and
T14–T17 were then resolved in the same round, on top of that fix.

## Security Findings

| ID | Sev | Finding | Resolution (rev 4) |
|---|---|---|---|
| S13 | Critical | Rev 3's reply-credit table (24 entries, credits living about 33 s, its size borrowed from the awaited table) can be saturated by forged mac-valid InitConfs: the mac key is public, `pq` sends nothing back, and `conf_global` admits about 20/s. Honest replies are then dropped as uncredited, an off-path L8 outage. Confirmed by Sonnet and by the Opus escalation; settled, escalate false | **The FIFO is the credit table** (§Reply ownership, I9a–I9c). An entry is `(kind, src, answered)`, pushed only on a successful send. Only the unanswered head may be answered, and only by its kind's reply type. The reply goes to the stored `src`; `RpReply` has no endpoint field. The credit is spent at admission, before TX. Every unsolicited, duplicate, kind-mismatched or out-of-order reply is dropped and audited. The capacity is `RP_IN_FLIGHT` by construction: no timer, no second table, no full-table path |
| S14 | Major | `pq` returns its buffer at receive, so the processing InitHello is not in flight and a Hello cap of 2 allows 1 processing + 2 queued | **Before (rev 3, as found):** about 3 × 16.1 ≈ 48 s worst-case InitConf wait. **After (rev 4):** the buffer is returned only after the reply (a held receive in `ring`), so the processing entry is inside the cap. Cap 2 means 1 + 1, and the wait is about 2 × 16.1 ≈ 32 s. The plan's 32 s figure and the "6 refused" reboot figure hold only after the fix |
| S15 | Minor | The orchestrator's time-graced credit proposal rests on `pq`'s wall time and on when `ingress` reads a reclaim. Its InitConf-side capacity was miscounted as 28; the correct figure is 8 in flight + 8 burst + 20/s × 1 s = **36** | The proposal is rejected and recorded in the plan. Under the adopted FIFO design no such capacity constant exists: the credit capacity is `RP_IN_FLIGHT` = 10. So the 28→36 correction is kept here as an error of the rejected design, and the "revert 36 to 28" red-proof is replaced by mutations of the real bound (see below) |

### The order contract (added to C3, both directions)

1. `pq` takes one input and keeps its buffer.
2. It enqueues at most one reply.
3. Only then does it return the buffer.
4. It takes no next input before that return (a held receive; a second
   take fails closed).
5. `ingress` **snapshots** the returned count, **then** drains every
   reply, **then** retires exactly the snapshotted number of oldest
   entries.

The user's statement of item 5 was "process replies, then reclaim". It is
made precise here. If `ingress` drains first and reads returns afterwards,
`pq` can preempt between the two (priority 105 > 100), enqueue reply j and
return buffer j. The return would then be retired before reply j is read,
and the honest reply dropped. Snapshotting the returns first closes this:
a return counted in the snapshot had its reply published before it.

### Red-proofs required for the FIFO (C2)

Each is a mutation that must fail its test:
- the buffer returned before the reply;
- an uncredited reply admitted;
- `pq`'s endpoint used instead of the stored one;
- two replies from one entry;
- the reply types swapped;
- a non-head entry consumed;
- the processing entry excluded from the cap;
- the capacity assertion and length bound removed (the stand-in for
  "revert 36 to 28"; see S15);
- retire before drain.

## Functionality Findings

| ID | Sev | Finding | Resolution (rev 4) |
|---|---|---|---|
| F15 | Major | `RP_REPLY_CREDIT_NS` (2 × the MCE-COST maximum) equals its own worst-case queueing bound with no margin, and nothing ties it to `RP_HELLO_IN_FLIGHT` | Resolved by removal: the FIFO has no credit TTL. A credit lives exactly as long as its buffer is unreturned, so no margin is needed. The queueing bound itself is asserted as `RP_IN_FLIGHT == RP_HELLO_IN_FLIGHT + RP_CONF_IN_FLIGHT`, with the processing entry counted [S14] |

## Testing Findings

| ID | Sev | Finding | Resolution (rev 4) |
|---|---|---|---|
| T14 | Critical | I9 had no Kani proof and no unit test, against the "each proved by Kani" claim | I9a–I9c have pure `RpGate` methods (`sent`, `reply_admit`, `retire`), Kani harnesses with symbolic event order, and deny/allow unit pairs (unsolicited, duplicate, kind mismatch, out of order, failed send, capacity 10/11, interleavings). The integration allow side is a zero `RpReplyUncredited` delta in every case. Selftest: `rp-reply-fifo` and `rp-reply-order` |
| T15 | Major | `RP_SLACK_S` undefined | 10 s: the MCE-COST max − median spread (7.6 s) plus the 1 Hz ticks, rounded up; named once in run.py |
| T16 | Minor | `CHECK-SELFTEST-FIXTURES` said 10 but listed 9 | 11 new names: 10 in the C6 list plus `rp-cookie-domain`, derived from the list |
| T17 | Minor | `NoCookieSecret` had no unit pair | Added (missing or expired → `NoCookieSecret`; usable → `CookieReply`) |

Round 2's T6, T8–T13 resolutions were verified sound by the testing
expert. Round 2's S11 and S12 resolutions held as safety properties; S13
is the liveness gap S11's first fix introduced.

## Recurring Issue Check

### Functionality expert
R1 N/A; R2 checked; R3-R11 N/A; R12 checked; R13-R16 N/A; R17 checked; R18-R28 N/A; R29 checked; R30-R39 N/A; R40 checked; R41 checked; R42 N/A; R43-R47 N/A; R48 N/A; R49 checked; R50-R52 N/A; R53 fired (F15); R54 N/A; R55 checked; R56-R57 N/A.

### Security expert (Sonnet)
R1-R11 N/A; R12 clean; R13-R17 N/A; R18 clean; R19-R28 N/A; R29 checked; R30-R39 N/A; R40 clean; R41-R48 N/A; R49 fired (S13); R50-R51 N/A; R52 fired (S13); R53 fired (S13); R54-R57 N/A.
RS1 clean; RS2 checked (see S13); RS3-RS6 N/A.

### Security expert (Opus escalation)
R1 OK; R2 noted; R3 OK; R4-R11 N/A; R12 OK; R13-R28 N/A; R29 fired (S13, S14, S15); R30-R37 N/A; R38 fired (S13 full-table wedge, removed by the FIFO); R39 N/A; R40 noted (order contract); R41 N/A; R42 OK; R43 OK; R44-R47 N/A; R48 OK; R49 fired (S13); R50 N/A; R51 OK; R52 fired (S13); R53 fired (S15); R54-R56 N/A; R57 OK.
RS1 N/A; RS2 OK; RS3 OK; RS4-RS6 N/A.

### Testing expert
R1-R2 clean; R3 clean; R4-R6 N/A; R7 checked; R8-R11 N/A; R12 checked; R13-R15 N/A; R16 checked; R17 checked; R18 checked; R19 checked; R20-R28 N/A; R29 fired (T14, T16); R30-R33 N/A; R34 checked; R35 N/A; R36 clean; R37 N/A; R38 checked; R39 checked; R40 checked; R41 checked; R42 checked; R43 N/A; R44 checked; R45 checked; R46-R47 N/A; R48 checked; R49 fired (T14); R50 N/A; R51 checked; R52 noted (T17); R53 fired (T15); R54 N/A; R55 checked; R56 N/A; R57 checked.
RT1 checked; RT2 applied; RT3 clean; RT4 checked; RT5 checked (I9 unresolved at the time, now T14); RT6 fired (T14); RT7 fired (T14); RT8 checked; RT9 checked; RT10 checked (I9 lightly, T14); RT11 checked.

---

# Review round: 4
Date: 2026-10-21

## Changes from Previous Round

A short, scoped round on the FIFO design.
- **Scope:**
  - functionality: held-receive exit paths, snapshot arithmetic, the
    10/11 boundary;
  - security: stored destination, the same-kind swap residual, the bound
    on a compromised `pq`;
  - testing: whether each of the I9 event model's mutations goes red only
    for its defect.
- **Process:** each Critical or Major finding was fixed in place and
  re-checked only by the expert who raised it. There was no full re-review
  (the stopping rule).
- **The plan:** rev 4, completion-record design.

## Functionality Findings

| ID | Sev | Finding | Resolution | Re-check |
|---|---|---|---|---|
| F16 | Major | Admission at literal FIFO position 0 drops honest replies batched within one sync. The orchestrator traced it further: with "a return completes an unanswered entry", an honest `pq` that refuses j and answers j+1 gets j+1's RespHello sent to j's source | **Completion records.** `pq` emits exactly one ordered record per input (`Reply` or `NoReply`). Entries are `AwaitingRecord`, `CompletedReply` or `CompletedNoReply`, and each record goes to the first `AwaitingRecord` entry. The sync is snapshot → drain → assign → check that the oldest `r` are Completed → retire. A mismatch is a sticky protocol violation. Return-only completion is withdrawn | RESOLVED |
| F17 | Major | `take_into` erroring while holding a buffer, combined with `pdkit::recv`'s retry loop, can livelock | No buffer is held after a failure before ownership. A failed return makes the link dead. `Held` arises only on a genuine second take. `pdkit::take` tries once. The re-check's note: returning the buffer internally after `accept` is a return with no record, which can misassign the next record before the check fires. So a post-`accept` failure now yields `Ok(Taken::Unreadable)` with the buffer held, and `pq` sends `NoReply` and releases. This departs from "return internally where possible", for that reason | RESOLVED (note applied) |

## Security Findings

| ID | Sev | Finding | Resolution | Re-check |
|---|---|---|---|---|
| R4-F1 | Major (prose) | The invariant that keeps a same-kind swap from escalating to a false proof was not stated | Stated: every awaited and proven lookup is keyed by the FIFO's stored `src`. Unit case: a swapped E2 RespHello in E1's entry updates only E1 and proves nobody. Residual 5 restated | RESOLVED |
| R4-F2 | Major | The recovery semantics of "link dead" were undefined | **Sticky `pq_sync_dead` until reboot** (user decision). No new forward, no relay, no awaited or proven update, no guessed retirement. Audited once (`RpPqSyncDead`); WireGuard continues. A TX-refused valid reply is not a violation | RESOLVED |
| R4-F3 | Minor | The `in_flight()` floor was not stated | `pool.accept` rejects any buffer not lent or already returned (`link.rs:74-85`, `lib.rs:172-188`) | RESOLVED |

The security re-check also walked every violation trigger. Each needs a
buggy or compromised `pq`; none is reachable from network input, so
`pq_sync_dead` is not an off-path kill switch.

## Testing Findings

| ID | Sev | Finding | Resolution | Re-check |
|---|---|---|---|---|
| T18 | Critical | The retire-before-drain mutation targeted untestable PD code | The pure `ingress_core::sync_pq<T: PqSync>` has the fixed order, and the PD is a thin caller. It is tested through a mock `PqSync`, as `FakePass` tests `run_passes`. The 12 red-proofs are labeled Unit or Integration | RESOLVED |
| T19 | Critical | The "`pq`'s endpoint" mutation had no input | First fix: a differing-fixture destination test. The re-check showed the PD's `relay` was still unreachable. Second fix: `PqSync::transmit(dst, reply)` replaces `relay(&Completion)`, and `sync_pq` itself passes `c.dst` to `transmit` and `replied`. The PD gets no `index`, so the PD half is closed by construction and the pure half by the unit test | RESOLVED (second re-check: the destination is chosen only in pure `sync_pq`, and `transmit` has no `index`) |
| T20 | Minor | A bundled mutation | Split into items 8 and 9 | RESOLVED |

## Recurring Issue Check

### Functionality expert
R1-R2 N/A; R3 checked (release point traced through every branch of `one()`); R4-R16 N/A; R17 checked; R18-R28 N/A; R29 checked; R30-R37 N/A; R38 fired (F17); R39-R41 N/A; R42 checked; R43-R48 N/A; R49 fired (F16); R50-R56 N/A; R57 checked.

### Security expert
R1-R37 N/A; R38 fired (R4-F2); R39-R42 N/A; R43 checked (no `pq`-supplied value chooses a destination); R44-R48 N/A; R49 fired (R4-F1); R50-R57 N/A.
RS1-RS2 N/A; RS3 fired (R4-F3); RS4-RS6 N/A.

### Testing expert
R1-R28 N/A; R29 checked; R30-R39 N/A; R40 checked; R41 N/A; R42 checked; R43-R48 N/A; R49 fired (T18, T19); R50-R57 N/A.
RT1 fired lightly (T19); RT2 checked; RT3-RT4 N/A; RT5 fired (T18, T19); RT6 checked; RT7 fired (T18, T19); RT8 fired lightly (T18); RT9 fired (T18); RT10 checked; RT11 N/A.

## Plan review closed

Round 4 left no open Critical or Major finding. Every finding was re-checked by the expert who raised it, and C1–C7 are locked. Under the stopping rule (memory: risk-tiered-review) there is no further plan round. Minor wording is fixed during implementation, and the code is judged in Phase 3.
