# Code Review: secureos-m2-5-cookies-keepalive
Date: 2026-10-19
Review round: 1

## Changes from Previous Round
Initial review of `feature/m2-wireguard...458d791`, with fresh reviewers. The
local LLM pre-screen and seeds (Step 3-2) were skipped, so every reviewer did
a full-diff review. The merge was done by hand.

## Merged findings
| ID | Expert | Severity | Subject |
|---|---|---|---|
| S1 | Sec | Major | ARP replies bypass the TX reserve, so half the TX ring is not guaranteed to hs/data |
| T1 | Test | Major | Flood step-2 retry budget assumes a constant survival; a chance failure reads as a data-path regression |
| F1 | Func | Minor | Stale wg-core noise.rs doc: "cookies not implemented" |
| F2 | Func | Minor | data PD input loops are unbounded ahead of keepalives (same shape fixed in ingress), so R3 propagates |
| F3 | Func (adj.) | Minor | `PassActions.flush` has no consumer |
| T2 | Test | Minor | integration-cookie needle shared with a generic message; detector possibly never red |
| T3 | Test | Minor | Step-1 suppression check blind to up to 63 coalesced events |
| T4 | Test | Minor | Band checks run after behavioural assertions (misattribution) |
| T5 | Test | Minor | Paired deny oracle races audit print latency |
| T6 | Test | Minor | Tautological ring Kani assertion |
| T7 | Test | Minor | data-core test relies on a backwards clock |
| T8 | Test | Minor | ROTATE_AT and NET_BUFFERS-equality asserts lack selftest cases |

Security verdicts on the deviation log's open items:
- **TX handshake reservation:** not needed, once S1 is fixed.
- **M3 branch 2:** sound.
- **PD `from_*` via `drain`:** verified.

## Raw expert outputs
# Functionality expert — Code review Round 1
No Critical/Major. Verified: WP §5.4.7 construction; Gate C3; C5; PD loop; C7; write/read consistency; harness; checklist.
F1 Minor (R29): wg-core noise.rs:6-7 doc says cookies not implemented.
F2 Minor question (R3): data PD input loops unbounded (pds/data main.rs:138,180) ahead of keepalives(); C7 timing and tick depend on notified() returning. Fix: measure, or bound at NET_BUFFERS per pass with keepalives each pass (shared helper).
F3 Minor [Adjacent] (R41): PassActions.flush has no consumer; tests pin dead behaviour; Wake no-notify untested.

# Security expert — Code review Round 1
Verified clean: CookieSecret validity flag; mac16 + ct_eq; zero-mac2 skip; no crypto on Missing/Expired; nonce (AEAD key public, binding to mac1 only); RNDR pacing; drain-based loops; ring reclaim-then-count; never-coalesced edge rates; timer channel exemption; C5 bounds; keepalive on current only; cookie reply destinations pass ipv4_is_valid_src.
S1 Major (R3, RS5): ARP replies bypass the TX reserve (ingress-core lib.rs:111, 130-151; PD ArpReplied arm sends unconditionally) — attacker-paced, cheaper than cookie path; under ingress saturation ARP flood can fill TX to 0 and drop hs responses / data output. Fix: pass tx_free to ARP path; ArpReplied only if tx_free > TX_RESERVE else Outcome::ArpSuppressed (coalesced audit); boundary tests (exactly half refused, +1 replied); allow side existing ARP tests; keep ARP replies; Kani (e) extended to ArpReplied; separate red-proofs (comparison removed; > → >=). Optional: ignore ARP not from router_mac (spoofable; auxiliary).
Verdicts: TX handshake reservation not needed (conditional on S1 fix); M3 branch 2 sound; PD from_* via drain verified.
RIC: R3 S1; R29 ok; R42 ok; R43 ok; R17/R47 ok; RS1 ok (libcrux internal state residue known, rotated secret worthless); RS2-RS4 ok; RS5 S1; others N/A.

# Testing expert — Code review Round 1
Verified: counts vs manifest, oracle outputs vs pinned constants, selftest anchors/needles, wireguard-go budget math, Kani harness symbolic starts.
T1 Major (R49,R50,R53): step-2 retry budget constant (s2=0.5/3 every run; run.py:1531-1534,1592); "measured" claim false; no runtime check of >=1/6; chance failure prints same as starved data path. Fix: measure s2m after step 2 (rate 0, ARP barrier, cookie_totals), distinct Fail when s2m < s2; red-prove both messages separately; reword log.
T2 Minor (RT7) question: integration-cookie needle is prefix shared with generic 'no cookie reply'; detector "without mac2 ... got a handshake response" maybe never seen red. Fix: pin needle and make reachable, or record what it proves.
T3 Minor: boot b step-1 no-new-WgCookieSuppressed blind to up to 63 suppressions; print blind window; log paired fresh-boot check authoritative.
T4 Minor: band checks after behavioural assertions misattribute harness shortfall; check lower band first on Fail and chain.
T5 Minor: paired deny oracle races audit latency; require WgMac2Accepted line time after A's first allow send.
T6 Minor (RT7): ring Kani sender_in_flight_stays_within_pool asserts tautology (proofs.rs:216); assert n <= sent; red-prove.
T7 Minor: data-core test relies on backwards clock (tests.rs:604-621); reorder times.
T8 Minor (RT7): ROTATE_AT<MAX_AGE (ingress-core lib.rs:302) and NET_BUFFERS equality asserts (hs-core tests.rs:24, pds/ingress main.rs:35) lack messages and selftest cases.

## Recurring Issue Check (round 1, non-N/A)
- **Functionality:**
  - R3: F2.
  - R29: F1. Figures verified: 243 ≤ 255, codes, `FIXED_SLOTS`, channel ids, needles.
  - R41: F3.
  - Checked: R4, R12, R40, R42, R13, R38, R39, R17, R1.
  - Others N/A.
- **Security:**
  - R3: S1.
  - Checked: R29, R42, R43, R17, R47.
  - RS1: residue is known; a rotated secret is worthless.
  - RS2–RS4: OK.
  - RS5: S1.
  - Others N/A.
- **Testing:**
  - R2/RT3: OK.
  - R29: checked (T1 wording).
  - R42, R44: OK.
  - R49, R50, R53: T1 (R50 also T2).
  - RT1: OK.
  - RT5: resolved.
  - RT6: OK.
  - RT7: T2, T6, T8.
  - RT8, RT9, RT10, RT11: OK.
  - Others N/A.

## Environment Verification Report
- **VE1–VE7** (M2) and **VE8** (tap and AF_PACKET in the netns):
  verified-local by `make check` (exit 0) on 458d791. `INTEGRATION-CASES 11`,
  per-run C 975/s and 1081/s.
- **M3 measurement:** verified-local on a throwaway copy; command and
  figures are in the deviation log.
- **No `blocked-deferred` paths.**

## Resolution Status
### Round 1
- **S1 [Major]:** the ARP path takes `tx_free` and replies only if
  `tx_free > TX_RESERVE`; otherwise it returns `Outcome::ArpSuppressed`
  (coalesced audit 0x003c).
  - Tests pin the boundary: exactly half is refused, half + 1 is answered.
  - Kani invariant (e) covers `ArpReplied`, with a cover for
    `ArpSuppressed`.
  - Red-proved on throwaway copies.
  - Files: `crates/ingress-core/src/lib.rs`, `crates/pds/ingress/src/main.rs`,
    `crates/audit-event`.
- **T1 [Major]:** step 2 measures survival `s2m` after a drain barrier and
  raises a distinct "not judged" Fail when `s2m` is below the budget's
  assumption. Both messages are red-proved. Latest run: `s2m` 0.442
  against an assumed 0.167. File: `tests/integration/run.py`.
- **F1:** `noise.rs` doc corrected.
- **F2:** shared `ring::pass` (`run_passes`, `drain`, `any_full`), with the
  pass orders in ingress-core and data-core.
  - data's inputs are bounded, and keepalives run every pass.
  - Orchestrator follow-up: session expiry also runs every pass.
  - Selftest cases `unbounded-drain` and `late-notify` target
    `ring/src/pass.rs`.
- **F3:** `PassActions`/`pass_plan` removed; `continue` is now
  `ring::pass::any_full`.
- **T2:** the recorded injected run fired the specific detector. The needle
  is pinned to "cookie attribution failed: an initiation without mac2 under
  load got a handshake response".
- **T3:** the blind window is printed before step 1, and the paired
  fresh-boot `total=1` check is stated as authoritative.
- **T4:** `check_low_band_first` attributes harness shortfalls.
- **T5:** the `WgMac2Accepted` line must follow port A's first allow send.
- **T6:** the ring harness asserts `n <= usize::from(sent == Ok(true))`.
  Red-proved: an over-count mutant fails it.
- **T7:** data-core test times reordered; no session seals before its
  install.
- **T8:** messages added; selftest cases `rotate-before-max-age` and
  `net-buffers-equal` red-proved.
- **Verification:** `make check` exit 0 alone (C 943/s, step-2 measured
  survival 0.442).

# Review round: 2
Round 2 reviewed `458d791..7a86aef` with the same reviewers, as an
incremental review.
- **Functionality:** F1–F3 resolved. New: R2-F1 [Minor], a stale data
  `notified` doc.
- **Security:** S1 verified correct and complete.
  - Every unauthenticated reply (ARP, cookie) respects the TX reserve.
    Keeping hs responses and data outbound outside it is intended.
  - R43: no widening. ARP suppression gives the same proportional service
    as before, and hs/data now keep half of TX.
  - No new DoS levers in the data loop.
  - New: S2 [Minor], the same stale doc as R2-F1.
- **Testing:** T1–T4 and T6–T8 resolved, and the selftest renames
  verified. New: R2-T5 [Minor], the T5 fix was nearly vacuous.

### Resolution (round 2)
- **R2-F1 / S2:** doc reworded in `crates/pds/data/src/main.rs`, and the
  deviation log's stale sentence marked as superseded.
- **R2-T5:** in `tests/integration/run.py`:
  - deny is conclusive only for the reply to B's latest initiation
    (`opens_for`);
  - a 1 s settle (`DENY_SETTLE_S`) runs before the `WgMac2Accepted` count;
  - the time check is kept.
- **Verification:** `make check` exit 0 alone.

# Review round: 3
Round 3 reviewed `7a86aef..ac3e2ba`, an incremental diff touching docs and
the test harness only.
- **Functionality:** No findings. R2-F1 resolved, and the R2-T5 change is
  sound.
- **Security:** No findings. S2 resolved, and R43 shows no widening.
- **Testing:** No findings.
  - R2-T5 resolved.
  - The "not red-proved" justification is accepted: reaching the count
    needs a gateway that accepts only B's first initiation plus a forced
    audit delay, and even then the settle would not be isolated.

## Termination
All three experts returned "No findings" in Round 3. Code review is
complete after 3 rounds; every finding from Rounds 1–2 is resolved, and
`make check` passed alone on `ac3e2ba`.

# Post-review: external review of 3750758..3fca70f
- **Minor: the C5 inequalities existed only in test builds.** Moved into
  hs-core's library, so the production `pd-hs` build rejects unsafe
  constants (red-proved).
- **Known Minor: a keepalive was consumed on seal, not delivery.** Debt is
  now restored on a failed send and retried on a later pass (red-proved).
- **Record inconsistency:** the date is corrected to 2026-10-19.

Details are in the deviation log ("External review after code review").
- **Verified state:** these fixes were committed as `62e26b7`, and
  `make check` passed alone on it (exit 0, `INTEGRATION-CASES 11`). A
  follow-up external review of `62e26b7` found no further findings. Its two
  precision notes are recorded in the deviation log.
