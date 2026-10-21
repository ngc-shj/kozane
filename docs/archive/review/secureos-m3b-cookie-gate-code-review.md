# Code Review: secureos-m3b-cookie-gate
Date: 2026-10-21
Review round: 2 (complete)
Branch: feature/m3b-cookie-gate, `3d54604..07eeea6` (C1–C5 landed before this review; this review covers the Kani, C6, C7 and selftest slices and the final state)

## Changes from Previous Round
Round 1 was an external read-only review of the uncommitted Kani/C6/C7 work on top of `3d54604`. Round 2 re-reviewed `3d54604..8c2ab7e` after the fixes. Per the risk-tiered process, only the reviewer who raised a Critical/Major re-checked it, and mutations replaced re-review where a finding was a missing deny side.

## Round 1 Findings
- **M1 [Major] Load clears under a sustained low-rate spoof.** With trigger 4 removed, load cleared 60 s into a spoof of one address at one per 20 s, which the per-source meter never refuses; `pq` got up to 16.1 s of work per 20 s. The rationale on `RP_UNDER_LOAD_AFTER_NS` was false for that code. Required: a > 60 s test at 1/20 s, a bound on unauthenticated `pq` work after clearance, an R6/SC26 residual, ideally a one-shot legacy probe that re-arms.
- **M2 [Major] The C6 floods did not fail closed.** `RpSpoof` counted ENOBUFS as sent, swallowed thread errors, and was never checked at the judgment point; global drain passed with RespHellos at spoofed addresses as long as one CookieReply existed; the plan's "`RpInitHello` rises only by the client" check was missing.
- **M3 [Major] No red-proof of the full-RAM scan itself.** The expiry mutation ran only `unit`.
- **B1 [Blocker] The count manifest was stale,** and the new `RP-COOKIE-TWIN-FIXTURES` count was absent, so `make check` could not pass.
- **N1 [Medium] Cookie attribution did not bind the RespHello to the InitHello** (no sidi match).

## Round 1 Resolution
| ID | Resolution | Evidence |
|---|---|---|
| M1 | Legacy probe: the first uncookied forward within `RP_LEGACY_PROBE_NS` after a clearance re-arms load, in `rp_forward_hello` (`ce50e3f`). R6 gains residuals (6) and (7) | Unit test at 1/20 s for 10 min plus two window-edge tests; Kani assertion in `rp_forward_spends_its_own_meters_once`; selftest `rp-legacy-probe` red |
| M2 | `RpSpoof` counts delivered datagrams and `verify()` fails on error, stop, or < 90 % delivery at each judgment point; RespHellos to spoofed sources bounded by the clearances (`38a8193`) | Integration 32/32 |
| M3 | Selftest `integration-expiry-residue`: the expiry tick leaves the entry `Live`; the scan fails with `expired OSK still in guest RAM` | Selftest red |
| B1 | Manifest raised to measured counts, two new keys (`8c2ab7e`) | `make check` rc=0 at `8c2ab7e` |
| N1 | Attribution requires the RespHello's sidi to equal the cookied InitHello's | Integration 32/32 |

Found during the fixes: selftest `rp-sid-binding` and `integration-rp-src-meter` were not red under their mutations; both tests were corrected (deviation log, "Selftest slice").

## Round 2
No Critical or Major. One Minor: the probe is not sticky, so "at any rate" (code comment) and "once a load has happened" (R6 (6)) overstated it; R6's heading should name rekey starvation. Fixed in `07eeea6`. The reviewer agreed with the legacy-probe design and set the SC26 close conditions: the solo `make check` at `8c2ab7e` passes (it did), the Minor is fixed, and the pins/package waiver checks are rerun on the final state (`make pins` rc=0; selftest `pins`, `package-release`, `package-waiver`, `package-waiver-removed` red as expected).

## Outcome
SC26 closed in `policy/waivers.toml` (`07eeea6`). Review closed with no open Critical/Major.
