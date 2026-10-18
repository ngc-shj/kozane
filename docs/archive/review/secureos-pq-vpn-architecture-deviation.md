# Coding Deviation Log: secureos-pq-vpn-architecture

Iteration 1 (M0 + M1). Each entry: what differs from the locked plan, why, and impact.

## D1 — C1: base image is Debian trixie, not bookworm
Kani 0.68 release binaries require glibc ≥ 2.39 (bookworm has 2.36). Base is
`debian:trixie@sha256:913f…c2d5` with apt pinned to snapshot `20261015T000000Z`.
Snapshot is fetched over plain http because `ca-certificates` is not yet installed at
that step; apt verifies Release signatures with the archive keyring. No contract impact.

## D2 — C1: PD toolchain baked into the image; no rustup volume
A persistent rustup volume masked the image's toolchain (Kani's bundle became invisible)
and contradicted the "from clean" acceptance. The toolchain is installed in the image
(`ARG PD_TOOLCHAIN`, kept equal to `rust-toolchain.toml` by check-pins P4). The cargo
registry cache volume was renamed (`secureos-cargo-registry`); the old volumes
`secureos-rustup` / `secureos-cargo` are unused and were not deleted (a local hook blocks
volume deletion; left to the user).

## D3 — C2: Kani has no `--fail-uncoverable`; wrapper used
Kani 0.68 rejects the flag. `tools/kani-gate.sh` fails unless every
`** M of N cover properties satisfied` line has M == N and ≥ 1 harness verified. This is
the plan's stated fallback.

## D4 — C2: Kani results cached by input hash
`wire` proofs take ~40 min. `tools/kani-gate.sh` caches a pass under `build/kani-cache/`
keyed by the hash of all crate sources, Cargo.lock, toolchain files, Kani version, the
script and its arguments. Any change re-runs the proof; `check-selftest` injects into
crate sources, so injected failures are never served from cache.

## D5 — C3: `ring` is generic over the slot type
Plan C3 specified rings of `Desc`. Audit records (C8) travel over the same ring, so
`SharedAccess<T>` / `Producer<A, T, N>` / `Consumer<A, T, N>` are generic; the read-once
proofs are instantiated for `Desc`. Slot types must be valid for every bit pattern
(documented on the trait).

## D6 — C3/C5/C6: shared `ring::link` module
Sender/Receiver logic (reclaim, ownership, copy-in, return-before-parse) is shared by
`eth_out` and `ingress` instead of being written twice. Kani harnesses for the driver
copy path (L7, C5) prove `link::Receiver::recv_into` and `link::Sender::send_with`
stay inside the data region for arbitrary peer-written indices and descriptors.

## D7 — Crate structure not named in the plan
`layout` (sizes and channel ids shared by PDs and the .system), `audit-event` (C8 schema
+ coalescer), `ingress-core` (C6 decision logic, host-testable and Kani-proved). PDs
are thin wrappers.

## D8 — C6/C8: two extra outcome/audit codes
`NotForUs` (valid frame for another host) and `NoService` (for us, no handler) are
distinct audit events so the integration test can tell them apart from parser drops.

## D9 — C2: PDs are built with one cargo invocation each
Building all PDs in one invocation unified features: `sel4-microkit/alloc` (needed only
by `eth_out` for virtio-drivers) forced a global allocator on `ingress` and `audit`.
Separate invocations keep those PDs heap-free.

## D10 — C7: decisions taken by the implementation
- DOCTYPE, entities and duplicate attributes are parse errors (exit 2), not law IDs.
- `x` permission on any MR mapped by ≥ 2 PDs is reported as L4.
- Budget ratio caps are single global values in `[budgets]` applied to every tainted PD.
- A `data`-kind MR may be produced by any role; consumers must map it read-only.
- `policy/laws.toml` describes the M1 system (not only `hello`); the M0 hello system is a
  frozen allow fixture with its own policy.

## D11 — C4: bolero corpus location
bolero names the corpus directory after the test path without the `fuzz_` prefix
(`__fuzz__/tests__parse_never_panics_and_round_trips/`). Only `seed-*` files are
committed; generated corpus and crash directories are git-ignored.

## D12 — VE4: integration test details
PDs print ready lines in scheduler order (`ingress`, `audit`, `eth_out`); the harness
accepts any order. During the 640-frame flood the budget-limited `ingress` falls behind
and `eth_out` drops with `RxNoBuffer` (counted and audited) — expected under L13.

## C3 acceptance evidence — proofs fail when a guard is removed (2026-10-18)
Run on throwaway copies in the container (`/tmp/mut*`), never on the real tree:
- Removing `len > BUF` from `Pool::accept` → `pool_accept_stays_in_region` FAILED
  (`start + d.len <= region_len`).
- Removing the consumer distance check → initially still SUCCESSFUL with the
  `Corrupt` cover unsatisfied (caught only by kani-gate's cover rule). The harnesses
  were strengthened to assert directly that a peer index implying more than `N`
  slots yields `Err(Corrupt)`; re-run → FAILED.
- Removing the index mask in `slot()` → `consumer_n4` FAILED (slot index out of range).

## Step 2-5 self R-check — dispositions
All Major findings fixed in Phase 2:
- R38 audit stall: `Coalescer::record` returns "offered"; producers notify on every
  offer (incl. a full ring); `audit` drains up to one ring's worth per notification.
- R29/R2 .system vs layout: `crates/layout` tests parse `system/secureos.system` and
  assert data-region, ring and DMA sizes; `ETH_OUT_DMA_SIZE` / `ETH_OUT_MMIO_OFFSET`
  moved into `layout`.
- R42/R2 audit names: `Event::FIXED`, `name()`, `from_fixed_code()` in `audit-event`
  with round-trip tests; `pd-audit` no longer has its own table. Unknown-code
  accounting moved to `audit_event::UnknownCodes` with a unit test (C8).
- RT1 Kani model bound: `Adversary<N>` bounds slots by `N` (was 256); the real
  `ShmRing::slot_ptr` now hard-asserts `i < N` (fail-closed) instead of `debug_assert`.
- C4 round-trip harness: covers for accepted ARP and non-empty UDP added.
- RS3/R47 check-pins: P1 requires the hash check to name the downloaded file; any
  `curl`/`wget` invocation (any argument order), `ADD <url>` and `git clone` are covered;
  the Microkit SDK `.asc` is now hash-pinned too (found by the tightened rule).
- R44/R50 kani-gate: `inherit_errexit`, source-dir list computed as a checked step
  (empty → error), `.cargo/config.toml` in the key, harness name on unsatisfied covers.
- RS3 laws policy: `deny_unknown_fields` on every policy struct (typo → parse error).
- R55 DMA paddr sentinel: `eth_out` asserts its region symbols are non-zero; laws
  requires the owner's `setvar region_paddr` for every policy-declared DMA MR (L5).
Minor, fixed: `--locked` resolution via `cargo metadata --locked` before bolero/kani;
LINT-CRATES counted from cargo JSON; R36 unused-const suppression removed; selftest
needles name the injected item; local crash files excluded from selftest copies.
Minor, accepted: `CHECK-PINS-RULES` and `LAWS-SYSTEMS` are fixed counts (the rule set
and the single system file); laws fixtures are counted in UNIT-TESTS. The MAC / echo
port / QEMU command appear in Python, Rust and the Makefile (cross-language, low risk).
Kani cover-summary absence on a future Kani upgrade is guarded only by check-selftest.

## C2 acceptance evidence — `make check` and `make check-selftest` (2026-10-18)
`make check` green: CHECK-PINS-RULES 5, CHECK-PINS-FIXTURES 16, LINT-CRATES 6,
UNIT-TESTS 110, KANI-HARNESSES 13, BOLERO-TARGETS 1, LAWS-SYSTEMS 1,
INTEGRATION-CASES 3 (all ≥ tests/manifest.txt).
`tools/check-selftest`: every layer fails on its injection and names it —
unit (selftest_injected_failure), kani (selftest_unsatisfiable_cover), bolero
(selftest-bolero-injected), lint (indexing), laws (L4), pins (P5), integration
(bad echo), manifest (UNIT-TESTS).
