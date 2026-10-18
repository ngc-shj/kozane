# Code Review: secureos-pq-vpn-architecture
Date: 2026-10-18
Review round: 1

## Changes from Previous Round
Initial review of `main...HEAD` (fe17f4f, M0+M1). Local LLM pre-screen and seeds unavailable (server down); all three experts reviewed the full diff.

## Seed Finding Disposition
Seed unavailable — no dispositions to record (all three experts).

## Functionality Findings
F1 [Major] C6 echo not behind cargo feature `echo` — ingress-core/src/lib.rs:65, Cargo.toml (R41)
F2 [Major] eth_out uses blocking virtio send (add_notify_wait_pop, unbounded spin) in notification handler — pds/eth-out/src/main.rs:145. Fix: transmit_begin/poll, QUEUE_SIZE in flight, TxNoBuffer when full.
F3 [Major] L4: IRQs not described/owned in policy — tools/laws/src/check.rs:46, sdf.rs:282 (dup of Sec F1 IRQ part)
F4 [Major] C7 phys_addr vs board RAM overlap not implemented — check.rs:288, policy (relates Sec F2)
F5 [Minor] unknown attrs on memory_region/end/channel → parse error not L4; contradictory comment; <system> attrs unchecked — sdf.rs:319,371,139
F6 [Minor] page_size default differs from Microkit — sdf.rs:125
F7 [Minor] link: Full not sticky, buffer leaked (give before push) — ring/src/link.rs:79,115
F8 [Minor] eth_out may miss rx IRQ during init — eth-out/src/main.rs:86
F9 [Minor] layout tests skip channel IDs / IRQ — layout
F10 [Minor] L2 allows several key-role PDs to map secrets — policy.rs:161
Recurring: R2 F9, R29 F5/F9, R41 F1, R48 F6; others OK/N/A.

## Security Findings
F1 [Major] laws gate ignores channel pp/notify and IRQ numbers (L4 fail-open); pp=true on ingress end lets ingress PPC into eth_out (default `protected` panics) — tools/laws/src/check.rs:46, sdf.rs:282/381, policy schema. Fix: per-end pp/notify in [[channels]] (Microkit defaults applied), irqs=[...] per driver; fixtures.
F2 [Minor] device MR phys_addr/size not pinned in policy — check.rs:262. Fix: phys_addr+size in policy device MRs, mismatch = L5.
F3 [Minor] ratio_cap=nan passes validation, disables L13 ratio checks — policy.rs:256/259. Fix: !(x>0 && x<=1); fixture.
F4 [Minor] echo reflection/loop: sport==7 loop, ARP reply to a.sha not eth.src, own IP / 127/8 accepted as source — ingress-core/src/lib.rs:55,65-75; wire/src/lib.rs:123.
Recurring: R3 F1, R18 F1, R42 F2, R49 F1, RS3 F3; others OK/N/A.

## Testing Findings
T1 [Major] check-pins P5 misses `|| :` (end of line) and `+-` recipe prefix — tools/check-pins:94,96
T2 [Major] laws L3/L13-priority and other branches have no deny fixture; `if false` mutation stays green — tools/laws/src/check.rs:384,439
T3 [Major] stale build/counts satisfy manifest for a gate that did not run — Makefile:127, tools/check-manifest
T4 [Major] kani cache path never exercised by selftest (build/ skipped) — tools/check-selftest:20
T5 [Minor] kani verification failure hides harness name (log redirected) — Makefile:93
T6 [Minor] selftest layer set not enforced — tools/check-selftest:101
T7 [Minor] integration: echo header checks, flood margin, free-port race — tests/integration/run.py
T8 [Minor] proofs: pool NotWithPeer not proved; link read-once counters; eth_out closure abstracted — ring/src/proofs.rs:116
T9 [Minor] bolero corpus load and audit unknown-code print unasserted
Adjacent: eth-out recycle_rx_buffer result discarded.
EVR: C1 from-clean docker build not evidenced.

## Adjacent Findings
- (Testing) eth_out discarded the `recycle_rx_buffer` result — moot after the driver rewrite (Func F2): rx completion errors now mark the device dead.
- Functionality F3/F4 and Security F1/F2 overlap (IRQ and device-range coverage in C7) — merged and fixed together.

## Quality Warnings
None (merge done manually; Ollama unavailable).

## Recurring Issue Check
### Functionality expert
R2 F9 · R29 F5,F9 · R41 F1 · R48 F6 · all other R1–R57 OK or N/A (full list in the expert output).
### Security expert
R3 F1 · R18 F1 · R42 F2 · R49 F1 · RS3 F3 · all other R1–R57/RS1–RS6 OK or N/A.
### Testing expert
R44/R50 T3,T5 · R47 T1 · R57 boundaries T2 · RT1 T8 · RT7 T4 · RT8 T2 · RT10 OK (allow neighbours added) · others OK.

## Environment Verification Report
| Contract | Path | Status |
|---|---|---|
| C1 | pinned image build incl. SDK `.asc` hash | verified-local (`make -C docker build`, 2026-10-18) |
| C1 | check-pins fixtures | verified-local (`make pins`, CHECK-PINS-FIXTURES 20) |
| C2 | `make check`, manifest, `check-selftest` | verified-local (see Resolution Status) |
| C3 | Kani N ∈ {1,4,256}, mutation evidence | verified-local (deviation log C3 evidence; `make kani`) |
| C4 | Kani covers incl. round-trip, bolero with seed corpus | verified-local (`make kani`, `make bolero`) |
| C5/C6 | QEMU raw frames, exact flood totals, hostfwd smoke | verified-local (`make test`, INTEGRATION-CASES 3) |
| C7 | exact-set fixtures + 22 mutation proofs | verified-local (`cargo test -p laws`: 17 + 70) |
| C8 | unit + integration | verified-local |
| C5/C7 | DMA isolation, real hardware | blocked-deferred — VE3, VE5 (plan); accepted residual R2 |
| L11 | MCS kernel proofs | blocked-deferred — VE1; residual R1 |
| — | root of trust | blocked-deferred — VE2 (M5) |

## Resolution Status
### Func F1 [Major] echo not behind cargo feature
- Action: `ingress-core` feature `echo` (off by default); `pd-ingress` forwards it; Makefile builds the M1 image with it; unit tests run with and without it; Kani runs with it.
- Modified: crates/ingress-core/{Cargo.toml,src/lib.rs,src/tests.rs}, crates/pds/ingress/Cargo.toml, Makefile
### Func F2 [Major] blocking virtio send in the notification handler
- Action: eth_out rewritten on `VirtIONetRaw`: rx/tx submitted and reaped asynchronously, unknown tokens or failed completions mark the device dead (fail-closed), backpressure via the ring when all tx buffers are in flight. Also fixes Func F8 (service() at the end of init) and the Adjacent recycle finding.
- Modified: crates/pds/eth-out/src/main.rs
- Alternatives searched: keeping `VirtIONet` with `can_send()` checks — rejected, `send` still spins until completion.
### Func F3/F4, Sec F1/F2/F3, Func F5/F6/F10, Test T2 [Major/Minor] laws checker coverage
- Action: per-end pp/notify and per-driver irqs in policy (L4), duplicate IRQ (L5), device phys_addr/size pinned (L5), `[board] ram` overlap (L5), NaN-safe ratio caps, unknown attributes on memory_region/end/channel/system → L4, Microkit page_size default, single key PD / single secrets mapper (L2); 39 new exact-set fixtures with allow neighbours; 22 mutation proofs on a throwaway copy.
- Modified: tools/laws/src/{policy,sdf,check}.rs, tools/laws/tests/**, policy/laws.toml
### Sec F4 [Minor] echo reflection / ARP aiming
- Action: no reply to sport == echo port; own-IP sources and ARP sha ≠ eth.src → new `Spoofed` outcome/audit event; 127/8 rejected by `wire`; ARP reply addressed to eth.src.
- Modified: crates/wire/src/{lib,tests}.rs, crates/ingress-core/src/{lib,tests}.rs, crates/audit-event/src/*, crates/pds/ingress/src/main.rs
### Func F7 [Minor] link Full not sticky / buffer leak
- Action: `Sender`/`Receiver` carry a sticky `dead` flag set on any ring failure; test with a peer that stalls its read index.
- Modified: crates/ring/src/{link,tests}.rs
### Func F9 [Minor] layout tests skip channel ids / IRQ
- Action: `ETH_OUT_IRQ` in layout; tests assert every channel id pair and the IRQ against the .system.
- Modified: crates/layout/src/{lib,tests}.rs
### Test T1 [Major] check-pins misses `|| :` and `+-`
- Action: regexes fixed; fixtures for `|| :`, `||:`, `+-` and an allow case.
- Modified: tools/check-pins, tests/tools/test_check_pins.py
### Test T3 [Major] stale count files
- Action: `make check` runs `clean-counts` first; selftest case `stale-counts`.
- Modified: Makefile, tools/check-selftest
### Test T4 [Major] kani cache never exercised
- Action: selftest copies the real proof cache before injecting; new `kani-cache` case edits a path dependency (wire) and requires ingress-core to be re-proved, not served from cache.
- Modified: tools/check-selftest
### Test T5 [Minor] kani failure hides harness name
- Action: kani target prints its log on failure.
### Test T6 [Minor] selftest layer set not enforced
- Action: `EXPECTED_LAYERS` must equal the case set.
### Test T7 [Minor] integration weak spots
- Action: flood paced by echo round trips (exact totals 65..641, lost 0); echo checks MACs, IPs and ports; boots retried on early QEMU exit (port race).
### Test T8 [Minor] proof/model gaps
- Action: `pool_accept_stays_in_region` uses arbitrary per-buffer ownership and asserts accept ⇔ well-formed ∧ with-peer; link proofs assert read-once. The eth_out device-length closure stays abstracted in the link proof (the closure only slices with `get`).
### Test T9 [Minor] bolero corpus / unknown-code print
- Action: bolero gate requires a non-empty corpus load; `audit_event::decode` (+ tests) drives pd-audit's formatting.

### Round 1 verification (2026-10-18)
- `make check` green: CHECK-PINS-RULES 5, CHECK-PINS-FIXTURES 20, LINT-CRATES 6, UNIT-TESTS 175, KANI-HARNESSES 13, BOLERO-TARGETS 1, LAWS-SYSTEMS 1, INTEGRATION-CASES 3; manifest floors raised to match.
- `tools/check-selftest`: all 10 layers detect their injection (unit, kani, kani-cache, bolero, stale-counts, lint, laws, pins, integration, manifest). Allow side of kani-cache: the unmodified tree reports `cached pass`.
- Side fix: the round-trip harness called `parse_frame` twice after adding covers and CBMC itself failed (not a property violation); restructured to parse once and emit into a 64-byte buffer — wire proofs now 10 min instead of 40.
- Integration with the non-blocking driver: flood totals exactly 65..641, lost 0.

---

# Round 2
Date: 2026-10-18

## Changes from Previous Round
Reviewed `fe17f4f..f4e7e81`. All Round 1 findings confirmed resolved by their originating experts (Func F1–F10, Sec F1–F4; Testing T1/T2 continuing, rest resolved or narrowed). No Critical or Major from Functionality or Security; Testing kept two Majors open (T1, T2).

| ID | Expert | Sev | Status | Finding | Resolution |
|---|---|---|---|---|---|
| S5 | Sec | Minor | new | `[board] ram = []` disables the RAM-overlap check | empty list is a policy error; unit test |
| S6 / N2 | Sec+Func | Minor | new | oversize device rx length dropped silently | used length beyond the buffer → `device_broke()`; frame > NET_BUF_SIZE → `FrameTooLong` audit |
| S7 | Sec | Minor | new | own MAC as eth.src not Spoofed | `eth.src == our MAC` → Spoofed in ARP and UDP; test |
| N1 | Func | Minor | new | unbounded rx loop delays ingress notification | ≤ QUEUE_SIZE completions per call |
| N3 | Func | Minor | new | dead device reported as RingCorrupt | new `DeviceFault` event |
| N4 | Func | Minor | new | echo build not linted | `make lint` also runs clippy with `--features echo` |
| T1 | Test | Major | continuing | P5 misses whitespace before `@-` and `(cmd \|\| true)` | `^\t[\s@+]*-` (not on continuation lines), `\|\|\s*(true\|:)(?![\w-])`; fixtures for both |
| T2 | Test | Major | continuing | bundled fixtures hide single check sites | one fixture per site (`<system>`, `<memory_region>`, `<channel>`, `<end>` unknown attrs; `cspace`, `virtual_machine`, `smc`); each shown red by removing its site on a throwaway copy (`/tmp/lm`): all 7 FAILED under mutation |
| T3 | Test | Minor | continuing | `check` could drop clean-counts unnoticed | selftest asserts `check` runs clean-counts first |
| T4 | Test | Minor | continuing | kani-cache could pass vacuously | selftest requires the uninjected copy to hit the cache first |
| T6 | Test | Minor | continuing | layer list compared with itself | selftest derives gates from the Makefile `check` recipe |
| T7 | Test | Minor | continuing | echo checksum/length; boot retry hides crashes | IPv4 checksum + UDP length asserted; retry only on port-in-use |
| T8 | Test | Minor | continuing | pool proof frame condition | other buffers unchanged on Ok, all unchanged on Err |
| T8b | Test | Minor | new | round-trip harness diverged from `check` | shared `check_into` used by bolero and Kani |
| T9 | Test | Minor | continuing | decode boundaries | upper FrameDropped edge and first code after fixed range tested |
| T10 | Test | Minor | new (Adjacent) | tx backpressure never exercised | integration `burst_echo`: 40 back-to-back echoes (> 16 tx buffers), all replies required |

Side fix during Round 2: the tightened P5 prefix regex initially flagged backslash-continued recipe lines (`\t\t-Z ...`); make honours `-` only at the start of a logical line, so continuation lines are exempt. (Caught by running check-pins on the real tree; an earlier `| tail -1` had hidden the failure — gates are now read by exit status.)

## Recurring Issue Check
### Functionality expert
R57 N2 · all others OK or N/A
### Security expert
R43 checked (no widening; namespaced attributes ignored identically by laws and the Microkit tool) · RS3 S5 · R29 S6 · others OK or N/A
### Testing expert
R47 T1 · R57 T9 · RT1 T8/T8b · RT7 T4/T6 · RT8 T2 · R44/R50 T3 · others OK or N/A

### Round 2 verification (2026-10-18)
`make check` green (CHECK-PINS-FIXTURES 22, UNIT-TESTS 185, KANI-HARNESSES 13, INTEGRATION-CASES 3, others unchanged); manifest floors raised. `tools/check-selftest`: all 10 layers pass, gate list derived from the Makefile, clean-counts ordering asserted, kani-cache allow side checked before injection.

---

# Round 3
Date: 2026-10-18

## Changes from Previous Round
Reviewed `f4e7e81..cea39df`. All Round 2 findings confirmed resolved (S5–S7, N1–N4, T1–T10; T2 mutation evidence reproduced independently). All new findings are Minor; none Critical/Major.

| ID | Expert | Sev | Finding | Resolution |
|---|---|---|---|---|
| N-S8 | Sec | Minor (R43, fix-induced) | continuation exemption used `rstrip().endswith("\\")`; trailing space or even backslashes hid a real `-` prefix (reproduced with GNU make 4.4.1) | lines grouped into logical lines with make's rule (odd count of trailing backslashes, nothing after); prefix checked on the first physical line only; fixtures for both bypasses plus a true-continuation allow case |
| N-S9 | Sec | Minor | masked-exit check per physical line (`\|\| \` + `true`); `\|\| exit 0` missing | checked on joined logical lines; `exit 0` added; fixtures |
| N5 | Func | Minor | bounded rx loop + RING_EVENT_IDX: a non-delivering batch could strand completions without an interrupt | `service` loops while `pump_rx` reports it stopped at the bound, notifying ingress per batch |
| T11 | Test | Minor | `check_gates` read only `$(MAKE)` lines | reads `check:` prerequisites; any non-`$(MAKE)` recipe line is an error |
| T12 | Test | Minor | burst_echo not shown to exercise backpressure | mutation on a throwaway copy (`/tmp/txm`): dropping frames when no tx buffer is idle makes the raw-frames case FAIL ("no reply") |
| T13 | Test | Minor | continuation exemption had no allow fixture | covered by the N-S8 allow case |
| T14 | Test | Minor | kani-cache pre-check crashed if the log was absent | guarded; prints make output on failure |

### Round 3 verification
`make check` green (CHECK-PINS-FIXTURES 27, UNIT-TESTS 185, KANI-HARNESSES 13, INTEGRATION-CASES 3); manifest floor raised. `tools/check-selftest`: 10/10 layers.

## Recurring Issue Check
### Functionality expert
R29 N5 · others OK
### Security expert
R43 N-S8 · RS3 N-S9 · others OK
### Testing expert
R47 T13 · RT7 T11/T12 · RT3 T14 · others OK
