# Plan Review: secureos-pq-vpn-architecture
Date: 2026-10-18
Review round: 1

## Changes from Previous Round
Initial review. Local LLM pre-screen raised one Major (audit rate limiting without a timer), fixed before Round 1.

## User decisions taken during Round 1
- S1 (escalated): aarch64 stays primary; no DMA isolation accepted as residual risk R2; drivers copy-only with Kani-proved bounds; x86_64 + VT-d recorded as SC10.
- F1: Microkit's MCS kernel accepted; AArch64 MCS proofs pending recorded as residual risk R1; MCS budgets used for availability (L13).

## Disposition
All Critical and Major findings are reflected in the plan (revision 2). Mapping:

| Finding(s) | Plan change |
|---|---|
| F1 | VE1, R1, L11 restated (single core, MCS as shipped) |
| S1, T11 | VE3, R2, per-PD consequence table, L7 (Kani harness for driver copy path), C5 |
| F2, S2 | L1 taint definition with conditional `key` exemption; L2 oracle requirements; C7 evaluates both |
| S3 | Per-PD consequence table; L12 zeroization; SC12 |
| F3, S5, T3 | C3 rewritten: free+used rings, read-once via `SharedAccess`, checked arithmetic, distance check, owner state, copy-in, RO consumer maps, mutation proof |
| F4, S11 | C4 `Frame` has `EthAddrs`; `total_len ≤ available`; ARP field checks; source address checks; C6 dst checks, swap reply, `echo` feature |
| F5, T1 | VE4 + C6 acceptance: raw frames over `-netdev dgram`, hostfwd smoke only |
| F6 | L5 keyed by physical page; SC1 placement decision |
| F7, T2, T10 | C8: emit on 1st and every 64th, `b` = overflow, concrete tests, flood bound K/64+2 |
| S4, T4 | C7: pinned roxmltree 0.19.0, DOCTYPE/entity rejection, attribute allowlist with defaults, denied elements, phys_addr/prefill rules, program_image resolution, exact-ID fixtures with allow pairs |
| S6 | L13 availability (priorities, MCS budgets, cookie gate before hs/pq) |
| S7 | L6: secrets in one `prefill_path` MR added by a separate packaging step; M5 parameter-encrypted TPM session |
| S8, T7, F9 | C1: base digest, apt snapshot, Kani/bolero pinned at image build, `--locked`, check-pins positive rules, from-clean incl. volumes, no `#![feature]` in ring/wire |
| S9, T8 | C2: bash pipefail, masking patterns, test-count manifest, `check-selftest` |
| T5, T6, T12, T13 | C4 acceptance: symbolic length + covers, shared `check()`, seed corpus, clippy lints replace grep, no cfg forks |
| T9 | Testing strategy: readiness lines, nonce, retries, process-group kill, free port |
| S10 | L8: `Option<Psk>` with age bound, replay role |
| S12 | R4 (debug putchar), L6 (peer list in image accepted), NET_ADMIN removed from docker/Makefile |
| F8 | C8 note + SC11 |

Quality warnings below (m3/S12, m6/T13, M18/T11) are artefacts of the orchestrator's condensed input to the merger; the experts' original reports contain the concrete fixes and evidence (plan text L7 vs Proof row). Not returned to experts.

# Merged Review Findings — Round 1

## Critical

### C1. Non-MCS configuration impossible on Microkit 2.3.1 AArch64
- **Flagged by:** Functionality (F1)
- **Problem:** L11 requires a non-MCS configuration, but all Microkit 2.3.1 board configs set `CONFIG_KERNEL_MCS=1` (confirmed in `gen_config.h` debug+release). AArch64 MCS proofs are not yet complete (roadmap Q3/27).
- **Impact:** The stated threat model assumption is unimplementable on the target platform; any non-MCS design work is blocked.
- **Recommended action:** Restate L11 as "single core + MCS as shipped"; add a residual risk / VE entry documenting the AArch64 MCS proof gap.

### C2. No ARM SMMU support in Microkit 2.3.1
- **Flagged by:** Security (S1)
- **Problem:** The `iomap` mechanism is x86-only. On AArch64, compromise of `eth_*` PDs yields permanent full compromise (no IOMMU to bound DMA). Line 76 of the design contradicts L7.
- **Impact:** The isolation guarantee for DMA-capable devices is absent on the primary target architecture.
- **Recommended action:** Correct L7/VE3 to move `eth_*` into the full-compromise class. (USER DECISION 2026-10-18: aarch64 primary, accept residual risk, copy-only proven drivers, keep x86 VT-d as possible second target.)

### C3. Hostfwd cannot inject ARP or malformed frames
- **Flagged by:** Functionality (F5), Testing (T1)
- **Problem:** The QEMU `hostfwd` backend only carries IPv4 datagrams; it cannot inject raw L2 frames (ARP, malformed, oversized). Drop-path tests are untestable.
- **Impact:** All frame-validation and drop-path logic is untestable in the current CI configuration.
- **Recommended action:** Add a raw-L2 backend (`-netdev dgram` unix or `socket` UDP) for frame injection; keep one `hostfwd`/`nc` smoke test; pin `ipv4=10.0.2.15` for the user-net.

### C4. Coalescing (1-per-64) makes serial assertions unreachable/vacuous
- **Flagged by:** Functionality (F7), Testing (T2)
- **Problem:** The current 1-per-64 coalescing policy hides low-volume events entirely, making serial assertion checks vacuous (they pass because no event is emitted, not because the logic is correct).
- **Impact:** Audit log completeness is unverifiable; overflow and unknown-code paths are silently dropped.
- **Recommended action:** Emit on the 1st and every 64th event; add an `audit_overflow` field; assert exact reason+total line counts; define flood bound as a concrete number.

### C5. Ring Kani harness must model fresh peer value per read (read-once semantics)
- **Flagged by:** Testing (T3)
- **Problem:** The current Kani harness for the ring does not model the shared-memory read-once property: a peer can change the value between the consumer's check and read.
- **Impact:** Kani proofs for the ring are vacuously satisfied; real double-fetch or stale-read bugs are not caught.
- **Recommended action:** Use a trait-based shmem accessor where the Kani impl returns `kani::any` per read and counts reads; fix N; prove the harness can go red (mutation test).

### C6. Laws mutation fixtures must assert exact law ID set
- **Flagged by:** Testing (T4)
- **Problem:** Current mutation fixtures do not assert the exact set of law IDs that should fire, nor that no parse error occurs. Allow/deny pairs and scenario-2 fixtures are missing.
- **Impact:** A law that is silently dropped or a new spurious law will not be caught by the mutation suite.
- **Recommended action:** Fixtures must assert exact law ID set + no parse error; include allow/deny pairs; add scenario-2 fixture.

## Major

### M1. Taint propagation rule undefined for key PD
- **Flagged by:** Functionality (F2)
- **Problem:** L1 literally forbids the key PD from holding secrets, but the key receives inputs from untrusted PDs. No taint propagation rule is defined for shared regions or channels.
- **Impact:** The confidentiality invariant is formally unenforceable; a tainted value can transit to key without detection.
- **Recommended action:** Define taint propagation over shared regions + channels; key is exempt only if inputs are PPC message registers (closed enum) and it shares no memory region with any PD.

### M2. L1/L2 contradiction: key consumes attacker-chosen points
- **Flagged by:** Security (S2)
- **Problem:** The key PD consumes attacker-chosen X25519 points and McEliece ciphertexts, contradicting L1's isolation intent. No typed oracle exemption exists.
- **Impact:** The key PD is an oracle for side-channel or fault-injection attacks; the stated security boundary is broken.
- **Recommended action:** Define a typed fixed-size PPC oracle exemption checked by C7; reject all-zero DH; enforce constant-time; add per-caller quota.

### M3. HS/data compromise understated; no zeroization law
- **Flagged by:** Security (S3)
- **Problem:** The design understates the consequence of `hs`/`data` PD compromise and provides no zeroization requirement.
- **Impact:** A compromise of the data PD leaks all live traffic; secrets persist in memory after use.
- **Recommended action:** Define per-PD compromise consequence explicitly; add L12 zeroization law; state that data compromise = all live traffic exposed.

### M4. C7 surface-form checking gaps (roxmltree, attributes, defaults)
- **Flagged by:** Security (S4)
- **Problem:** C7 relies on surface-form XML checking. Microkit uses `roxmltree 0.19.0` which supports DTD entities; dangerous attributes (`phys_addr`, `prefill_path`, `cspace` caps, child PDs, VMs, `smc`, `setvar`, `path_for_symbols`) are not allowlisted; defaults (`perms rw`, `priority 0`) are unchecked; `program_image` resolution is uncontrolled.
- **Impact:** A malicious or erroneous Microkit config XML can escalate privileges, map arbitrary physical addresses, or spawn child PDs outside the intended topology.
- **Recommended action:** Pin `roxmltree 0.19.0`; reject DOCTYPE/entities/duplicate attributes; implement per-attribute allowlist with explicit defaults; restrict `phys_addr` to driver device MRs only; deny `cspace`/child/vm/smc; prohibit `x` on shared maps; resolve `program_image` via same search path and record ELF hashes.

### M5. Ring/Pool double-fetch and memory safety issues
- **Flagged by:** Functionality (F3), Security (S5)
- **Problem:** The ring has no free/return path; ingress parses a driver-writable buffer in place (double-fetch UB with `&[u8]` over shared memory); `u32` overflow in bounds check; buffer ownership aliasing; tail back-channel.
- **Impact:** Undefined behaviour in the shared ring; potential information leak via tail value; out-of-bounds reads.
- **Recommended action:** Copy to private buffer before parse; use `checked_add`/`u64` for bounds; enforce `head - tail <= N`; add owner state; consumer RO maps enforced by C7; evaluate `sel4-shared-ring-buffer` (R1); N must be power of two; add ordering fences.

### M6. No availability law; PPC priority inverts intended ordering
- **Flagged by:** Security (S6)
- **Problem:** No availability/DoS law exists. PPC priority (callee > caller) means key outranks `hs`/`pq`; a decapsulation flood can starve legitimate traffic.
- **Impact:** An attacker can DoS the system by saturating the key PD with expensive operations.
- **Recommended action:** Define a priority-order law checked by C7; add per-caller quota in key; add cookie gate in ingress before `pq`; consider domain scheduler (MCS budgets/periods are available since MCS is accepted).

### M7. Secrets delivery contradicts L6 (memory initialisation)
- **Flagged by:** Security (S7)
- **Problem:** L6 states Microkit initialises memory only from ELF or `prefill_path`. The secrets delivery mechanism does not fit this model.
- **Impact:** Secrets may be visible in the initial image or in shared memory during the boot window.
- **Recommended action:** Use one `prefill_path` MR mapped only into key (enforced by C7); separate packaging step measured independently; M5 salted parameter-encrypted TPM session terminating in key.

### M8. C1 pinning gaps
- **Flagged by:** Security (S8)
- **Problem:** Base image digest, apt snapshot, toolchain manifest hash, persistent volumes, `cargo --locked`, forbidden patterns, and Kani setup are not all pinned.
- **Impact:** Build non-reproducibility; "from clean" guarantee is broken by persistent volumes or unpinned dependencies.
- **Recommended action:** Pin base image digest; snapshot apt; hash toolchain manifest; clear persistent volumes in C1; enforce `cargo --locked`; complete forbidden-pattern list; pin Kani setup.

### M9. C2 gate masking is incomplete
- **Flagged by:** Security (S9)
- **Problem:** Makefile gate checks do not catch all masking patterns: `.IGNORE`, `MAKEFLAGS -i/-k`, `|| :`, `; true`, `set +e`, and pipes without `pipefail` under `dash`.
- **Impact:** A step can fail silently while the gate reports success, allowing broken builds to ship.
- **Recommended action:** Set `SHELL := bash`; use `-euo pipefail`; forbid `.IGNORE`/`-i`/`-k` in gate scope; add fixtures that exercise each masking pattern.

### M10. Frame struct lacks MACs; IPv4 length check rejects padded min-frames
- **Flagged by:** Functionality (F4)
- **Problem:** The `Frame` struct does not include Ethernet src/dst MACs. The IPv4 total-length check uses equality, which rejects legitimately padded minimum-size frames.
- **Impact:** ARP and any MAC-dependent logic is impossible; valid frames are dropped.
- **Recommended action:** Add eth src/dst to `Frame`; change to `total_len <= available`; reply = swap src/dst; pin `ipv4 10.0.2.15`.

### M11. Virtio-mmio transports share 4 KiB pages
- **Flagged by:** Functionality (F6)
- **Problem:** Multiple virtio-mmio devices can map to the same 4 KiB physical page. Per-device ownership must be keyed by physical page, but this is not currently enforced.
- **Impact:** Cross-device aliasing can lead to information leak or corruption between PDs.
- **Recommended action:** Key per-device ownership by physical page; record M2 placement decision.

### M12. Wire Kani proofs incomplete
- **Flagged by:** Testing (T5)
- **Problem:** No Kani proofs exist for the wire layer. Symbolic length, coverage of all `Ok` variants and `DropReason` values, and round-trip properties are unverified.
- **Impact:** Wire parsing bugs (truncation, overflow, silent misparse) are uncaught by formal verification.
- **Recommended action:** Add Kani: symbolic length 0..=64; `kani::cover!` for each `Ok` variant and `DropReason`; bounded round-trip; one-field-mutation unit tests.

### M13. Bolero fuzzing not integrated
- **Flagged by:** Testing (T6)
- **Problem:** No bolero fuzzing target exists for the wire or ring layers.
- **Impact:** Fuzz-discoverable edge cases (malformed inputs, boundary conditions) are not exercised in CI.
- **Recommended action:** Create a plain `check(bytes)` function shared by Kani harness and bolero target; seed corpus; 30s in `make check`, longer in `make fuzz-long`; add to C2.

### M14. Kani and cargo-bolero not pinned in Docker
- **Flagged by:** Functionality (F9), Testing (T7)
- **Problem:** Kani version and toolchain are not pinned; `cargo kani setup` downloads at runtime. AArch64 support for Kani is unconfirmed. No `#![feature]` gates in ring/wire.
- **Impact:** Build non-reproducibility; Kani may fail or behave differently across runs; AArch64 CI is at risk.
- **Recommended action:** Pin Kani version and toolchain in Docker; pre-install Kani in image; confirm aarch64 support; add `#![feature]` declarations where needed.

### M15. Per-layer can-fail selftest missing
- **Flagged by:** Testing (T8)
- **Problem:** No selftest verifies that each test layer can actually fail (can-fail guard). Gates are piped, masking failures.
- **Impact:** A broken test harness silently passes, giving false confidence.
- **Recommended action:** Add per-layer can-fail selftest; add zero-harness/zero-test guard via manifest; unpipe gates.

### M16. QEMU test infrastructure not production-ready
- **Flagged by:** Testing (T9)
- **Problem:** No readiness line (poll until QEMU accepts connections), no retry logic, no nonce for test isolation, no process-group kill, no free-port selection.
- **Impact:** Flaky CI; port conflicts; zombie QEMU processes; tests interfere with each other.
- **Recommended action:** Add readiness poll; bounded retries; per-test nonce; `kill` process group; select free port dynamically.

### M17. C8 fixed-size test is vacuous
- **Flagged by:** Testing (T10)
- **Problem:** The C8 test only checks a single fixed-size input, making it vacuous. Coalescing, overflow, and unknown-code paths are untested.
- **Impact:** C8 provides no real assurance; regressions in edge-case handling are undetected.
- **Recommended action:** Test coalescing boundary, overflow, and unknown code paths with varied inputs.

### M18. L7 claims Kani enforcement with no driver harness
- **Flagged by:** Testing (T11)
- **Problem:** L7 states Kani enforcement for the driver, but no driver Kani harness exists in the repository.
- **Impact:** The stated verification coverage is not actually delivered; a gap between documentation and implementation.
- **Recommended action:** Either provide a driver Kani harness or restate L7 to reflect the actual verification scope.

## Minor

### m1. L8 current-PSK undefined; zero-PSK sentinel needed
- **Flagged by:** Security (S10)
- **Problem:** The "current PSK" concept is undefined for the first boot or after reboot. No sentinel for zero/no-PSK state. Replay of role across reboot is unaddressed.
- **Impact:** Undefined behaviour on first use or after reboot; potential replay attack.
- **Recommended action:** Use `Option<Psk>` with a zero-PSK sentinel (R55); add age bound to prevent replay across reboot.

### m2. Echo reflection and ARP/IP address validation
- **Flagged by:** Security (S11)
- **Problem:** The ingress echoes back malformed frames; no checks on broadcast/multicast/zero source addresses; no validation that dst equals own address; ARP fields unchecked.
- **Impact:** Information reflection to attacker; processing of bogus ARP entries.
- **Recommended action:** Drop broadcast/multicast/zero-src frames; require dst == own; validate ARP fields; put echo behind a feature flag.

### m3. Debug `putchar` bypasses L10; peer list in published image; unneeded `NET_ADMIN`
- **Flagged by:** Security (S12)
- **Problem:** Debug `putchar` output bypasses the L10 information-flow rule. The peer list is included in the published image. `NET_ADMIN` capability is granted but not needed.
- **Impact:** Information leak via debug channel; reduced attack surface.
- **Recommended action:** Gate `putchar` behind L10-compliant audit path; strip peer list from published image; remove `NET_ADMIN`.

### m4. Release config has no kernel printing
- **Flagged by:** Functionality (F8)
- **Problem:** The release configuration disables all kernel printing, making audit trail dependent on a UART driver PD that does not yet exist (M5).
- **Impact:** No audit output in production; forensics impossible.
- **Recommended action:** Implement UART driver PD (M5) as the audit channel.

### m5. Forbidden-pattern greps are blind
- **Flagged by:** Testing (T12)
- **Problem:** Current forbidden-pattern checks use naive grep, which is blind to obfuscated or reformatted patterns.
- **Impact:** Forbidden patterns can slip through in reformatted code.
- **Recommended action:** Prefer `clippy::indexing_slicing` deny + targeted fixtures over grep.

### m6. No `std`/`test` cfg forks in wire/ring non-test code
- **Flagged by:** Testing (T13)
- **Problem:** No `#[cfg(test)]` or `#[cfg(feature = "std")]` separation exists in the wire and ring non-test code.
- **Impact:** Test-only dependencies may leak into release builds; no way to conditionally compile test utilities.
- **Recommended action:** Add `cfg` gates to separate test utilities from release code in wire and ring crates.

---

## Recurring Issue Check

### Functionality expert
| Code | Status | Linked Finding |
|------|--------|----------------|
| R1 | Flagged | F3 (→ M5) |
| R29 | Flagged | F1, F5 (→ C1, C3) |
| R41 | Flagged | F5 (→ C3) |
| R42 | Flagged | F2 (→ M1) |
| R49 | Flagged | F1 (→ C1) |
| R53 | Flagged | F7 (→ C4) |
| others | N/A or checked-ok | — |

### Security expert
| Code | Status | Linked Finding |
|------|--------|----------------|
| R16 | Flagged | S8 (→ M8) |
| R29 | Flagged | S1 (→ C2) |
| R38 | Flagged | S10 (→ m1) |
| R39 | Flagged | S3 (→ M3) |
| R41 | Flagged | S7 (→ M7) |
| R42 | Flagged | S4 (→ M4) |
| R44 | Flagged | S9 (→ M9) |
| R47 | Flagged | S4 (→ M4) |
| R48 | Flagged | S4 (→ M4) |
| R49 | Flagged | S5 (→ M5) |
| R51 | Flagged | S4 (→ M4) |
| R55 | Flagged | S10 (→ m1) |
| RS1 | Flagged | S2 (→ M2) |
| RS2 | Flagged | S6 (→ M6) |
| RS3 | Flagged | S11 (→ m2) |
| RS4 | Flagged | S12 (→ m3) |
| others | N/A or checked-ok | — |

### Testing expert
| Code | Status | Linked Finding |
|------|--------|----------------|
| R12 | Flagged | T5 (→ M12) |
| R16 | Flagged | T7 (→ M14) |
| R40 | Flagged | T1 (→ C3) |
| R41 | Flagged | T11 (→ M18) |
| R44 | Flagged | T8 (→ M15) |
| R47 | Flagged | T12 (→ m5) |
| R48 | Flagged | T6 (→ M13) |
| R49 | Flagged | T11 (→ M18) |
| R50 | Flagged | T8 (→ M15) |
| R53 | Flagged | T2 (→ C4) |
| RT1 | Flagged | T3 (→ C5) |
| RT4 | Flagged | T3 (→ C5) |
| RT5 | Flagged | T1 (→ C3) |
| RT7 | Flagged | T4 (→ C6) |
| RT8 | Flagged | T2 (→ C4) |
| RT9 | Flagged | T13 (→ m6) |
| RT10 | Flagged | T4 (→ C6) |
| RT11 | Flagged | T9 (→ M16) |
| others | N/A or OK | — |

---

## Quality Warnings

| Finding | Flag | Detail |
|---------|------|--------|
| m3 (S12) | [VAGUE] | Identifies three issues (debug putchar, peer list, NET_ADMIN) but provides no concrete fix for any of them. Recommend the expert specify: (a) the exact audit-path gate for putchar, (b) the build step to strip peer list, (c) the capability removal in the seccomp/capability spec. |
| m6 (T13) | [VAGUE] | No file/line reference and no concrete fix. States an absence ("no cfg forks") without specifying which modules need gating or what the `cfg` boundary should be. |
| M18 (T11) | [NO-EVIDENCE] | Claims "no driver harness exists" without providing a `grep` output, file listing, or path that demonstrates the absence. Recommend the expert provide evidence (e.g., `find . -path '*driver*kani*'` returns empty) or the specific path where a harness would be expected. |

## Recurring Issue Check
### Functionality expert
R1 F3 · R2 N/A · R3 checked-ok · R4 checked-ok · R5–R11 N/A · R12 checked-ok · R13–R15 N/A · R16 checked-ok · R17–R28 N/A · R29 F1,F5 · R30 N/A · R31 N/A · R32 checked-ok · R33–R35 N/A · R36 checked-ok · R37–R39 N/A · R40 checked-ok · R41 F5 · R42 F2 · R43 N/A · R44 checked-ok · R45 N/A · R46 N/A · R47 checked-ok · R48 N/A · R49 F1 · R50 checked-ok · R51 checked-ok · R52 N/A · R53 F7 · R54–R57 N/A

### Security expert
R1 N/A · R2 N/A · R3 checked-ok · R4–R11 N/A · R12 checked-ok · R13–R15 N/A · R16 S8 · R17–R28 N/A · R29 S1 · R30–R31 N/A · R32 checked-ok · R33–R37 N/A · R38 S10 · R39 S3 · R40 checked-ok · R41 S7 · R42 S4 · R43 N/A · R44 S9 · R45 N/A · R46 N/A · R47 S4 · R48 S4 · R49 S5 · R50 checked-ok · R51 S4 · R52–R54 N/A · R55 S10 · R56 N/A · R57 N/A · RS1 S2 · RS2 S6 · RS3 S11 · RS4 S12 · RS5 N/A · RS6 N/A

### Testing expert
R1 N/A · R2 OK · R3–R11 N/A · R12 T5 · R13–R15 N/A · R16 T7 · R17–R28 N/A · R29 OK · R30 N/A · R31 N/A · R32 OK · R33 N/A · R34 N/A · R35 OK · R36 OK · R37–R39 N/A · R40 T1 · R41 T11 · R42 N/A · R43 N/A · R44 T8 · R45 N/A · R46 N/A · R47 T12 · R48 T6 · R49 T11 · R50 T8 · R51 OK · R52 N/A · R53 T2 · R54–R57 N/A · RT1 T3 · RT2 OK · RT3 N/A · RT4 T3 · RT5 T1 · RT6 OK · RT7 T4 · RT8 T2 · RT9 T13 · RT10 T4 · RT11 T9

---

# Round 2
Date: 2026-10-18

## Changes from Previous Round
Plan revision 2 applied all Round 1 Critical/Major findings (disposition table above). All three experts confirmed Round 1 fixes resolved. New findings are law-wording precision issues; no Critical.

## Findings and disposition (all reflected in plan revision 3)

| ID | Expert | Sev | Label | Finding | Plan change |
|---|---|---|---|---|---|
| F10 | Func | Major | design | C7 denied `setvar region_paddr`, the only way a driver learns its DMA paddr | C7: `setvar` allowed only `region_paddr`, driver PD, own DMA MR; fixture pair |
| F11 | Func | Major | design | `sel4-shared-ring-buffer` needs `#![feature(core_intrinsics)]`; internal index reads defeat `SharedAccess` model | C3: own ring, reason recorded (R1) |
| F12 / S13 | Func+Sec | Major | design | L13 "budgets present" vacuous under Microkit defaults (budget = period); `key` not passive | L13: explicit `budget < period`, per-PD and sum ratio caps, `key` passive; fixture |
| F13 | Func | Minor | prose | C7 number parsing must match Microkit (`0x`, `_`) | C7 line + M0 allow fixture |
| S14 | Sec | Major | design | `audit` is A3-driven yet trusted/unbudgeted; 65 536 unknown codes flood | PD table, L13 budget, C8 drain/notify limits, single unknown-code counter |
| S15 | Sec | Major | design | prefill secrets packaging breaks reproducibility and escapes C7 | L6: zero placeholder, re-run C7, diff confined to MR range, masked hash, blob path check |
| S16 | Sec | Minor | design | `key` exemption: pp direction, notify default, message size not visible to C7 | L1 wording, C7 attribute list; message size → M2 `key` contract; quota count-based |
| S17 | Sec | Minor | prose | M5 TPM path vs L1/L2 | L6 note: PPC-only TPM↔key exception |
| T14 | Test | Major | design | Unsatisfiable `kani::cover!` does not fail by default | C2: `--fail-uncoverable` or wrapper; selftest case |
| T15 | Test | Major | design | selftest accepts wrong-reason failures; manifest omits layers | C2: hard-error injection, named failure, single layer, extended manifest, delete-one-test |
| T16 | Test | Major | design | flood bound upper-only; arrival non-deterministic | C8 acceptance: ≥1 and ≤ bound, a ≡ 1 mod 64, a+b ≤ K, liveness echo |
| T17 | Test | Minor | design | DropReason completeness not compiler-enforced | C4: exhaustive `index()` + per-reason frame `match` (already implemented in `crates/wire`) |
| T18 | Test | Minor | prose | dgram and hostfwd cannot share one NIC | C6: hostfwd smoke as separate boot |

## Recurring Issue Check
### Functionality expert
R1 F11 · R18 F10 · R41 F10 · R48 F13 · R49 F12 · all others ok or N/A
### Security expert
R41 S15 · R42 S16 · R48 S13 · R51 S16 · RS1 S16,S17 · RS2 S13,S14 · all others checked-ok or N/A
### Testing expert
R44 T15 · R50 T15 · R53 T16 · RT5 T18 · RT8 T14,T16 · RT9 T17 · Round 1 items resolved · all others OK or N/A

---

# Round 3
Date: 2026-10-18

## Changes from Previous Round
Plan revision 3 applied all Round 2 findings. All experts confirmed Round 2 fixes. Functionality expert verified empirically with Microkit 2.3.1: passive `key` + PPC from budgeted lower-priority PD builds; `0x`/`_` numbers parse; three images differing only in a 4 KiB `prefill_path` blob differ in exactly one contiguous 4096-byte range and identical inputs build byte-identical images (L6 packaging design holds).

| ID | Expert | Sev | Label | Finding | Plan/code change |
|---|---|---|---|---|---|
| S18 | Sec | Major | design | DMA MR not required to be driver-exclusive; shared mapping would give `ingress` arbitrary DMA | C7: DMA MR mapped only into its driver, never a C3 data region; fixture pair |
| S19 / N1 | Sec+Func | Minor | prose | C7 L13 bullet stale; missing fixtures | C7 bullet + fixtures for passive/ratio/sum |
| S20 | Sec | Minor | design | Packaged image output path unchecked | L6: same path check for packaged output |
| N2 | Func | Minor | prose | `--fail-uncoverable` may need `-Z unstable-options` | C2 wording; checked at image build |
| T19 | Test | Minor | design | `ALL` membership and Kani covers not enforced | Code: `drop_reasons!` macro generates enum + `ALL`; Kani covers via exhaustive match; doc fixed |
| T20 | Test | Minor | design | Packaging diff check passes on empty diff | SC2 acceptance requirements |
| note | Test | — | prose | M0 allow fixture policy | C7: own minimal policy file |

## Recurring Issue Check
### Functionality expert
R49 N1 · R50 N2 · others ok or N/A
### Security expert
R41 S20 · R48 S19 · RS1 S18 · RS2 S19 · others checked-ok or N/A
### Testing expert
RT5 T20 · RT9 T19 · others OK or N/A

---

# Round 4
Date: 2026-10-18

## Changes from Previous Round
Plan revision 4 applied all Round 3 findings; `crates/wire` updated for T19. Deviation: Round 4 was a verification-only pass run by one sub-agent covering the three expert scopes in turn (not three parallel agents), chosen for speed per the user's fast-cycle directive; the three full parallel reviews ran in Rounds 1–3.

| ID | Expert | Sev | Label | Finding | Change |
|---|---|---|---|---|---|
| S21 | Sec | Minor | prose | L5 text did not cover DMA MR exclusivity that the S18 fixture attributes to `{L5}` | L5 text extended |

Functionality: No findings. Testing: No findings.

## Saturation call (Round 4)
- ≥ 2 rounds completed: yes (4).
- Open Critical/Major in any category: none.
- Findings against the design: none in Round 4.
- Remaining Minor: none (S21 fixed).
Plan phase complete; all contracts C1–C8 locked. No Carried-Forward Plan Findings.
