# Plan Review: kozane-m9-kvm-client

## Round 1

Date: 2026-11-03
Review round: 1

### Changes from Previous Round

Initial review. Before it, local-LLM pre-screening raised one Minor
finding: `PSK_LIFETIME` had no single source. It was folded into C8.
Round 1 then superseded it with `wg_core::REJECT_AFTER_TIME_NS`.

Round 1 rewrote the plan. These are the contract-level changes:

- **New contracts and probes:**
  - C14, the timer on the ARM generic timer;
  - C15, Kozane's own Microkit SDK (GICv3);
  - probes P9–P13.
- **New decisions:**
  - D9, the own SDK;
  - D10, libvirt out of M9 (SC51);
  - D11, existing cases keep upstream (SC52);
  - D12, the client in its own workspace.
- **Decisions rewritten:** D1/H2 (firmware pin, P11 H-CRTM probe), D2
  (stock QEMU, GICv3), D6 (privilege split, remove-and-re-add scrub, acks),
  and I7.1 (OSK at RespHello, as upstream).
- **Testing:** an injection/needle table and a manifest wiring list.

### Merged findings and dispositions

Convergent findings (reported by two or more experts) are merged, and the
severity floor is Major (Perspective Convergence). Every disposition below
is "reflected in the plan" unless it says otherwise.

| ID(s) | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| F1.1 | Critical | design | `gic-version=3` pinned; the SDK kernels are GICv2-only. Verified on gx10: KVM logs `disabling GICv2 emulation` | D9, C15, P9; C1 kernel-config asserts GICv3 |
| F1.2 | Critical | design | The image depends on the sp804-patched QEMU; stock `virt-9.0` lacks it | D2 stock QEMU; C14 generic timer; P12; I14.1 pin |
| S1.1 | Major | design | An unmeasured EL1 first stage can forge PCR 8; H2 overstated | H2/C2/C5 restated; C4 launcher firmware pin (I4.2); P11 host H-CRTM probe; RM9-1 |
| S1.2 | Major | design | Guest RAM reaches host storage (managed save, core dump, swap) | `mem-lock=on` and `dump-guest-core=off` in `vm.machine`; host.md rules |
| S1.3, F1.7, T1.5 | Major | design | The libvirt equality is infeasible or ungated; swtpm encryption ungated | D10 (libvirt → SC51); `vm.swtpm` renders `--key`; I4.1 runs the launcher; the release boot asserts encrypted state |
| S1.4 | Major | design | `mon:stdio` monitor inherited by the launcher; I1.2's list incomplete | `-monitor none`, non-mux serial, `-display none`; I1.2 extended; the harness adds QMP outside `machine` |
| S1.5 | Major | design | `fstat` cannot see a symlink; keygen write path unspecified | C10 `O_NOFOLLOW`/`openat`/`O_EXCL`/`fchmod`/`fsync`; I10.1 |
| S1.6 | Major | design | CAP_NET_ADMIN acquisition unspecified; setcap privesc; the parser holds the cap | D6: `kzc-psk` helper over a socketpair, systemd unit, no setcap, euid owner |
| S1.7 | Major | design | Netlink acks unchecked; getrandom failure; REPLACE_PEERS; buffer not wiped | D6/I10.3: `NLM_F_ACK`, fatal on error, no zeros, wipe, no REPLACE_PEERS |
| S1.8, F1.15, T1.11 | Major | design | No startup scrub; the I8.1 boundary and allow side untested | I8.1: `Client::new` returns `Scrub` first; boundary tests ±1 tick; deadline reset; red-proofs |
| S1.9 | Major | design | Gateway key provenance and enrollment identity undefined | C13 enrollment and Config steps; the node prints its digests; out-of-band confirmation |
| S1.10 | Major | design | Co-resident guests missing | A19, host.md dedicated host, RM9-6 |
| S1.11, F1.20 | Major (convergent) | design | A scrub does not end live WireGuard keypairs (+180 s) | D6: remove-and-re-add drops the keypairs; I8.1 restated |
| S1.12, F1.19 | Major (convergent) | design | Two sources for the PSK window | C7/C8 use `wg_core::REJECT_AFTER_TIME_NS` |
| S1.13, F1.11, T1.9 | Major (convergent) | design | `catch_unwind` inert under the root `panic = "abort"` | D12: own workspace with `panic = "unwind"`; a shipped-profile panic test |
| S1.14 | Minor | design | FFI secret lifecycle incomplete | C9 caller-wipe rule; boxed `Secret`; fixed wiped slots |
| S1.15, F1.9 | Major (convergent) | design | I7.1's EmptyData timing contradicts upstream and `written_at` | I7.1: OSK at RespHello, as upstream |
| F1.3, T1.18 | Major | design | C3 misses the mixed outcome; fallbacks forbidden or inert; untested | C3 outcome table with events and needles; the launcher watchdog for the halt case; P4 (i)/(ii) |
| F1.4 | Major | design | P24 contradicts C2 | C12 rewrites P24, with needles and fixture updates |
| F1.5, T1.20 | Major | design | The C2 member-set grep misses members and returns noise | `git grep -lIiE` over the tree; dispositions logged before lock |
| F1.6 | Major | design | `vm.machine(accel)` cannot serve the harness | Full `machine(...)` and `swtpm(...)` signatures; fixed vs per-run listed |
| F1.8, T1.1 | Major | design | `kzc`'s kernel WG vs the harness's wireguard-go/`key_out`; member set misses observers | D11 (existing cases keep upstream); C11 new `kzc` cases read the PSK with `wg show`; P10, VE25; mksecrets emits a `kzc` config |
| F1.10, T1.6 | Major | design | No initiator vectors; regeneration churns the existing ones | `rp-vectors --initiator` into new files; existing hashes pinned |
| F1.12 | Major | design | C9's ABI inputs and buffer/queue rules missing | C9 `cfg`/`keys` layout, constants, `KZ_ERR_BUFFER`/`KZ_ERR_BUSY` |
| F1.13 | Major | design | The sans-IO core has no RNG source; duplicate rng | D5/C8: entropy bytes per call into a DRBG; one RNG via `Seams` |
| F1.14 | Major | design | The clock is unspecified; MONOTONIC stops in suspend | D5/C8: a clock that counts suspend (`CLOCK_BOOTTIME`) |
| F1.16 | Major | design | Enrollment lacks `wg_pub`; netlink needs IFNAME and family lookup; ambiguous peer key | C8 `gw_wg_pub`; C10 keygen emits `wg_pub`; config `interface`; D6 family lookup |
| F1.17, T1.2 | Major | design | A KVM line in `tests/manifest.txt` breaks the TCG `make check`; outside the self-test | `tests/manifest-kvm.txt`; `kvm` partition in `selftest-split`; `check-selftest` learns `test-kvm` |
| F1.18 | Major | design | D8 lacks `--group-add` | D8 spelled out |
| T1.3 | Major | design | `test-kvm` does not prove KVM ran | `query-kvm` asserted in every case; `-accel tcg` red-proof |
| T1.4 | Major | design | The launcher is an untested twin | I4.1 executes the launcher under stubs; the release boot goes through `kozane-vm` |
| T1.7 | Major | design | Kani on rosenpass-core unprobed; I7.2/I7.3 lack tests | `initiator_state` pure core; P13; residue cases; deny/allow pairs |
| T1.8 | Major | design | Several lock changes, several 13 h re-proofs | D12: client crates in their own workspace; the root lock unchanged |
| T1.10, F1.24 | Major (convergent) | design | The `nm` header gate is blind to signatures | cbindgen-generated header compared byte for byte; `-Werror` C harness |
| T1.12 | Major | design | I10.1 deny-only; axes uncovered; other-owner untestable | C10 allow/deny matrix; VE26 |
| T1.13 | Major | design | Red-proofs are deny tests, not mutations; valgrind unproven | The injection table; `--error-exitcode=1`, no suppressions |
| T1.14 | Major | design | TPM-startup refusal coverage lost | C2 keeps a `fail_nth` CC_STARTUP case with a red-proof |
| T1.15 | Major | design | The repro firmware red-proof is removed with no replacement | `repro-uboot` injection; the SDK repro injection |
| T1.16 | Major | design | No injection table or wiring list | Added |
| T1.17 | Major | design | The oracle count is a source-text count | A runtime equality line counted by the manifest |
| F1.21, T1.19 | Major (convergent) | design | The PCR 0 deny U-Boot variant duplicates `TpmProxy` | `TpmProxy` injection generalised to PCR 0 |
| F1.22, T1.25 | Major (convergent) | design | The keygen digest helper; the identity test | `secret_blob::blake2s`; an independent Python blake2s check |
| F1.23 | Minor | prose | The EL1 difference is SDK metadata, not `.system` | P1 records `platform_gen.json` and related values |
| F1.25 | Minor | design | The upstream responder must be configured responder-only | D4: no endpoint for the `kzc` peer |
| F1.26 | Minor | prose | `wg_peer` and a duplicate `rng` in `Initiator::new` | Removed |
| T1.21 | Minor | design | Bolero cannot reach later states | Deterministic prefix; seeded corpus |
| T1.22 | Minor | design | iperf3 is not runnable | Added to the image; netns topology; dropped if infeasible, recorded |
| T1.23 | Minor | design | P8's host unspecified | The slowest qemu-partition host |
| T1.24 | Minor | prose | Missing VE entries | VE25, VE26; libvirt is gone (D10); the restart policy is tested by stub (C3) |
| T1.26 | Minor | design | `run.py` anchors checked only at the end | Affected self-test cases in C11's slice gate |
| T1.27 | Minor | design | Upstream constants not gated | Fixture pinned to upstream file and line |

### Verified by the orchestrator

- gx10's boot log has `kvm [1]: disabling GICv2 emulation` and
  `GICv3: no GICV resource entry`, so F1.1 holds. It also has `nv: … trap
  handlers`, so nested support is compiled in (VE22).
- The SDK EL1 `gen_config.h` has `CONFIG_ARM_GIC_V3_SUPPORT` disabled,
  `EXPORT_PTMR_USER` and `EXPORT_PCNT_USER` on, and `EXPORT_VTMR_USER`
  off.
- `system/kozane.system:16-17` maps the sp804 at `0x90d0000`.
  `docker/Dockerfile` applies the coliasgroup sp804 patch to QEMU 9.0.0.
- The z1mn container runs LinuxKit 6.12.76. Kernel WireGuard is not yet
  probed (P10).

### Owner-visible narrowings

- D10: the libvirt domain leaves M9 (SC51).
- D11: existing cases keep upstream rosenpass (SC52).
- D9/C15: Kozane builds its own SDK. This is required by F1.1, and widens
  M9.

### Recurring Issue Check

#### Functionality expert
- R1: F1.21, F1.22
- R2: F1.19
- R3: F1.4
- R4–R9: N/A (no event bus, DB or UI)
- R10: Checked, no issue (client → rosenpass-core is one-way)
- R11: N/A
- R12: Checked, no issue
- R13–R15: N/A
- R16: F1.2, F1.17, F1.18
- R17: F1.6
- R18: F1.6
- R19: N/A
- R20: Checked, no issue
- R21: N/A (plan stage)
- R22: F1.8
- R23–R24: N/A
- R25: F1.8
- R26: N/A
- R27: Checked, no issue
- R28: N/A
- R29: F1.1, F1.2, F1.3, F1.9, F1.10, F1.16, F1.23. P4's HVC claim verified by dumpdtb; `virt-9.0` and `CASE_TIMEOUT_S` verified.
- R30–R31: Checked, no issue
- R32: Checked, no issue
- R33: F1.17
- R34–R37: Checked, no issue
- R38: F1.3, F1.15
- R39: Checked, no issue
- R40: F1.6, F1.12
- R41: F1.1, F1.3, F1.7, F1.8, F1.10, F1.11, F1.13
- R42: F1.4, F1.5, F1.8
- R43: N/A
- R44–R45: Checked, no issue
- R46: N/A
- R47: Checked, no issue
- R48: F1.19
- R49: F1.20, F1.24
- R50: F1.1
- R51: Checked, no issue
- R52: F1.4
- R53–R54: N/A
- R55: Checked, no issue
- R56–R57: N/A

#### Security expert
- R1: N/A
- R2: S1.12
- R3: S1.3
- R4–R28: N/A
- R29: Checked. The seL4 quote is accurate. S1.15 is the upstream divergence.
- R30: Checked, no issue
- R31: N/A
- R32: Checked
- R33–R34: N/A
- R35: Checked
- R36–R37: N/A
- R38: Checked (I7.3)
- R39: S1.14
- R40: Checked
- R41: S1.3
- R42: Checked
- R43: N/A
- R44: S1.7
- R45–R46: N/A
- R47: S1.4
- R48: Checked (the unmeasured adjudicator is S1.1)
- R49: S1.1, S1.2, S1.7, S1.8, S1.11, S1.13
- R50: S1.3
- R51: S1.5
- R52: Checked
- R53–R57: N/A
- RS1: Checked (shared `crypto`)
- RS2: N/A
- RS3: Checked; S1.5, S1.7
- RS4: Checked, no issue
- RS5: S1.9
- RS6: N/A

#### Testing expert
- R1–R2: N/A
- R3: T1.1
- R4–R15: N/A
- R16: T1.1, T1.5
- R17–R28: N/A
- R29: T1.6
- R30–R31: N/A
- R32: T1.4 (partial)
- R33–R34: N/A
- R35: T1.5
- R36: T1.13
- R37–R40: N/A
- R41: T1.1, T1.5
- R42: T1.16, T1.20
- R43: N/A
- R44: Checked (gates run unpiped under pipefail)
- R45–R46: N/A
- R47: T1.17
- R48–R49: N/A
- R50: T1.3, T1.9
- R51–R52: N/A
- R53: T1.23
- R54–R57: N/A
- RT1: T1.1, T1.9, T1.25
- RT2: T1.6, T1.7, T1.18, T1.21
- RT3: Checked
- RT4: N/A
- RT5: T1.1 (partial)
- RT6: T1.16
- RT7: T1.2, T1.3, T1.10, T1.13, T1.14, T1.15, T1.17, T1.26
- RT8: T1.7
- RT9: T1.1, T1.4, T1.10, T1.27
- RT10: T1.11, T1.12
- RT11: Checked (netns state dies with the namespace)

## Round 2

Date: 2026-11-03
Review round: 2

### Changes from Previous Round

The plan was rewritten again.

- **Withdrawn:** P11, the host H-CRTM (D1).
- **Added:** D13, timer ownership as a code property.
- **Contracts and checks:**
  - C3's table drops QMP from the launcher and adds a heartbeat watchdog;
  - C4 adds the sealed-memfd firmware pin, `pin-firmware`, and the
    provisioning flow;
  - the swtpm ctrl socket is unix-only;
  - the client draws OS entropy itself (D5);
  - `kzc-psk` becomes the unit's main process and owns its interface
    (D6, D7);
  - the endpoints are split;
  - `test-kzc` gets its own manifest;
  - the `kvm` partition takes the proof lock;
  - image-identity checks;
  - P14 (memlock);
  - the injection table is expanded.

### Merged findings and dispositions

| ID(s) | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| S2.2, F2.4 | Critical (convergent) | design | The generic-timer EL0 export reaches every PD; L5 ownership and the L1 timer exemption are lost | D13: a binary timer-register scan of every PD ELF except `timer`, plus laws' no-executable-MR rule; A20; RM9-8; P12 records `CNTKCTL_EL1`; laws exemption made non-vacuous |
| S2.1 | Major | design | The firmware pin has no update path or writer constraint | C4: `pin-firmware` verifies the manifest signature; root-owned 0600 pin; I4.3 |
| S2.3 | Major | design | swtpm socket access means a full unseal | `vm.swtpm`: unix ctrl only, mode 0600, data over ctrl, no TCP; I1.2 |
| S2.4, F2.2, T2.1 | Major (convergent) | design | Launcher QMP contradicts C1 and S1.4 | P11 withdrawn; no QMP in the launcher; the watchdog reads a serial heartbeat; the `kozane-vm` KVM proof by `/proc/<pid>/fd` |
| F2.3, T2.9 | Major (convergent) | design | P11 breaks unseal on in-guest reset; needs a harness twin | P11 withdrawn (D1) |
| S2.5, F2.8 | Major (convergent) | design | The privilege split cannot be built; key ownership; a user config steers the capability holder | D6: `kzc-psk` is the main process and forks `kzc` with all caps cleared; root-owned settings; owns only an interface it creates; D7 paths; I10.4 |
| S2.6 | Major | design | Caller entropy is the only randomness | D5: OS RNG inside the core via `getrandom`; failure is an error |
| S2.7, T2.13 (part) | Major (convergent) | design | Client lock outside the gates | D12: audit-gate, clippy, shared-crate lock pin; `make client` |
| F2.1 | Major | design | `mem-lock=on` fails under the 8 MiB memlock limit | D8 `--ulimit memlock=-1`; P14; host.md `LimitMEMLOCK` |
| F2.5 | Major | design | C14 has no member set | C14 member set; `TIMER_FREQ_HZ`; laws fixtures |
| F2.6 | Major | design | QEMU may be an SDK build input; amd64 parity | D9/P9 record and pin every input; both arches |
| F2.7 | Major | design | One endpoint for Rosenpass and WireGuard | Split into `rp_*`/`wg_*`; Config holds only `rp_endpoint` |
| F2.9 | Major | design | The harness HMP monitor was omitted | C1 harness-only additions list it |
| F2.10 | Major | design | No encrypted-state or pin provisioning flow | C4 provisioning: `swtpm_setup --keyfile`, harness `Swtpm` with the key |
| F2.11, T2.5 | Major (convergent) | design | The VE25 fallback makes counts host-dependent | `test-kzc` with its own manifest and partition |
| T2.2 | Major | design | Needles not failure-only | Every needle is failure-path text; separate I8.1 needles |
| T2.3 | Major | design | SDK repro is not checkable in-container | VE27, `tools/sdk-repro` host-side, gx10 vs z1mn |
| T2.4 | Major | design | No image/QEMU identity; I14.1 can pass on patched QEMU | Counts record the image digest and QEMU id; merge requires one; I14.1 precondition (no sp804 node) |
| T2.6 | Major | design | The `kvm` partition can run beside Kani | It takes the qemu and proof locks; exclusion fixture |
| T2.7 | Major | design | Remove-and-re-add is untested | Ping fails right after the scrub with the gateway reachable; PSK-only injection |
| T2.8 | Major | design | The watchdog stub tests the wrong mode | Two branches: a real halt image and a stub exit |
| T2.10 | Major | design | mksecrets is a twin of `keygen` | Keys from `kzc keygen`; mksecrets writes the config only |
| T2.11 | Major | design | The cookie path has no oracle or case | `cookie.txt` initiator test; a `kzc` cookie-flood case |
| T2.12 | Major | design | The timer has no KVM case | `test-kvm` tick-rate case |
| T2.13 | Major | design | Wiring list incomplete | Completed (keys, `make client`, CASES_FOR_GATE, pins regex, MIR 18→19, CHECK-SELFTEST-FIXTURES) |
| T2.14 | Major | design | Injection rows missing | Added (I10.1–I10.4, I7.2, D6, `/dev/kvm` seam, getrandom seam, vectors) |
| S2.8 | Minor | design | `gw_rp_pub_path` is outside I10.1 | Covered by I10.1 |
| S2.9, F2.13, T2.17 | Major (convergent) | design | `virtualization=on` scope | Only the TCG reset cases (`reset_case`); never in `kvm`; I1.2 |
| S2.10 | Minor | design | KSM and hibernation | `mem-merge=off`; host.md |
| S2.11 | Minor | design | Client memory hardening | D6 dumpable/core/mlock/DONTDUMP; `Box<Keys>` |
| S2.12 | Minor | design | SDK supply-chain pins | D9 |
| S2.13 | Minor | prose | GICv3 is not a gap | D3 reworded |
| S2.14 | Minor | design | Hash vs QEMU read TOCTOU | Sealed memfd |
| F2.12 | Minor | design | The generated launcher contains `-bios` | The launcher is a build output; the pattern covers tracked files only |
| F2.14 | Minor | prose | FFI walkthrough stale for Scrub | Fixed |
| F2.15 | Minor | design | Signature gaps | `Result` on `new`; FFI arguments; `kz_sockaddr`; no caller entropy |
| F2.16 | Minor | design | Client profile opt-levels | D12 copies them |
| F2.17 | Minor | prose | Key format unnamed | C7: the liboqs-layout McEliece secret key, `LIBOQS_SK_LEN` |
| F2.18 | Minor | design | No interface owner | `kzc-psk` creates and owns it (D6) |
| F2.19 | Minor | prose | "Exchange succeeded" undefined | An authenticated RespHello |
| T2.15 | Minor | design | KVM counts directory | `build/counts-kvm` |
| T2.16 | Minor | design | GICv2 fixture input | Committed fixture |
| T2.18 | Minor | design | Vector file set | Listed; corpus seeds pinned |
| T2.19 | Minor | design | I10.1 allow sides | Added |
| T2.20 | Minor | design | Encrypted-state oracle | swtpm without the key fails; with it, it succeeds |

### Recurring Issue Check

#### Functionality expert
- R1: Checked, no issue
- R2: F2.5
- R3: F2.14
- R4–R9: N/A
- R10: Checked, no issue
- R11: N/A
- R12: Checked, no issue
- R13–R15: N/A
- R16: F2.1, F2.6, F2.13, F2.16
- R17: F2.9
- R18: F2.12
- R19: N/A
- R20: Checked, no issue
- R21: N/A
- R22: Checked, no issue
- R23–R24: N/A
- R25: F2.10, F2.17
- R26: N/A
- R27: Checked, no issue
- R28: N/A
- R29: Checked (mem-lock failure verified; F2.6 from memory, P9 confirms)
- R30–R32: Checked, no issue
- R33: F2.11
- R34–R37: Checked, no issue
- R38: F2.3
- R39: Checked, no issue
- R40: F2.7, F2.15
- R41: F2.2
- R42: F2.5, F2.9, F2.10
- R43: N/A
- R44–R45: Checked, no issue
- R46: N/A
- R47: Checked, no issue
- R48: F2.2
- R49: F2.4
- R50: F2.1, F2.6
- R51: Checked, no issue
- R52: F2.4
- R53–R54: N/A
- R55: Checked, no issue
- R56–R57: N/A

#### Security expert
- R1: N/A
- R2: Checked
- R3: S2.3
- R4–R28: N/A
- R29: S2.13 (the seL4 quote was re-checked)
- R30: Checked
- R31: N/A
- R32: Checked
- R33: S2.7
- R34: N/A
- R35: Checked
- R36–R37: N/A
- R38: S2.1
- R39: S2.11
- R40–R42: Checked
- R43: S2.4
- R44: Checked
- R45–R46: N/A
- R47: S2.9
- R48: Checked
- R49: S2.1, S2.2, S2.3, S2.5
- R50: Checked
- R51: S2.8, S2.14
- R52: Checked (via S2.2)
- R53–R57: N/A
- RS1: Checked
- RS2: N/A
- RS3: Checked
- RS4: Checked
- RS5: Checked
- RS6: N/A

#### Testing expert
- R1–R2: N/A
- R3: Checked
- R4–R15: N/A
- R16: T2.5, T2.12
- R17–R28: N/A
- R29: Checked
- R30–R31: N/A
- R32: Checked
- R33–R34: N/A
- R35–R36: Checked
- R37–R41: N/A
- R42: T2.13
- R43: N/A
- R44: Checked
- R45–R46: N/A
- R47: Checked
- R48–R49: N/A
- R50: T2.1, T2.3, T2.4, T2.5
- R51–R52: N/A
- R53: Checked
- R54–R57: N/A
- RT1: T2.8, T2.17
- RT2: T2.12
- RT3: Checked
- RT4: N/A
- RT5: Checked
- RT6: T2.11, T2.13
- RT7: T2.1, T2.2, T2.3, T2.4, T2.7, T2.14
- RT8: T2.7
- RT9: T2.9, T2.10
- RT10: T2.19
- RT11: Checked

## Round 3

Date: 2026-11-03
Review round: 3

### Changes from Previous Round

Targeted edits:

- **D13:**
  - the encoding-class scan, with a counter-read allowlist;
  - W^X gated;
  - the scan moved to `package`, with a subject count and a positive
    control;
  - the supervisor named as a trusted exception.
- **D6:** two units and two uids over a peer-cred-checked socket; the
  interface ownership mark and delete-on-exit.
- **D7:** root `keygen` with per-unit directories.
- **C4:** `kozane-vm` is a compiled binary in its own `host/` workspace,
  with the root → dedicated-user privilege flow, an embedded verifier, and
  a downgrade check.
- **C3:** row-2 halt mechanism, heartbeat channel and threshold.
- **C6:** `EXTRA_GATES`, image records in `check-manifest`, and the
  tick-rate observable.
- **C10/C11:**
  - key formats defined once;
  - the SIGTERM matrix;
  - the cookie evidence;
  - the keygen → `peers.toml` route;
  - the `kzc` partition lock.
- **Injection table** rows added.

### Merged findings and dispositions

| ID(s) | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| F3.1, T3.1, S3.1 (register set) | Major (convergent) | design | The scan rejects the counter reads every PD makes; the name list is incomplete | Encoding class op0=3/op1=3/CRn=14; allow only `MRS CNTPCT_EL0` and `MRS CNTFRQ_EL0`; allow fixture; SS variants rejected |
| S3.1 (W^X) | Major | design | W^X is assumed, not gated | `PT_LOAD` W\|X and page-overlap rule; Microkit XN recorded in P12 with a fault check |
| F3.5, T3.2 | Major (convergent) | design | The scan runs before the ELFs exist | Runs in `package` on the release ELFs; `build/timer-scan.txt`; TIMER-SCAN-PDS; positive control in `timer` |
| S3.2 | Minor | design | Supervisor TCB authority undeclared | Declared exception (A20, D13); pin against restart and register writes |
| F3.2, T3.6 | Major (convergent) | design | The heartbeat cannot fire; the halt stops nothing; threshold and wiring | Row 2: `microkit_pd_stop` on every child; timer → audit channel 6; event wiring; `WATCHDOG_S` from the measured TCG gap |
| F3.3, S3.6 | Major (convergent) | design | Interface refusal wedges restarts | `IFLA_IFALIAS` mark; delete on exit and in `ExecStopPost`; marked leftovers recreated; foreign refused; RM9-4 restated; SIGKILL-restart case |
| F3.4, S3.4, T3.13 | Major (convergent) | design | A POSIX sh launcher cannot memfd; reader privilege; I4.1's firmware compare | Compiled `kozane-vm` (`host/` workspace) embedding `vm-args.json`; root → `kozane-qemu`/`kozane-swtpm` fd passing; I4.1 stub checks the seals, hash and uid |
| S3.3 | Major | design | Verifier provenance; signed downgrade | Host-installed embedded verifier; `RELEASE_SEQ` in the pin; I4.3 older-release case |
| S3.5 | Major | design | Shared uid and fork memory; `wg.sk` reachable; euid-owned config | Two units and uids; `SO_PEERCRED`; `client.conf` root-owned only; VE26 for the cross-uid cells |
| S3.7 | Minor | design | `CapBnd` zero needs SETPCAP | Unit `CapabilityBoundingSet`; I10.4 restated |
| T3.3 | Major | design | `kzc` partition lock | Takes the `qemu` host lock; fixture |
| T3.4 | Major | design | Capability tests run as userns root | `setpriv` noroot securebits (VE26) |
| T3.5 | Major | design | The cookie case can pass vacuously | Audit-line evidence of a CookieReply and the accepted InitHello; an ignore-cookie red-proof |
| T3.7 | Minor | design | `CASES_FOR_GATE` conflict | `EXTRA_GATES` with a fixture |
| T3.8 | Minor | design | `check-manifest` ignores the digest | Record type with fixtures; cross-gate comparison |
| T3.9 | Minor | prose | P24 needle | `P24 support/u-boot/boot.cmd` |
| T3.10 | Minor | design | Missing rows | Added (tick, dtb precondition, seals, swtpm key, cookie) |
| T3.11 | Minor | design | Tick observable | The L8 expiry within `EXPIRY_SLACK_S`; a wrong-divisor red-proof |
| T3.12 | Minor | design | `Swtpm` builds its own argv | Calls `vm.swtpm` |
| T3.14, F3.6 | Minor | design | keygen → bundle path; `wg.*` format | The harness routes keygen output through `peers.toml` and `tools/policy`; formats defined in C10 |
| T3.15 | Minor | design | Encrypted-state observation | `swtpm_ioctl -i` plus `TPM2_Startup` |
| T3.16 | Minor | prose | P14 omits mrx33 | Added |
| T3.17, F3.8 | Minor | design | amd64 SDK | The SDK stage is arm64 only in M9 (no amd64 gate host) |
| T3.18 | Minor | design | `sdk-repro` record | `SDK-REPRO-ARTIFACTS 3` |
| T3.19 | Minor | design | SIGTERM target | Per-process matrix |
| F3.7 | Minor | design | keygen before StateDirectory exists | Root `keygen` creates the directories and `fchown`s |
| F3.9 | Minor | prose | Circular `rp.sk` definition | Defined in C10 only |

### Recurring Issue Check

#### Functionality expert
- R4: F3.2
- R6: F3.3
- R11: F3.2
- R12: F3.2
- R16: F3.8
- R17: F3.1
- R18: F3.1
- R25: F3.6
- R29: F3.2 (priorities, peers, `cpu::cntpct` and the Makefile wiring were re-verified)
- R38: F3.2, F3.3
- R40: F3.6
- R41: F3.1, F3.2, F3.4
- R42: F3.4
- R49: F3.1
- R50: F3.5
- All other rules (R1–R57): Checked, no issue, or N/A, as the expert filed them

#### Security expert
- R3: S3.1
- R38: S3.6
- R41: S3.4, S3.7
- R43: S3.5
- R47: S3.1
- R49: S3.1, S3.2, S3.3, S3.5
- R50: S3.1
- All other rules (R1–R57): Checked, no issue, or N/A
- RS1–RS6: Checked or N/A. RS4 note: the test swtpm key is generated per run and never committed

#### Testing expert
- R16: T3.4, T3.16, T3.17
- R29: T3.1, T3.9
- R42: T3.1
- R50: T3.2, T3.8, T3.18
- R52: T3.1
- R53: T3.6, T3.11
- RT1: T3.4
- RT6: T3.6
- RT7: T3.4, T3.5, T3.10
- RT8: T3.5
- RT9: T3.12
- RT10: T3.1, T3.19
- All other rules (R1–R57, RT2–RT5, RT11): Checked, no issue, or N/A

## Round 4

Date: 2026-11-03
Review round: 4

### Changes from Previous Round

Targeted edits:

- **The launcher's privilege flow** passes fds for every cross-uid
  resource: a TPM socketpair and tap fds. It also sets the kvm group and
  memlock, and an unprivileged serial reader.
- **Test seams** (`--root-prefix`, `--user-map`) exist behind a feature
  that release builds lack.
- **The verifier:** `tools/release` gets a lib target, and the manifest a
  `kozane_vm_sha256` entry. The first-install bootstrap is ASSUMED.
- **The client socket's lifecycle** is defined; the initial peer gets a
  random PSK.
- **The supervisor's TCB use** is confined through the existing
  allowlist.
- **The scan, and laws' ELF check after it,** run in `package`, with a
  single emission point.
- **The heartbeat** is unconditional, with a `ticks=` field, which the
  tick-rate case reads.
- **The capability flags** are derived from the unit files; VE28 is
  added.

### Merged findings and dispositions

| ID(s) | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| S4.1, F4.1 | Major (convergent) | design | The swtpm 0600 socket is unreachable across uids; taps, kvm and memlock unspecified | TPM socketpair fds; root-opened tap fds; kvm group; `RLIMIT_MEMLOCK` before the drop; launcher fd forms in `vm.machine`/`vm.swtpm`; I1.2 forbids `path=`/`helper=`/`br=` there |
| F4.2, T4.1 | Major (convergent) | design | The root and two-uid flow cannot run in the single-uid harness | `test-seams` feature (`--root-prefix`, `--user-map`), absent from release builds with a pin; cross-uid cells → VE26, unit-tested |
| T4.2 | Major | design | Capability tests check the harness's own flags | `setpriv` flags parsed from the shipped unit files; the injection edits a unit; `systemd-analyze verify` or VE28 |
| T4.3 | Major | design | The tick observable measures CNTPCT | Unconditional `Heartbeat ticks=`; the rate over host time; 2× divisor red-proof |
| S4.2 | Minor | design | Netdevs and `/dev/kvm` for unprivileged QEMU | Covered by the S4.1 fix |
| S4.3, F4.3, T4.4 | Major (convergent) | design | The supervisor pin uses C names and duplicates the allowlist | Through `tools/supervisor-allowlist` in rust-sel4 terms; only `tcb_suspend` added; the separate pin dropped |
| S4.4 | Minor | design | Initial peer PSK | A random PSK in the creating message; `kozane-psk`-alone case |
| S4.5 | Minor | design | First-install verifier | Build `tools/release` from the signed tag; `kozane_vm_sha256`; ASSUMED in C5 |
| S4.6 | Minor | design | Root parses guest serial | An unprivileged reader reports one byte per heartbeat |
| F4.4, T4.5 | Minor (convergent → Major floor) | design | Scan ordering vs laws; duplicate count | laws' ELF check moves into `package` after the scan; one emission point |
| F4.5 | Minor | design | `tools/release` is binary-only; manifest key list | lib target; `kozane_vm_sha256`; `release.py` |
| F4.6 | Minor | design | Client socket lifecycle | Reconnect after scrub; `BindsTo`/`After`; 0660 socket, group `kozane-net`; reconnect case |
| T4.6 | Minor | prose | `CASES_FOR_GATE` lacks `host` | Added |
| T4.7 | Minor | design | The euid-owned deny cell under uid 0 | Injected `fstat` under VE26 |
| T4.8 | Minor | prose | The allow row names no mutation | Drop CNTPCT from the allowlist |
| T4.9 | Minor | prose | C15 architecture contradiction | arm64 only |

### Recurring Issue Check

#### Functionality expert
- R1: F4.3
- R16: F4.2
- R18: F4.3
- R29: Checked (`microkit_pd_stop` in `microkit.h`; `tools/release` is binary-only)
- R38: F4.6
- R40: F4.1
- R41: F4.1, F4.2
- R42: F4.3, F4.5
- R44: F4.4
- R50: F4.4
- R52: F4.3
- All other rules (R1–R57): Checked, no issue, or N/A

#### Security expert
- R3: S4.1, S4.2
- R41: S4.1, S4.2
- R47: S4.3
- R49: S4.4, S4.5
- All other rules (R1–R57): Checked or N/A
- RS1–RS6: Checked or N/A. RS4: the test key is generated per run.

#### Testing expert
- R16: T4.1, T4.2
- R29: Checked
- R32: T4.1
- R35: T4.2
- R47: T4.4
- R48: T4.4
- R50: T4.5
- R53: T4.3
- RT1: T4.2
- RT2: T4.1
- RT7: T4.2, T4.3, T4.8
- RT10: T4.7
- All other rules: Checked or N/A

## Round 5

Date: 2026-11-03
Review round: 5

### Changes from Previous Round

Targeted edits:

- **C1:** both argv forms (harness paths, launcher fds); the I1.2 ban on
  `path=`/`helper=`/`br=` in the launcher form.
- **C4:** the swtpm bullet now says socketpair.
- **The heartbeat:** its wiring is unconditional, and `ticks=` is defined
  (with coalescing).
- **The row-2 threshold** includes the at-capacity floods.
- **Test seams:** `--build-info` `SEAMS=` with a positive control, bound
  to the hashed binary; a feature-free release build; the cfg confined to
  one module.
- **The systemd layout:** `Group=kozane-net`, `Type=notify`,
  `PartOf`/`Upholds`, connect retry, and a canonical unit subset.
- **New injection rows** and audit-event manifest keys.

### Merged findings and dispositions

| ID(s) | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| F5.1, T5.1 | Major (convergent) | design | Heartbeat wiring still scoped to row 2 | Wiring made unconditional; audit-line counting cases re-checked; audit-event manifest keys raised |
| T5.2, S5.2 | Major (convergent) | design | Tests run the seams build; the marker pin is surface-form and unbound | Feature-free `-p kozane-vm --locked` release build; `--build-info SEAMS=` pin with a positive control on the hashed file; cfg confined to one resolver module; injection row |
| F5.2, S5.3 | Minor (convergent → Major floor) | design | systemd restart, startup race, directory group | `Group=kozane-net`, `Type=notify`, `PartOf`/`Upholds`, retry; read-back via VE28; restart cell |
| F5.3 | Minor | design | `ticks=` source undefined | Notification count, undercount only; idle-node case; tolerance covers it |
| S5.4 | Minor | design | A flood starving `audit` triggers row-2 restarts | `WATCHDOG_S` measured including at-capacity floods |
| T5.3 | Minor | design | The I10.4 injection depends on emulating systemd | Canonical unit subset pinned; injection effective under systemd |
| T5.4 | Minor | design | Missing rows | Added (launcher-form `path=`, test-seams build) |
| F5.4, S5.1, T5.5 | Minor (convergent) | prose | Stale path-form text in C1/C4 | Rewritten for both forms |

### Recurring Issue Check

#### Functionality expert
- R3: F5.1, F5.4
- R12: F5.1
- R38: F5.2
- R50: F5.3
- All other rules (R1–R57): Checked, no issue, or N/A

#### Security expert
- R3: S5.1
- R41: S5.3
- R47: S5.2
- R53: S5.4
- All other rules (R1–R57): Checked or N/A
- RS1–RS6: Checked or N/A

#### Testing expert
- R3: T5.1
- R47: T5.3
- R50: T5.2
- RT1: T5.3
- RT6: T5.1
- RT7: T5.2, T5.4
- RT9: T5.2
- All other rules: Checked or N/A

## Round 6

Date: 2026-11-03
Review round: 6

### Changes from Previous Round

Round 6 returned no Critical or Major findings, so the fixes are small:
- swtpm's key is passed by fd in the launcher form, and `file=` is banned
  there;
- the `SEAMS=` check is placed in `make release`/`release-verify` and in a
  `make host` build ahead of `pins`;
- a systemd floor of 249;
- VE28 now covers the dependency directives, and the restart cells are
  stated as emulated;
- the leftover `tpm_ctrl` name is fixed.

### Merged findings and dispositions

| ID | Sev | Label | Finding | Disposition |
|---|---|---|---|---|
| S6.1 | Minor | design | The launcher-form swtpm still uses `--key file=` | `--key fd=N` in the launcher form; `file=` banned; stub checks the key fd |
| F6.2 | Minor | design (expert: resolvable in Phase 2) | The `SEAMS=0` pin has nowhere to run in `make check` | Check in `make release`/`release-verify`; check-time pin on a `make host` release-command build ahead of `pins` |
| T6.1 | Minor | design | systemd-dependent restart cells are not in VE28 | VE28 extended; harness cells stated as emulation |
| F6.1 | Minor | prose | Stale `tpm_ctrl` | Fixed |
| F6.3 | Minor | prose | systemd floor | client.md: systemd ≥ 249 |

### Recurring Issue Check

#### Functionality expert
- R3: F6.1
- R16: F6.3
- R50: F6.2
- All other rules: Checked or N/A

#### Security expert
- R41: S6.1
- All other rules (R1–R57, RS1–RS6): Checked or N/A

#### Testing expert
- R35: T6.1
- RT1: T6.1
- All other rules: Checked or N/A

## Round 7 (confirmation)

Date: 2026-11-03
Review round: 7

- **Functionality:** F7.1 (Minor, design), the same finding as S7.1, is
  resolved by the same edit. The expert's view: saturation holds once
  that edit is applied, and it needs no further design round.
- **Testing:** No findings. Saturation holds.
- **Security:** S7.1 (Minor, design). The launcher-form `file=` ban also
  matched the media loaders. Disposition: the media are passed as
  root-opened fds (`loader,file=/dev/fd/<n>`), the ban admits only
  `file=/dev/fd/<n>`, and an allow fixture holds a launcher argv with
  media. Saturation holds.

### Saturation call (round 7)

All four conditions hold:

1. Seven rounds have completed.
2. No Critical or Major finding is open in any category. Round 6 had
   none, and round 7's single Minor (S7.1 = F7.1) is applied.
3. No finding against the design remains open. The experts labelled the
   last one design, and it is applied. Both of them stated that saturation
   holds after it.
4. No Minor remains.

Carried-forward findings: none. Every contract is `locked`, subject to the
slice-0 probes, which can send their named contracts back to `pending`.
