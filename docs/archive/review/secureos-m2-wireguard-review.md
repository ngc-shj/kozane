# Plan Review: secureos-m2-wireguard

# Round 1
Date: 2026-10-18 — initial review. All findings reflected in plan revision 2.

| ID | Expert | Sev | Finding | Plan change |
|---|---|---|---|---|
| F1 / S1 / T1 | all | Major / Critical (T1) | no key confirmation; hs→data install races the first packet; IKpsk2 responder cannot detect a wrong PSK, so "no PSK → no response" is untestable and false | next/current/previous slots, keepalive confirms, install-before-response, Objective and case 2 restated |
| F2 | Func | Major | endpoint ownership contradictory | ingress sole owner; updates only from data on authenticated new-max counter |
| F3 | Func | Major | hs cannot guarantee index uniqueness | hs mirror table + data rejects collisions |
| F4 | Func | Major | slot 23 is IRQ 71, not 78 | IRQ 71; QEMU `bus=virtio-mmio-bus.23` placement (verified), no fillers |
| F5 | Func | Minor | responder-only expiry limitation | recorded; client configs carry PersistentKeepalive |
| F6 | Func | Minor | CNTFRQ, RNDR encoding, early spike | in design decisions |
| F7 | Func | Minor | blob format has no owner | `secret-blob` crate |
| S2 | Sec | Major | lazy-only expiry cannot zeroize idle sessions (L12) | sp804 `timer` PD, 1 s ticks, sweep |
| S3 | Sec | Major | PSK oracle exposes static PSKs to tainted hs | `PskMix` in key; L2 oracle set amended |
| S4 | Sec | Major | no cookies → L13 unmet; key quota is a global choke | residual stated, dev-only until M2.5, per-source bucket, early unknown-peer reject, quota sizing, audit |
| S5 | Sec | Major | NET_ADMIN in the build container widens A5 | no NET_ADMIN; tests in `unshare -rn` via a pinned seccomp profile |
| S6 | Sec | Minor | secret residue in IPC buffers / ring slots | zeroing required |
| S7 | Sec | Minor | inner anti-spoof; roaming on any in-window packet | static neighbor IP+MAC check; roaming on new max counter |
| S8 | Sec | Minor | silent drift from architecture plan; RNDR hedge; PSK bound by index | decisions recorded; BLAKE2s(seed‖ctr‖RNDR); peer-hash binding; 0600 + symlink-resolved paths |
| T2 | Test | Major | Python initiator not independent | captured wireguard-go fixture, kernel selftest vectors |
| T3 | Test | Major | negative cases by absence | audit line + liveness barrier per case |
| T4 | Test | Major | boot halt test non-specific; blob source for make test | distinct lines; temp-dir mksecrets + package with cleanup |
| T5 | Test | Major | manifest blind to new crates; selftest anchor removed | per-crate keys, new anchor, selftest cases |
| T6 | Test | Major | Kani feasibility of the replay window | const-generic small N, two-call harness, crypto-free modules |
| T7 | Test | Major | wireguard-go prerequisites/teardown | fail-not-skip, `wg show` assertion, teardown on all paths |
| T8 | Test | Major | package diff precondition | reproducibility check + counted diff fixtures |
| T9 / T10 | Test | Minor | test homes; untested invariants | config lib tests; non-Clone assertions, roaming test, injectable clock, bolero targets |

# Round 2
Date: 2026-10-18 — one sub-agent covering the three perspectives (verification round). Integration feasibility verified empirically: in a throwaway container with the seccomp profile, `unshare -rn` works, `lo` comes up, `ip tuntap add` succeeds, and QEMU binds user-net hostfwd + dgram ports with `-cpu neoverse-n2` and `bus=` placement. All findings reflected in plan revision 3.

| ID | Sev | Finding | Change |
|---|---|---|---|
| F8 | Major | hs index mirror cannot follow data's slot rule; install effect on next/previous unspecified | install replaces next (old next zeroized); indices unique by construction (per-boot keyed 32-bit Feistel permutation of a counter); mirror removed |
| F9 | Minor | dropping unconfirmed next at REKEY_TIMEOUT diverges from wireguard-go | next expires at REJECT_AFTER_TIME |
| S9 | Major | BootSeed exported a static blob secret; hedge repeated across reboots | key returns BLAKE2s(blob_seed‖RNDR‖CNTPCT) only; hs mixes CNTPCT per draw |
| S10 | Major | unconditional `unshare` for the dev container | seccomp arg filter: exactly CLONE_NEWUSER\|CLONE_NEWNET; residual R5 recorded in the architecture plan |
| S11 | Major | timer tainted under L1 | notify-only exemption added to L1 (no shared memory, peers cannot notify it) |
| S12 | Minor | "dev-only" unenforced; no L13 waiver | residual R6; `make package` refuses release config until M2.5 |
| S13 | Minor | keys kept to 3× REJECT_AFTER_TIME | zeroize at REJECT_AFTER_TIME |
| T11 | Major | wrong-PSK case peer identity unspecified | same peer as case 1, newer TAI64N, Python fails the empty AEAD, barrier with latest-handshakes unchanged; data slot unit tests |
| T12 | Minor | Kani/bolero would compile libcrux; per-crate counts | crypto-free `wg-wire` crate; unit target counts per crate |

# Round 3
Date: 2026-10-18 — one sub-agent, verification round. Re-verified empirically: `unshare -rn` works and `ip tuntap add` succeeds inside it; `unshare -rm`, `-U` and `-rnm` are refused, so the EQ filter matches util-linux's exact flags; without CAP_SYS_ADMIN only the appended entry applies. All findings reflected in plan revision 4; contracts locked.

| ID | Sev | Finding | Change |
|---|---|---|---|
| F10 | Minor | release refusal keyed on a make variable; `benchmark` config passes | refuse every non-`debug` config, read from the built `gen_config.h`; removed with SC13 |
| S14 | Major | timer exemption did not forbid `pp` on the timer end (PPC replies would taint it) | L1: `pp="false"` on both ends, peer `notify="false"`, timer maps only its device page |
| S15 | Minor | 4-round Feistel on 16-bit halves is not unpredictable; key not separated from boot_seed | 8 rounds, labelled `k_idx`, unpredictability explicitly not relied on |
| T13 | Minor | no tests for the permutation, timer exemption, release refusal | exhaustive 8-bit-half bijection test; C7 fixture pairs; check-selftest case |
| T14 | Minor | seccomp JSON has no offline drift check or deny-side test | offline diff check in `make check`; `run.py` asserts `unshare -rm` fails |
