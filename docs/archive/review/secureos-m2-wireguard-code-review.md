# Code Review: secureos-m2-wireguard
Date: 2026-10-19
Review round: 1

## Changes from Previous Round
Initial review of `97d2eb8..5c4e486` (plan lock + implementation). Three
expert sub-agents in parallel (local-LLM seeds unavailable: the diff exceeded
the analyzer's request size). An external review supplied by the user
(2026-10-19) reported S1, S2, F2 and one new finding, X1.

## Functionality Findings
- F1 [Major] Every in-order inbound packet produced an `EndpointUpdate`, which could fill the 64-buffer `di` link and starve outbound traffic — crates/pds/data/src/main.rs, crates/data-core/src/lib.rs.
- F2 [Major] Peer-capacity constants drifted (secret_blob 62, config 61 claimed to "mirror" it, data 8 enforced only at boot) — crates/config/build.rs, PD mains.
- F3 [Minor] `make run` stale for M2 (cortex-a53 without RNDR, one NIC, echo port) — Makefile.
- F4 [Minor, Adjacent] Install link scrubbed only on the next send (see S1).
- F5 [Minor] Key budget exhaustion not audited distinctly; `KeyClient::last_error` unused.
- F6 [Minor, Adjacent] `msgs::Install` derived Debug/Clone/Copy while carrying keys.
- F7 [Minor] Neighbors unbounded, silently truncated at 64; alias cases not rejected.
- F8 [Minor] `data` state size not checked against its stack.
- F9 [Minor] `inner` copied a 2 KiB buffer per frame; `self.reply` dead.

## Security Findings
- S1 [Major] hs→data install buffers (transport keys) stayed in `hd_data` until the next handshake, outliving session expiry (L12).
- S2 [Major] `tools/package` checked only the blob path; OUT, `build/` and cache volumes unchecked, existing OUT accepted, loader written under the caller's umask (L6).
- S3 [Minor] `key`'s last reply stays in its own IPC buffer; comment overclaimed.
- S4 [Minor] Receiver index consumed before authentication; 2^32 rejected initiations would disable handshakes permanently.
- S5 [Minor] `data` took the session start time from hs (RS5).
- S6 [Minor] Allowed IPs could cover inside neighbors or the inside address; neighbor equal to `inside_ip` accepted.
- S7 [Minor] DoS rationale understated the precondition (the published gateway key passes mac1).
- S8 [Minor] mksecrets silently dropped an unresolvable repository root (fail-open).
- S9 [Minor] = F5. S10 [Minor, Adjacent] = residue test on helper only. S11 [Minor, Adjacent] auth failure and unknown index shared one audit code.

## Testing Findings
- T1 [Major] `INTEGRATION-CASES 7` was a literal, not a count of passed cases.
- T2 [Major] No bolero target for the WireGuard parsers (C9).
- T3 [Major] No captured wireguard-go initiation fixture (C9/T2).
- T4 [Major] No end-to-end proof that build.rs rejects an invalid configuration (C15).
- T5 [Major] The "blob appears twice" package fixture passed with its clause removed (red-proved by the reviewer).
- T6 [Major] A failing wireguard-go setup leaked the daemon and its UAPI socket.
- T7 [Major] SIGTERM skipped the temp-dir cleanup (keys left in /tmp).
- T8–T22 [Minor]: per-crate Kani keys; msgs harness without covers; `unshare -rm` probe could pass via mount(2); monitor fault line not asserted; untested validator branches; mksecrets scratch leaks and loose deny asserts; `cpu` not linted/tested; boot-error distinctness 4/8; wrong-PSK case without allow side; port collisions; Feistel test re-implementing the round; bucket harness doc overclaim and no RateLimited cover; T20 = F2; T21 = F5; T22 round function swallowing a hash error.

## External Findings (user-supplied review)
- X1 [Major] IPv4 TTL not decremented when forwarding; a routing loop through the gateway would not die out.

## Adjacent Findings
F4, F6 (security), S10 (testing), S11 (functionality), T21, T22 — all resolved below.

## Quality Warnings
None.

## Recurring Issue Check
### Functionality expert
R1 checked (two token buckets with different parameters, not merged); R2 violated (F2); R3 checked; R4/R12 checked; R16 violated (F3); R29 violated (F2 comment, F4 deviation claim); R32 checked; R38 checked; R39 partially (F4); R40 checked; R41 violated (F5); R44 checked; R49 see F4. N/A: R5/R6/R9/R14/R15/R24 (no DB), R7/R8/R23/R26/R28/R37 (no UI), R31, R45–R48, R51–R57.

### Security expert
R3 checked (only `hd` carries keys; S1); R29 violated (S7); R39 violated (S1); R48 violated (S2/S8 different forbidden-root sets); R49 violated (S1, S3, S7); R51 checked. RS1 OK (ct_eq, scanner clean); RS2 partial (S4, S7; L13 waived, R6); RS3 OK except config gap S6; RS4 OK except output path S2; RS5 violated (S5); RS6 N/A. N/A: DB/UI families, R11/R12, R45–R47.

### Testing expert
R2 T20; R3 checked except T8; R29 checked (T3 claim); R44 checked; R49 T16/T18/T19; R50 T1; R53 checked. RT1 checked; RT2 checked; RT3 checked; RT4 N/A; RT5 T18; RT6 T14; RT7 T1/T4/T5/T9; RT8 T5/T13; RT9 T18; RT10 T10/T16; RT11 T6/T7/T13.

## Environment Verification Report
Phase 1 constraints (VE6–VE8: RNDR needs neoverse-n2, integration in `unshare -rn`, sp804 timer): all paths `verified-local` by `make check` in the dev container (integration boots QEMU with wireguard-go inside `unshare -rn`).

## Resolution Status
### F1 [Major] EndpointUpdate flood
- Action: data-core keeps the endpoint `ingress` last accepted; an update is due only on a new highest counter from a different source, and `endpoint_delivered` records it only after a successful send (a failed send is retried). Tests for repeat suppression, retry, roam-once and old-counter roam; red-proved (dropping the source comparison fails two tests).
- Modified: crates/data-core/src/lib.rs, crates/data-core/src/tests.rs, crates/pds/data/src/main.rs
### F2 / T20 / external #3 [Major] Peer capacity
- Action: one `MAX_PEERS` (8, the deployable bound) and `MAX_NEIGHBORS` (64) in validate.rs, rendered into `config`; build.rs asserts it fits secret_blob; mksecrets, hs, ingress, data and inner use it with compile-time assertions; data's runtime halt removed. End-to-end fixture: 9 peers fail the build.
- Modified: crates/config/{build.rs,src/validate.rs,Cargo.toml}, tools/mksecrets/src/main.rs, crates/pds/{hs,ingress,data,inner}/src/main.rs
### S1 / F4 / external #1 [Major] Install residue
- Action: the scrubbing sender clears the whole link at construction (shared pages are not assumed zero), and `hs` reclaims it on every notification (errors audited). Integration (PD path, closes S10): after peer 1's handshake (the only session whose keys the harness knows; wireguard-go's are not exposed) the harness rebuilds the 74-byte `msgs::Install` hs sent (length tied to `msgs::INSTALL_LEN`) and polls the guest RAM window `OBJECT_RAM` in tests/integration/run.py through the QEMU monitor until no copy remains, while requiring in the same snapshot a positive control (the session key `data` must hold), so a window that misses PD memory fails instead of passing. The Microkit report's frame addresses were found not to match runtime placement (they held page-table entries), so no address is assumed. Red-proved: with the reclaim removed the install is found at 0x6053f000 and the case fails.
- Modified: crates/ring/src/link.rs, crates/ring/src/tests.rs, crates/pds/hs/src/main.rs, tests/integration/run.py
### S2 / external #2 [Major] Package output protection
- Action: shared forbidden-root predicate for blob and OUT (repo incl. build/, cargo/rustup homes; repo must resolve), OUT must not exist, 0700 staging dir under umask 077, rename on success, staging removed on every failure path. Fixtures: OUT in build/, in repo, through a symlink, existing; blob in cargo home; allow cases.
- Modified: tools/package, tests/tools/test_package.py
### X1 [Major] TTL
- Action: `wire::forward_ipv4` decrements TTL, recomputes the header checksum, refuses TTL <= 1 (`TtlExpired`); `inner` applies it in both directions. Kani harness (parseable, TTL−1, nothing else changed), unit tests at the TTL 2/1/0 boundary, integration asserts echo requests arrive with TTL 63 and a TTL-1 datagram is audited `TtlExpired`.
- Modified: crates/wire/src/{lib.rs,proofs.rs,tests.rs}, crates/inner-core/src/{lib.rs,tests.rs}, crates/pds/inner/src/main.rs, tests/integration/run.py
### T1 [Major] Integration count
- Action: each case appends to `passed` after its assertions; the count printed is `len(passed)`. check-selftest case `integration-count` removes one case and requires the manifest to fail.
### T2 [Major] WireGuard bolero target
- Action: wg-wire target (parse/emit round trip for all three messages, replay window against a set model) with five committed seeds; the bolero gate loops over targets, each must load its corpus and complete runs; BOLERO-TARGETS 2; check-selftest case `bolero-wg-wire`.
### T3 [Major] Captured wireguard-go fixture
- Action: a real wireguard-go initiation (known keys) must be accepted and map to the configured peer; tampered static (re-MACed) → Decrypt; other responder → BadMac1. Red-proved by mutating `IDENTIFIER`.
### T4 [Major] Build-failure fixture
- Action: tests/tools/test_config_build.py builds `config` with the committed file (must pass) and four invalid files (overlap, neighbor cover, 9 peers, unknown field) that must fail with their message; wired into the pins gate (CONFIG-BUILD-FIXTURES 5).
### T5 [Major] Package fixtures
- Action: every deny fixture names the error it expects; "blob appears twice" rebuilt so only uniqueness can fire; red-proved.
### T6, T7 [Major] Harness teardown
- Action: `WgGo` tears itself down if configuration fails; SIGTERM/SIGHUP raise SystemExit in parent and netns child so `finally` removes the key-bearing temp dir.
### Minor findings
- F3 `make run` mirrors the integration QEMU arguments, `LOADER=` boots a package. F5/S9/T21 `HandshakeKeyRateLimited`, mapping moved to `hs_core::reject_event` with tests. F6 `Install` no longer Debug/Clone/Copy. F7/S6 neighbor bound and alias checks with tests. F8 `size_of::<DataPd>()` asserted against `layout::DATA_STACK_SIZE` (layout test ties it to the .system). F9 no per-frame copies. S3 comment corrected, residue recorded. S4 index issued after authentication (test red-proved). S5 `created_ns` removed; data stamps install time (boundary test). S7 comment and R6 corrected. S8 unresolvable repo root is an error. S11 `TransportUnknownIndex`. T8 per-crate Kani keys. T9 covers per Ok variant. T10 `unshare -r --uts` probe requiring "unshare failed". T11 monitor fault line asserted. T12 tests per validator branch. T13 self-cleaning scratch dirs, deny asserts match "is inside". T14 `cpu` linted and tested (ticks_to_ns; RNDR not executed on the host, which lacks FEAT_RNG). T15 all boot errors compared, exhaustive. T16 allow side: the same response opens with the right PSK. T17 ports never reused within a run. T18 test calls `Indices::round`. T19 doc corrected, RateLimited cover. T22 a round hash failure refuses the index.

# Round 2
Date: 2026-10-19 — incremental review of `5c4e486..e234ed7` by the same three experts. Round-1 findings all resolved except where noted below; no Critical findings; R43 (fix-induced widening): none found by any expert.

## Findings
| ID | Sev | Finding |
|---|---|---|
| F-R2-1 / M8 | Major | Docs overstated the residue test (each handshake / all zero / 32 MiB) |
| M1 | Major | SIGTERM to the harness SIGKILLed the netns child, orphaning QEMU and wireguard-go |
| M2 / R2-S1 | Major | RAM residue scan had no positive control; vacuous if layout or window drifted |
| M3 | Major | Secrets-path symlink resolution in tools/package untested (red-proved removable) |
| M4 | Major | Package staging lifecycle (0700, rename, cleanup on failure) untested |
| R2-S2 | Minor | Package staging leaked on SIGTERM/SIGHUP; rmtree errors swallowed |
| R2-S3 / F-R2-4 | Minor | Package check/rename via an unresolved parent; rename replaces an empty OUT |
| R2-S4 | Minor | CNTFRQ == 0 freezes time, so sessions never expire |
| R2-S5 | Minor | Allowed IPs could cover unlisted inside hosts (no inside prefix) |
| F-R2-2 | Minor | `make run` lost its image prerequisite |
| F-R2-3 / M7 | Minor | Integration TTL case did not assert the TTL-2 allow side; PASS order |
| M5 | Minor | LINT-CRATES minimum not raised for `cpu` |
| M6 | Minor | hostfwd port chosen before Wire bound its port |
| M9 | Minor | Bolero corpus check satisfied by untracked generated inputs |
| M10 | Minor | Boot-error exhaustive match not tied to the compared list |

## Recurring Issue Check (Round 2)
Functionality: R2 resolved; R3, R4, R12, R32, R38, R40, R41, R44, R48 checked; R16 violated (F-R2-2); R29/R49 violated (F-R2-1); R43 checked, no widening.
Security: R43 none; RS1 OK; RS2 accepted (R6); RS3 gap R2-S5; RS4 OK; RS5 violated (R2-S4); RS6 N/A.
Testing: R29 (M7, M8); R49 (M1, M2); RT6 (M5); RT7 (M2, M3); RT10 (M4, M7); RT11 (M1, M6); others checked.

## Resolution Status (Round 2)
- F-R2-1 / M8: deviation log and Round-1 S1 entry restated to the actual mechanism (peer 1's install needle, `OBJECT_RAM`, positive control); both cite the constant instead of a size.
- M2 / R2-S1: the same snapshot must contain `data`'s live session key (control) and must not contain the install; needle length checked against `msgs::INSTALL_LEN` parsed from the Rust source; scratch file unlinked before each read; window 32 MiB.
- M1: the parent forwards SIGTERM to the netns child and waits 15 s (then kills, loudly); QEMU and wireguard-go get PR_SET_PDEATHSIG so a killed harness cannot orphan them.
- M3: fixtures for a secrets symlink into the repo (deny) and outside (allow). M4: fixtures run `main()` with `build` replaced: success → OUT 0700 with a 0600 image and no staging; failure and exception → no OUT, no staging. Red-proved: removing the cleanup fails both failure fixtures; removing the umask fails the success fixture.
- R2-S2: SIGTERM/SIGHUP raise SystemExit in tools/package; staging removal reports leftovers and fails the run. R2-S3 / F-R2-4: parent resolved once and used for mkdtemp and rename; the staging dir is re-checked against the forbidden roots; OUT existing just before the rename refuses (residual window between that check and rename(2) accepted: it needs write access to the operator's own directory).
- R2-S4: `cpu::checked_frequency` refuses 0; `data` and `hs` halt at init without a clock (host test 0 / 62.5 MHz).
- R2-S5: required `inside_prefix`; inside_ip and every neighbor must lie in it, outside_ip must not, and no allowed IP may overlap it (unit tests and a build-failure fixture).
- F-R2-2: `run` depends on `image` when the default LOADER is used. F-R2-3 / M7: the TTL case requires an echo reply to seq 2 and none to seq 1; `to_lan` TTL-2 unit test; PASS lines in order. M5: LINT-CRATES 17. M6: Wire records its held port; hostfwd chosen after it. M9: each bolero target requires committed `seed-*` files. M10: the compared list is built from the exhaustive match and its length asserted.

# Round 3
Date: 2026-10-19 — incremental review of `e234ed7..4e72286`. No Critical findings; R43: no widening.

## Findings
| ID | Sev | Finding |
|---|---|---|
| R3-S1 / T6 | Major | Positive control satisfiable by hs/data stack residue; coverage of `hd` itself unproven |
| T1 | Major | Bolero seed check (git) broke check-selftest: its copies have no .git |
| T2 / R3-S2 | Major | inside_ip test passed on a neighbor error (substring collision); outside_ip branch untested |
| T3 / R3-S3 / F-R3-A2 | Major | Package main() fixtures ignored exit status; new branches (OUT appeared, staging re-check, loud removal, signals) deletable green |
| T4 / F-R3-3 | Major | BlobError list tie still skippable by an arm-only addition (red-proved) |
| T5 | Major | Residue needle tied to msgs::Install by length only |
| R3-S4 / F-R3-1 / F-R3-2 | Minor | Second signal interrupted teardown; netns harness had no PDEATHSIG |
| R3-S5 | Minor | RAM dump kept until teardown; temp-dir removal errors swallowed |
| F-R3-4 | Minor | wireguard-go route hard-coded instead of inside_prefix |
| F-R3-5 | Minor | inside_prefix parse errors labelled "allowed IP" |
| F-R3-A1 | Minor | Package comment claimed a single parent resolution |
| T7 | Minor | inside_prefix overlap boundaries unpinned |
| T8 | Minor | Manifest minimums lagged the counts |
| T9 | Minor | run_main left signal handlers installed |
| T10 | Minor | Seed check misattributed git failures; per crate, not per target |
| T11 | Minor | SIGTERM forwarding had no recorded proof |

## Recurring Issue Check (Round 3)
Functionality: R2 (F-R3-4), R3 (F-R3-1/2), R12 (F-R3-3), R29/R49 (F-R3-3 comment, package comment) violated; R4, R16, R38, R40, R41, R43, R44, R48, R50, R52 checked.
Security: R43 none; RS1 (R3-S5); RS2 accepted residual undermined the control (R3-S1); RS3 (R3-S2); RS4 accepted windows only; RS5 resolved; RS6 N/A.
Testing: regression (T1); RT1 (T2, T4); RT3 (T3); RT5 (T9); RT6 (T8); RT7 (T2, T3, T7); RT8 (T7); RT9 (T4); RT10 partial (T3); RT11 partial (T6, T10).

## Resolution Status (Round 3)
- R3-S1 / T6: comments and docs restated to what the control proves (PD memory, not `hd`); check-selftest case `integration-residue` removes the reclaim and requires `make test` to fail with "install message still in guest RAM", so the scan's power to catch `hd` residue is re-proven mechanically. (Pinning `hd_data`'s physical address was rejected: C7 allows `phys_addr` only on device regions.)
- T5: golden vector `INSTALL_GOLDEN_HEX` in crates/msgs/src/tests.rs pins the encoder; run.py checks its packing against it before scanning.
- T1 / T10: check-selftest runs make with `GIT_DIR` of the real repository; the seed check is per target directory and reports a git failure as such. Deny side checked with an empty index ("no committed seed-*").
- T2 / R3-S2: inside_ip moved alone with the exact message asserted; outside_ip deny and adjacent allow tests. T7: /32 at both ends of the inside network refused, a neighboring /32 accepted. F-R3-5: inside_prefix errors carry their own label.
- T3 / R3-S3 / F-R3-A2 / T9: fixtures assert exit status and that the build ran; new fixtures for OUT appearing during the build, SIGTERM during the build, staging resolving into a forbidden root, and a failed staging removal; handlers, umask, argv and `build` restored. Red-proved: removing the staging re-check, the OUT-appeared refusal, the loud removal, or the signal handler each fails its fixture.
- T4 / F-R3-3: successor-walk over BlobError plus `variant_count` assertions for BlobError and BootError.
- R3-S4 / F-R3-1 / F-R3-2: signal handlers ignore further signals during teardown (run.py, tools/package); SIGTERM forwarded only to a live child; the netns harness gets PR_SET_PDEATHSIG (preexec and re-armed after exec, exiting if the parent is already gone); ctypes resolved at import.
- R3-S5: each RAM dump is unlinked right after reading; temp-dir removal reports leftovers and fails the run.
- F-R3-4: wireguard-go routes `inside_prefix` from the generated config. F-R3-A1: comment corrected. T8: minimums raised. T11: see the manual proof recorded below.
- T11 manual proof (2026-10-19, dev container): `run.py` started in the background; once "PASS [wireguard-go handshake" was logged, SIGTERM to the outer harness. Outer exit 143; afterwards no `qemu-system-aarch64`, no harness `wireguard-go` (`wgt*`), no `wgt*` UAPI socket and no `/tmp/secureos-it-*` directory remained.
- Verification of this round: `make check` green; `tools/check-selftest integration-residue bolero bolero-wg-wire` → all three ok (`integration-residue`: with the reclaim removed, `make test` fails with "install message still in guest RAM").
