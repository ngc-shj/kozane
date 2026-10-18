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
- Action: the scrubbing sender clears the whole link at construction (shared pages are not assumed zero), and `hs` reclaims it on every notification (errors audited). Integration (PD path, closes S10): after peer 1's handshake the harness rebuilds the 74-byte `msgs::Install` hs must have sent (indices and keys known to the Python initiator) and scans the first 32 MiB of guest RAM (every kernel object) through the QEMU monitor until no copy remains. The Microkit report's frame addresses were found not to match runtime placement (they held page-table entries), so no address is assumed. Red-proved: with the reclaim removed the install is found at 0x6053f000 and the case fails.
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
