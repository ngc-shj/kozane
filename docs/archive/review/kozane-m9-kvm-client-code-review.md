# Code Review: kozane-m9-kvm-client
Date: 2026-11-06T10:49:06+09:00
Review round: 1

## Changes from Previous Round
Initial review (HEAD a5c7704). Local LLM unavailable: no pre-screen or seeds; experts read the full diff; merged by hand (no cross-expert duplicates: F3 is the only Adjacent, testing-side, and does not overlap T1-T11).

## Functionality Findings
### F1 [Minor] --compare-identity sorts IMAGE and QEMU values together, losing which value belongs to which key
- tools/check-manifest:151 (`seen[d] = tuple(sorted(...))`), labelled at :154 by `dict(zip(IDENTITY_KEYS, v))`.
- sorted() orders values lexicographically, not by key: the "different images" message can mislabel; swapped values across dirs would compare equal (practically impossible: 64-hex vs 40-hex).
- Fix: drop sorted; fixture where dirs differ only in QEMU must report QEMU with that build-id; swapped-values fixture must fail; three identical dirs still pass; "?" for missing stays.

### F2 [Minor] host.md runs swtpm_setup as kozane-swtpm against a root:0600 key it cannot read
- docs/operations/host.md:152-154 vs table :73 and key creation :146-149. Following the doc fails with EACCES (loud). Harness unaffected (run.py:9178).
- Fix: keep key root:0600; pass as fd (`--keyfile-fd 3 3</etc/kozane/swtpm.key` from a root shell, via sudo -u kozane-swtpm) or run as root then chown the state dir. Must not relax the key's mode.

### F3 [Minor][Adjacent, testing] serial reader heartbeat tests use a format audit never prints
- host/crates/kozane-vm/src/serial.rs:156-182: tests feed `audit: src=timer Heartbeat ...`; audit prints `audit: Heartbeat ticks=<n> seq=<s>` (crates/pds/audit/src/main.rs; harness run.py:8942). is_heartbeat (serial.rs:29-32) accepts a bare `Heartbeat` token anywhere after `audit: `.
- Fix: positive case with exact bytes audit emits; decide whether matcher requires `Heartbeat` as the second token. Only drives the journal line.


## Security Findings
S1 [Major] tools/vm.py:168-172 `_value_problems` device branch checks only the driver; `-device loader,file=/dev/fd/7,addr=…,force-raw=on,cpu-num=0` (or an ELF loader without force-raw) passes I1.2 and sets the CPU's PC into boot media, bypassing the firmware pin (I4.2). Claim at vm.py:37-41 is stronger than the code (R49). escalate: false. Fix: exact key set per driver (loader {file, addr, force-raw=on}, file /dev/fd/N in launcher form; virtio-net-device {netdev, mac, bus}; virtio-rng-device {rng, bus}; tpm-tis-device {tpmdev}); refuse other/repeated keys; deny fixtures cpu-num, no force-raw, force-raw=off; allow: rendered argv still [].
S2 [Major] host/crates/kozane-vm/src/kv.rs:108-112 qemu/swtpm programs only checked for leading '/'; run at main.rs:229,263 via spawn.rs:53 without owner/mode/symlink checks every other input gets (R3). A non-root-writable QEMU voids the pin. escalate: false. Fix: open O_PATH|O_NOFOLLOW, check_meta (regular, root, no 022), check ancestors, exec the same fd; allow /usr/bin root 0755; deny cells; no PATH fallback.
S3 [Minor] tools/vm.py:173-174 `-object rng-random` checked by head only; filename=/dev/zero passes. Fix: exact {rng-random,id,filename=/dev/urandom}; deny fixture.
S4 [Minor] host/crates/kozane-vm/src/pin.rs:40-43 + tools/release/src/lib.rs:20-37: release keys checked by fd then re-read by name, unbounded (R51). Hardening. Fix: fd-taking loader, bounded reads.
S5 [Minor] client/crates/client/src/lib.rs:220-224, client-cli net.rs:89-95, client-ffi lib.rs:139-141: moved OSK copies left in unscrubbed, unlocked frames; deviation wording overstates (R39, R49). Fix: scrub_stack in the shell after perform/queue, or Box<Secret> locked; rp-residue case at Client::on_datagram; correct wording.

## Testing Findings
T1 [Critical] host gate never runs the launcher's non-seams config; two tests always pass — Makefile host: (only --features kozane-vm/test-seams); host/crates/kozane-vm/tests/build_info.rs:20-27 (early return under cfg!(test-seams)); host/crates/kozane-vm/src/tests.rs:106-110 (early return under resolve::SEAMS). Mutation that stays green: make not(test-seams) branch of Resolver::from_args (resolve.rs:73) strip --root-prefix, or change owner() fallback. Fix: second cargo test without features in host (count in UNIT-HOST); cfg-gate instead of runtime early returns; no-features run must fail if it sees SEAMS=1; selftest cases per mutation.
T2 [Major] kzc/kzc-psk never built or tested without test-seams; build_info.rs:1-2 claims a SEAMS=0 check that does not exist — client-cli Cargo.toml:43-44 self dev-dep with test-seams; Makefile client:, kzc-seams:. Mutation green: seams.rs not(feature) branch parsing --root-prefix, or SEAMS=true. Fix: build bins --release without features; --build-info must print SEAMS=0; `kzc --root-prefix /x up` must fail with usage; selftest case red-proving it.
T3 [Major] encrypted-state check (run.py:8609-8650 swtpm_state_encrypted, needle `swtpm-state: plaintext`) never red-proven; grep swtpm-state tools/check-selftest = 0. Fix: test-kvm selftest case that gives the keyless run --key; allow side: keyed check unchanged.
T4 [Minor] vm.py:269-271 render_launcher_args forbidden-argument chokepoint has no red-proof. Fix: monkeypatch vm.machine to add -gdb; assert raise + no file; pair with clean render.
T5 [Minor] tests/signal.rs cannot distinguish the self-pipe from a terminated() pre-check in sys::poll. Fix: deliver SIGTERM while a thread is blocked inside poll.
T6 [Minor] check-manifest tree_digest digests a missing tree silently (R50); IMAGE_TREES=("/nonexistent",) stays green. Fix: refuse a missing tree; require MICROKIT_SDK for --identity; fixtures.
T7 [Minor] RP-INITIATOR-VECTORS, UNIT-CLIENT-FFI, UNIT-CLIENT-CLI named in the plan's manifest list are absent with no deviation entry; UNIT-CLIENT sums the workspace. Question: intended?
T8 [Minor] netns.rs:45 holds all real-kernel cells in one #[test]; deleting a cell changes no count. Fix: NETNS-CELLS <n> in the manifest.
T9 [Minor] tests/manifest-kzc.txt:2-3 says make check counts never depend on the host (VE25), but client netns needs kernel WireGuard in unshare -rn. Fix: correct comment or record.
T10 [Minor] client-cli tests/units.rs:75-89 temp dir leaks on panic (RT11). Fix: Drop guard.
T11 [Minor] keygen.rs:175 unlink-on-failure untested (RT6). Fix: inject a write failure, assert no key file left; pair with success.

## Adjacent Findings
- F3 [Minor][Adjacent, testing] serial reader heartbeat tests use a format audit never prints.

## Quality Warnings
None: every finding names a file, line and a mutation or failure scenario.

## Recurring Issue Check
### Functionality expert
- R1 checked; R2 checked; R3 checked; R4 checked; R5 N/A; R6 N/A; R7 checked (F3); R8 N/A; R9 N/A; R10 checked; R11 N/A; R12 checked; R13 checked; R14 N/A; R15 N/A; R16 checked; R17 checked; R18 checked; R19 N/A; R20 N/A; R21 N/A; R22 checked; R23 N/A; R24 N/A; R25 checked; R26 N/A; R27 checked; R28 N/A; R29 checked; R30 N/A; R31 checked; R32 checked; R33 checked; R34 checked; R35 checked (F2); R36 N/A; R37 N/A; R38 checked; R39 checked; R40 checked; R41 checked (F1); R42 checked; R43 N/A; R44 checked; R45 checked; R46 N/A; R47 checked (F3); R48 checked (F3); R49 checked; R50 checked; R51 checked; R52 checked; R53 checked; R54 N/A; R55 checked; R56 checked; R57 checked (F1).

### Security expert
R1 ok; R2 ok; R3 S2; R4 N/A; R5 ok; R6-R11 N/A; R12 ok; R13-R15 N/A; R16 ok; R17 ok; R18 S1/S3; R19-R24 N/A (R22 ok); R25 ok; R26-R28 N/A; R29 checked; R30 N/A; R31 ok; R32 N/A; R33 ok; R34 none; R35 N/A; R36 none; R37 N/A; R38 ok; R39 S5; R40 ok; R41 ok; R42 ok; R43 none; R44 ok; R45-R46 N/A; R47 ok; R48 ok; R49 S1,S5; R50 ok; R51 S4; R52 ok; R53-R54 N/A; R55 ok; R56-R57 N/A.
RS1 ok; RS2 N/A; RS3 ok; RS4 none; RS5 ok; RS6 N/A.

### Testing expert
R1 ok; R2 ok; R3 T1/T2; R4-R15 N/A (R7 N/A, R8 N/A); R16 T9; R17 ok; R18 ok; R19 ok; R20 ok; R21 N/A; R22 ok; R23-R26 N/A; R27 ok; R28 N/A; R29 T9,T1,T2; R30 N/A; R31 N/A; R32 ok; R33 ok; R34 none; R35 VE28 deferred recorded; R36 none; R37 N/A; R38 N/A; R39 adjacent D-21 F1 fixed; R40 ok; R41 T2; R42 ok; R43 N/A; R44 ok; R45 ok; R46-R48 N/A; R49 T1,T2,T9; R50 T6; R51-R52 N/A; R53 ok; R54-R57 N/A.
RT1 ok; RT2 all testable; RT3 ok; RT4 N/A (T5); RT5 ok except T4; RT6 T11,T2; RT7 T3,T4,T5; RT8 ok; RT9 ok; RT10 T1,T2; RT11 T10.


## Environment Verification Report
Environment Verification (input): VE21 verified-local gx10; VE22 blocked-deferred SC46; VE23 fixture-verified; VE24 blocked-deferred SC47; VE25 verified P10; VE26 blocked-deferred (unit + setpriv cover); VE27 fixtures verified, two-host run not recorded in deviation log; VE28 narrowed by D-13; cross-gate --compare-identity not recorded.

## Resolution Status

Each fix is red-proved by mutation on a scratch copy, one mutation per
clause; the mutation and the assertion it reddened are named.

### T1 Critical — the host gate never ran the shipped (non-seams) configuration
- Action: `make host` runs `cargo test` without the seams first and checks that
  build reports `SEAMS=0`, then the seams run. tests/launcher.rs and
  tests/pin_firmware.rs gate themselves on the feature; build_info.rs's
  refusal test is `#[cfg(not(feature = "test-seams"))]`. UNIT-HOST 111.
- Red-proof: check-selftest `host-plain-seam-option` (the plain `from_args`
  drops `--root-prefix` and its value → "a release build took a seam
  option") and `host-plain-owner` (the plain owner (1, 1) →
  `without_seams_the_paths_are_fixed_and_the_owner_is_root ... FAILED`).
- Modified: Makefile `host:`, host/crates/kozane-vm/tests/{build_info,launcher,pin_firmware}.rs, tools/check-selftest.

### T2 Major — kzc and kzc-psk were never built without the seams
- Action: `make client` builds `-p kozane-client-cli --bins --release` with no
  features into its own target dir. Both binaries must print `SEAMS=0`, and
  `kzc --root-prefix /nonexistent up` must fail with `kzc: usage:`.
  The build_info.rs comment is corrected.
- Red-proof: check-selftest `client-ship-seams` (`--features test-seams` on
  that build → "client: shipped kzc has test seams").
- Modified: Makefile `client:`, client/crates/client-cli/tests/build_info.rs, tools/check-selftest.

### T3 Major — the encrypted-state check had no red-proof
- Action: check-selftest `kvm-swtpm-plaintext` (test-kvm, `kvm release boot`):
  the keyless swtpm also gets `--key`. Its needle
  `swtpm-state: plaintext: a copy of the state starts without the key` fired
  on gx10. The keyed half is unchanged.
- Modified: tools/check-selftest.

### S1 Major — `-device` values were checked by driver only (loader cpu-num/ELF)
- Action: `_DEVICE_KEYS` gives each driver its exact key set. A key outside
  it, a repeated key or a missing one is refused, and a loader needs
  `force-raw=on`. The rendered harness and launcher argv still give `[]`.
- Red-proof: removing the key-set call reddens 5 fixtures; dropping the
  `force-raw=on` test reddens "a loader with force-raw=off"; dropping the rng
  check reddens S3's fixture. VM-FIXTURES 44.
- Modified: tools/vm.py, tests/tools/test_vm.py.

### S2 Major — vm.conf's qemu/swtpm ran without the input checks
- Action: `files::check_program(path, &res.dir_owners())`, from `open_inputs`
  for both programs, before any child starts. It checks by path, not by fd
  (D-28): a regular, executable, non-symlink file that is not shared, and the
  file plus every directory from `/` owned by root (and, under the test
  seams, the input owner and the user namespace's overflow uid). A
  world-writable directory passes only when sticky.
- Allow side: the real QEMU in /opt under test-kvm, the stand-ins under the
  launcher tests' user namespace, and a 0755 scratch file under the sticky /tmp.
- Red-proof: no call → `a_qemu_program_others_can_write_is_refused_before_any_child_starts`;
  no directory mode test → `a_program_under_a_shared_directory_is_refused`;
  no exec-bit test → `a_program_that_is_not_executable_is_refused`;
  no directory owner test → `a_program_under_a_directory_of_another_uid_is_refused`.
  The file's own owner test is not provable with one uid (D-28, VE26).
- Modified: host/crates/kozane-vm/src/{files,main,resolve}.rs, tests/launcher.rs.

### S3 Minor — the rng backend was checked by head only
- Action: `-object` must be exactly `rng-random,id=,filename=/dev/urandom`.
  Red-proved with S1.

### S4 Minor — release keys were checked by fd, then re-read by name, unbounded
- Action: `release::verifying_from_hex`. pin-firmware reads both keys from the
  `open_checked` descriptors, bounded at 8 KiB. `load_verifying` stays a thin
  path wrapper for `release verify`.
- Red-proof: HEAD's pin.rs reddens `a_release_key_file_past_its_bound_is_refused`.

### S5 Minor — moved OSK copies were left in dead, unlocked frames
- Action: kzc's `session` calls `scrub_stack()` after every `step` (the first
  actions, `on_timer` and `on_datagram`). The FFI's `kz_client_on_datagram`
  and `kz_client_on_timer` call it after `with_handle` returns. D-13's
  wording is corrected.
- Deferred: an rp-residue case at the `Client` level.
  - Anti-Deferral check: Minor; not a security-boundary weakening (the fix
    only adds wiping).
  - Worst case: an OSK copy below the scrubbed region on kozane-net's stack.
    The OSK is the next minute's PSK, which kzc-psk also holds, and the
    process holds rp.sk itself.
  - Likelihood: the scrub covers 128 KiB below the calling frame, and these
    frames are shallow.
  - Cost to fix: a `Client`, a live responder and the scan harness's
    stack-window logic in rp-residue, about a day.
  - Decision: recorded in D-28, for M10's client work.

### T4 Minor — render_launcher_args's refusal had no red-proof
- Action: a test_vm fixture makes `machine` append `-gdb`. The render must
  raise `vm: forbidden argument` and write no file; the clean render still
  writes one.
- Red-proof: dropping the raise reddens "a forbidden launcher argv is not
  rendered".

### T5 Minor — tests/signal.rs could not tell the self-pipe from a pre-check
- Action: tests/signal_wake.rs. The polling thread blocks SIGTERM and waits
  until /proc shows it in ppoll; then the main thread raises SIGTERM. Only
  the pipe can wake the poll.
- Red-proof: a pre-check mutant (no wake fd, `terminated()` before poll)
  leaves signal.rs green and reddens signal_wake.rs ("the self-pipe did not
  wake it", after 5 s).

### T6 Minor — a missing image tree digested as empty
- Action: `tree_digest` refuses a tree that is not a directory, and
  `image_digest` refuses an unset `MICROKIT_SDK`. CHECK-MANIFEST-FIXTURES 29.
- Red-proof: HEAD's check-manifest fails both new fixtures (in the container).

### T7 Minor — the plan's manifest keys
- Action: UNIT-CLIENT, UNIT-CLIENT-CLI and UNIT-CLIENT-FFI are now per-crate
  keys. RP-INITIATOR-VECTORS is recorded as folded into
  UNIT-ROSENPASS-CORE (D-28).

### T8 Minor — deleting a netns cell changed no count
- Action: the outer test requires each of the nine `netns: <cell>` lines
  (`CELLS`).
- Red-proof: renaming one marker reddens "the cell `kzc restart ok` did not
  run".

### T9 Minor — manifest-kzc.txt's VE25 claim
- Action: the comment now says `make check` needs kernel WireGuard in a user
  namespace (P10).

### T10 Minor — units.rs leaked its directory on a panic
- Action: a `Scratch` drop guard.

### T11 Minor — keygen's unlink-on-failure was untested
- Action: a netns cell. With rp.pub already present, keygen fails and leaves
  none of wg.sk, wg.pub or rp.sk; with the way clear, it succeeds.
- Red-proof: no unlink → "keygen: var/lib/kozane-psk/wg.sk left after a
  failed run".

### F1 Minor — compare-identity sorted the values across keys
- Action: the tuple is in IDENTITY_KEYS order. Two fixtures: a QEMU-only
  difference with values that sort the other way, labelled correctly; and
  swapped values, refused.
- Red-proof: HEAD fails both.

### F2 Minor — host.md's swtpm_setup could not read the root-only key
- Action: `sudo -u kozane-swtpm swtpm_setup ... --keyfile-fd 3 ... 3<
  /etc/kozane/swtpm.key` from a root shell. The doc warns never to relax the
  key's owner or mode.

### F3 Minor — the reader's heartbeat tests used a format audit never prints
- Action: `is_heartbeat` matches `audit: Heartbeat ticks=`, the line audit
  prints. The tests, the QEMU stand-in and launcher.rs use those bytes. The
  old `src=timer` form is refused.

### Environment Verification Report (round 1)
- VE21 verified-local (gx10: test-kvm, kvm partition).
- VE22 blocked-deferred → SC46.
- VE23 verified (test_selftest_split `kvm beside solver`).
- VE24 blocked-deferred → SC47 (the C harness runs under valgrind instead).
- VE25 verified (P10).
- VE26 blocked-deferred (covered by injected-fstat unit tests and the setpriv
  noroot cell).
- VE27 verified-local: gx10 + z1mn `SDK-REPRO-ARTIFACTS 3` (D-28).
- VE28 narrowed by D-13 (systemd-analyze verify runs; runtime deferred).

---

# Review round 2 (fixes a5c7704..968b245)

## Changes from Previous Round
Round 1's fixes reviewed. F1, S2–S4, T1, T3–T10 resolved; F2, F3, S1, S5, T2, T11 continuing in part. New: three experts converged on bare `-device` fields (N2 = S6), and the S1 tightening pre-empted an existing self-test needle (N1).

## Functionality Findings (round 2)
- F3 [Minor] continuing: the heartbeat doc, tests, QEMU stand-in and launcher.rs use `seq=`, which audit never prints (crates/pds/audit/src/main.rs:507).
- N1 [Major] tools/check-selftest `vm-launcher-argv` injects `virtio-rng-device,id=selftest`, which the S1 key set now refuses at render time, so its needle never prints.
- N2 [Major] tools/vm.py:151 counts only `key=value` fields; a bare field (`noforce-raw`, `data-be`, `packed`) passes.
- N3 [Minor] (F2 continuing) sudo closes fd 3 (closefrom), so host.md's `--keyfile-fd 3` still fails.
- N4 [Minor] duplicated `#![cfg(feature = "test-seams")]` in launcher.rs and pin_firmware.rs.
- N5 [Minor][Adjacent] question: do the scrubs reach OSK copies in `session`'s own frame (inlined `step`)?
- N6 [Minor][Adjacent] signal_wake.rs hard-codes AArch64's ppoll number.
- N7 [Minor][Adjacent] test_vm.py's clean render is outside a check; a refusal is a traceback.

## Security Findings (round 2)
- S6 [Major] = N2, checked against QEMU v9.0.0 (util/qemu-option.c get_opt_name_value: a bare field is `<name>=on`, `no<name>` is `<name>=off`; the last value wins): `force-raw=on,noforce-raw` reaches the loader as `force-raw=off`. Question: pin the loader's `addr=` to the rendered set. escalate: false.
- S7 [Minor] = N5.
- S8 [Minor] check_program_dir accepts a sticky 022 directory in the shipped build; check_dir does not (R43).

## Testing Findings (round 2)
- TN1 [Major] the file-owner clause of check_program is provable with one uid: a file of ours directly in the root-owned sticky temp dir, with owners [0]. D-28's claim is wrong.
- TN2 [Major] the T11 cell leaves both key directories in place, so the successful keygen no longer runs the fresh-install branch of `key_dir`.
- TN3 [Major] S5's deferral fails the Anti-Deferral format and R34: deleting any new `scrub_stack()` call leaves every gate green; P42 can pin the call sites cheaply.
- TN4 [Minor] no launcher-level swtpm program cell; the not-a-regular-file clause and the symlink reason are unpinned.
- TN5 [Minor] the shipped kzc's `--root-prefix` refusal has no red-proof, and its echo text is literal in the recipe (not failure-only).
- TN6 [Minor] host src/tests.rs:80, :108 still return early under the seams and count in UNIT-HOST.
- TN7 [Minor] = N6.
- TN8 [Minor] the foreign-interface netns cell has no marker.
- TN9 [Minor] = N4.

## Recurring Issue Check (round 2)
- Functionality: R43 only narrowing except as noted; write-read: heartbeat bytes (F3); gate red-proof integrity (N1).
- Security: R3 S2 resolved; R43 S8; R49 S6, S7; R51 S4 resolved; R39 S7; R50 ok.
- Testing: R34 TN3; R44 ok; R50 TN1 precondition; RT6/RT7 TN1, TN4, TN5; RT8 ok; RT10 stated; RT11 ok.

## Resolution Status (round 2)

- **S6/N2 Major — bare device fields.** Fixed in tools/vm.py:
  - Every field after the driver must be `key=value`.
  - A launcher loader's `addr=` must be a launcher media address.
  - Four deny fixtures: `noforce-raw`, `packed`, an empty field, and a
    loader at an unrendered address.
  - Allow side: all 12 renderable argv (tcg/kvm, harness/launcher, rng
    on/off, media on/off) still give `[]`.
  - Red-proof: dropping the bare-field clause reddens 3 fixtures; dropping
    the address pin reddens 1. VM-FIXTURES 49.
- **N1 Major — `vm-launcher-argv` was pre-empted by S1.**
  - The drift is now a second rendered rng, which I1.2 admits.
  - test_vm pins that it stays admissible.
  - The case fires `vm-launcher: argv differs` on gx10.
- **TN1 Major — the file-owner clause is provable.**
  - `a_program_owned_by_another_uid_is_refused_though_its_directories_pass`
    uses a file directly in root's sticky /tmp with owners [0], paired
    with the allow side [0, me].
  - Red-proof: with the clause removed, the test fails. D-28 is corrected.
- **TN2 Major — fresh-install keygen.**
  - After the failure cell, both key directories are removed and checked
    gone, so the successful run creates them.
  - Red-proof: `mkdirat` at 0755 without the fchmod reddens
    `var/lib/kozane-psk` 0o40700.
- **TN3 Major / S7 / N5 — the shells' scrubs.**
  - kzc's `step` is an `#[inline(never)]` fn that runs the client call.
    The FFI's `with_handle` is `#[inline(never)]`.
  - P42 pins the 3 + 2 call sites, with two test_check_pins fixtures
    (CHECK-PINS-FIXTURES 426).
  - Self-test cases `client-shell-scrub-net` and `client-shell-scrub-ffi`
    each fire on gx10.
  - The Client-level residue measurement stays a residual (D-29).
    Anti-Deferral: the call sites the fix added are now gated, so its
    removal fails `make check`. What is left is measuring scrub depth at
    the Client level. Worst case: a copy below the scrubbed 128 KiB on
    kozane-net's stack. Likelihood: low (the frames are shallow). Cost: a
    Client and a responder in rp-residue, about a day. Owner: M10's
    client work.
- **S8 Minor — sticky directories in the shipped build.**
  - `check_program(…, sticky_ok)` with `resolve::SEAMS`.
  - `the_shipped_check_refuses_a_sticky_shared_directory` covers it.
  - Red-proof: the always-sticky mutant reddens it.
- **F3 Minor — heartbeat bytes.** The doc, the tests, the QEMU stand-in and
  launcher.rs now use `audit: Heartbeat ticks=60` and the line ending; the
  `seq=` form is gone.
- **N3 Minor (F2) — provisioning.** host.md uses `setpriv` (D-29).
- **N4/TN9 Minor.** The duplicate crate attribute is removed.
- **N6/TN7 Minor.** signal_wake.rs takes the poll syscall numbers per
  architecture, and `compile_error!` on any other.
- **N7 Minor.** The clean render is inside its check.
- **TN4 Minor.**
  - New tests: `a_swtpm_program_others_can_write_is_refused_before_any_child_starts`
    and `a_program_that_is_a_directory_is_refused`.
  - The symlink fixture is pinned to ELOOP.
  - Each is red-proved by removing its clause.
- **TN5 Minor.**
  - The recipe's `--root-prefix` lines are `@`-silent, so their text
    prints only on failure.
  - Self-test `client-ship-root-prefix` fires.
- **TN6 Minor.** Kept, because of P40 (D-29).
- **TN8 Minor.**
  - The foreign-interface cell prints `netns: a foreign kz0 is refused`,
    and CELLS has 10 entries.
  - Red-proof: dropping that marker reddens the outer test.

Found while fixing: under the self-test's own TMPDIR the two new owner
tests failed their /tmp precondition. They now use /tmp by name (D-29).

# Review round 3 (the owner's review of round 2)

## Findings
- R3-1 [Major] The bare-field and repeated-key refusal covered `-device`
  only. `-machine …,secure`, `-chardev …,mux`, `-machine …,mem-merge=on`,
  `-machine …,dump-guest-core=on` and `-chardev …,signal=on` all gave
  `violations() == []`.
- R3-2 [Medium] The scrub's precondition, `#[inline(never)]` on `step` and
  `with_handle`, was ungated. P42 stayed green with both removed.
- Note: host file tests failed where `/` shows as uid 65534.

## Resolution Status (round 3)
- R3-1:
  - `_opts_shape_problems` runs on every QemuOpts option. It refuses a
    bare field after the head, an empty field, and a repeated key
    (`hostfwd` excepted for netdev).
  - `-machine` must equal a rendered machine string. The console chardev
    must be the rendered one exactly. The TPM socket must have its exact
    key set.
  - Seven fixtures, the five reported patterns plus an unrendered machine
    property and an extra TPM socket key. VM-FIXTURES 56.
  - Every renderable argv, and both swtpm forms, still give `[]`.
  - Red-proof: disabling the shape check reddens the 5 reported patterns,
    plus the existing repeated device key. Disabling the exact machine
    match reddens its fixture, and so does disabling the socket key set.
- R3-2:
  - P42 requires `#[inline(never)]` on the line directly above each
    helper.
  - Four test_check_pins fixtures, removed and `inline(always)` for each
    helper. Each fails P42 on a scratch copy (CHECK-PINS-FIXTURES 430).
- Note: `owners()` in the host file tests includes the overflow uid.

# Review round 4 (the owner's review of round 3)

## Findings
- R4-1 [Major] Device keys were fixed but not their values. The outside
  and inside NICs' netdevs could be swapped, and two launcher loaders'
  fd/address pairs too.
- R4-2 [Medium] Fixed values went unchecked:
  - `-m 64G`, `-m size=2G,maxmem=4G`;
  - `-tpmdev …,chardev=serial0`, `-tpmdev …,x-data=on`;
  - TCG/KVM machine string or CPU mismatches.
- R4-3 [Testing] The host file tests depended on the umask and on uid 0
  owning /tmp.

## Resolution Status (round 4)
- **R4-1:**
  - Exact device strings, and the launcher loaders' (fd, address) pairs
    derived from LAUNCHER_QEMU_FDS and launcher_addrs().
  - The launcher's bios, taps, TPM socket and swtpm fds are exact too.
  - Fixtures: NICs swapped, media swapped, rng on another bus, TPM on
    another backend, launcher taps swapped, firmware, TPM socket and swtpm
    ctrl and key on other fds.
- **R4-2:**
  - `-m` is `MEMORY`, and `-tpmdev` is `TPMDEV`.
  - The once-only options are given once, and the machine string and CPU
    match the accelerator.
  - Fixtures: `-m 64G`, `-m size=2G,maxmem=4G`, the tpmdev on serial0,
    the tpmdev with `x-data`, kvm's machine under tcg, tcg's CPU under
    kvm, `-m` given twice.
- **Red-proof:** each of the 12 clauses was disabled on its own, and each
  reddened its own fixtures (exact devices 3, launcher loaders 2, tpmdev 2,
  memory 2, launcher taps 1, swtpm key fd 1, once 1, triple machine 1,
  triple cpu 1, bios fd 1, TPM socket fd 1, swtpm ctrl fd 1).
- **Allow side:** all 12 renderable argv, both swtpm forms and
  render_launcher_args still pass. VM-FIXTURES 72.
- **R4-3:**
  - The scratch is 0755 whatever the umask.
  - `root_like()` is 0 and the overflow uid. The tests pass with umask 002
    and a foreign TMPDIR.
  - Under `unshare -r` (test uid 0) the two other-uid tests fail on their
    precondition, as designed.

# Review round 5 (the owner's review of round 4)

## Findings
- R5-1 [Major] "Exactly once" refused only repeats. Dropping any of these
  still gave `[]`:
  - `-machine`, `-accel`, `-cpu`, `-m`, `-bios`, `-serial`, `-monitor`,
    `-display`;
  - the launcher's `-overcommit`;
  - swtpm's `--tpm2`, `--tpmstate`, `--ctrl`.

## Resolution Status (round 5)
- R5-1: every always-rendered part is required exactly once. That covers
  `_ONCE`, the launcher's overcommit (refused in the harness), tpmdev, both
  chardevs, the TPM device, both NICs, both netdevs and each launcher
  medium. swtpm's four options are likewise required once.
- Fixtures: one per dropped part (23), and `-overcommit` in the harness
  form. VM-FIXTURES 95.
- Allow side: every renderable argv, both swtpm forms and
  render_launcher_args still pass.
- Red-proof: each count clause relaxed to `> 1` reddens exactly its
  fixtures:
  - once 8, overcommit 2, one-each 5, TPM socket 1, netdev ids 2,
    launcher loaders 1, swtpm 4.
  - All 25 vm.py clauses were re-run under `python3 -B` after a stale
    `.pyc` was found to have merged equal-size mutants (D-29).
  - Two device-level clauses were unreachable behind the shape check and
    were removed.

# Review round 6 (the owner's review of round 5)

## Findings
- R6-1 [Medium] The launcher's swtpm `--tpmstate` value was unpinned.
  `dir=/tmp/attacker` gave `[]`, and `VmArgs::parse` accepted a field moved
  with it.
- R6-2 [Minor] Either rng half could be dropped alone.

## Resolution Status (round 6)
- R6-1:
  - vm.py: the launcher `--tpmstate` must be `dir=` LAUNCHER_SWTPM_STATE.
    Fixture `dir=/tmp/attacker`; the test's launcher swtpm uses the real
    state dir.
  - vmargs.rs: `swtpm_state` must be `SWTPM_STATE`. A unit test moves both
    the field and the argv. The old argv-only case now edits the argv
    alone, so it still proves the mismatch check.
  - Red-proof: dropping each pin reddens its own test.
- R6-2:
  - The launcher needs exactly one backend and at least one rng device;
    the harness needs both or neither.
  - Four fixtures: each half dropped, in each form. `rng=False` stays
    admissible.
  - Red-proof: relaxing the backend count reddens 1 fixture, and removing
    the pairing reddens 3.
- VM-FIXTURES 101. All renderable argv and render_launcher_args pass.
