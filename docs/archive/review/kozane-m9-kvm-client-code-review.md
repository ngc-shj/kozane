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
