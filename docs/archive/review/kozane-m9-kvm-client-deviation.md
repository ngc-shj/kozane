# Coding Deviation Log: kozane-m9-kvm-client

Plan: [kozane-m9-kvm-client-plan.md](kozane-m9-kvm-client-plan.md), locked
at cc83bf1. Entries are numbered D-1, D-2, …; probe observations are listed
by probe ID.

## Slice 0: probes

### P10 — kernel WireGuard in the workers' user namespaces (pass)

- **Hosts:** gx10, z1mn and mrx33, in today's `kozane-dev` image.
- **Command:** inside `unshare -rn`, `ip link add … type wireguard`, then
  `wg set … peer … preshared-key …` (`WG_CMD_SET_DEVICE`), then
  `wg show … preshared-keys`.
- **Result:** works on all three hosts. VE25 admits all three, so
  `test-kzc` can run on any of them.

### P5 — gx10 CPU features (recorded)

- `/proc/cpuinfo` has no `rng` flag, so FEAT_RNG is absent and RNDR
  faults under `-cpu host` too. RM9-2 does not arise on gx10.
- KVM's boot log has `nv: … trap handlers`, so the kernel carries nested
  support. `kvm-arm.mode` is unset, and FEAT_NV2 is not visible from user
  space. Enabling it is the owner's host decision (SC46).
- The boot log also has `disabling GICv2 emulation` and
  `GICv3: no GICV resource entry` (D9).

## Slice 0: image (C15, D2, D8, D9)

### D-1 — the SDK stage and its inputs

- **The board.** `docker/sdk/kozane-board.patch` adds
  `kozane_virt_aarch64_el1` to Microkit's `build_sdk.py`. It is Microkit's
  `qemu_virt_aarch64_el1` with three changes:
  - `QEMU_GIC_VERSION=3`, which sets `KernelArmGicV3`;
  - no SMP configs;
  - a `QEMU_DTB` the stage dumps itself: stock QEMU 9.0.0, machine
    `virt-9.0,secure=off,virtualization=off,gic-version=3`, `-cpu
    cortex-a72`, `-m 2048`.
- **Why the DTB is dumped here.** seL4's `qemu-arm-virt` config otherwise
  runs whatever QEMU it finds, on machine `virt`, to produce the DTB
  (`src/plat/qemu-arm-virt/config.cmake`). That makes QEMU a build input,
  which F2.6 suspected and the source confirms. The stage pins it.
- **Microkit already exports the physical timer.** Its own EL1 board sets
  `KernelArmExportPTMRUser` ("There is no peripheral timer, so we use the
  ARM architectural timer"). D13 leans on the same export.
- **Python modules come from the apt snapshot** (`python3-ply`, `-jinja2`,
  `-yaml`, `-lxml`, `-pyfdt`, `-setuptools`, `-jsonschema`), not from pip.
  The snapshot pins them, so there is no unhashed pip install (S2.12).
- **Rust.** Rust 1.94.0 (the tool's `rust-version`), with targets
  `aarch64-unknown-none` and the host's musl target. The crates resolve
  `--locked` from Microkit's `Cargo.lock`.
- **The sources** are GitHub tag archives, checked by sha256:
  - Microkit 2.3.1: `67ae0346…25c22f`
  - seL4 16.0.0: `d6d2b086…d48d40`
- **The Arm GNU toolchain** moves into an `armgcc` stage shared by the SDK
  stage and the dev image. It is one pin, not two (R2).
- **The stock SDK's GICv2 `gen_config.h`** is kept as
  `tests/fixtures/kernel-config/gicv2-el1-gen_config.h`, the red-proof
  input for `kernel-config` (T2.16).

### P1/P2/P4 (early, with the SDK's `hello` example, no U-Boot)

The `hello` example was built for `kozane_virt_aarch64_el1` (debug) and
loaded with `-device loader` at `0x70000000`. Machine:
`virt-9.0,gic-version=3`, `-m 2048`.

| Accelerator | Machine extras | Result |
|---|---|---|
| `kvm`, `-cpu host` (gx10) | none | Entered at EL1; `PSCI version is 1.3`; reached `hello, world` |
| `tcg`, `-cpu cortex-a72` | none | Entered at EL1; the loader's `smc` (the PSCI version query) is UNDEFINED (`esr_el1` 0x02000000, EC 0) |
| `tcg`, `-cpu cortex-a72` | `virtualization=on` | Entered at EL2; the loader's GICv2-only distributor/CPU-interface setup faults on GICv3 (`GICC_BASE` is not mapped) |
| `tcg`, `-cpu cortex-a72` | `virtualization=on`, loader patched (D-2) | EL2 → EL1; `PSCI version is 1.1`; reached `hello, world` |

So KVM handles an EL1 SMC as PSCI (P4 (i), still to be confirmed with the
supervisor's reset), and TCG needs EL2 for it (P4 (ii)).

### D-2 — TCG boots enter at EL2 (P4 refutes part of D2, C1 and C3)

- **What changes.** D2 said "`virtualization=on` only for the TCG reset
  cases; every other TCG boot enters at EL1". That cannot hold. Microkit's
  loader asks PSCI for its version through `smc` on every boot, before
  seL4 starts. QEMU's TCG answers PSCI over SMC only when the machine has
  EL2 (or EL3), so a TCG boot at EL1 faults in the loader.
- **The new rule:**
  - `vm.machine("tcg", …)` always adds `virtualization=on`;
  - `vm.machine("kvm", …)` never does;
  - I1.1's allowed difference is now `-accel`, `-cpu` and `virtualization`, for every TCG boot. `reset_case` goes away.
- **The loader fix.** `docker/sdk/kozane-board.patch` also makes the
  loader's `configure_gicv2` a no-op under `CONFIG_ARM_GIC_V3_SUPPORT`. On
  QEMU `virt` with no EL3, every interrupt is already Group 1 NS, and the
  GICv2 setup would fault on a GICv3 machine.
- **What production keeps.** The EL1 entry path that production uses
  (U-Boot and the loader at EL1, PSCI through KVM) runs only under KVM.
  `test-kvm` already holds a boot-path-sensitive case for each concern:
  release boot, seal and unseal, a `kzc` session, HTTPS, a policy update,
  a reset, the tick rate (T2.17). The TCG suite tests the same image
  entered at EL2, with the loader dropping to EL1 before seL4.
- **Contracts sent back to `pending`, then re-locked with this text:**
  C1 (I1.1, I1.2, `reset_case`) and C3 (the TCG column).

## C7: the initiator (batch 1)

### D-3 — the initiator's API and error mapping, against C7's text

- **Return types.**
  - `start` returns `[u8; INIT_HELLO_LEN]`, and `handle_resp_hello` returns
    `([u8; INIT_CONF_LEN], Osk)`: the sealed bytes, not the wire structs;
  - `new` returns `Result`, because building the hash domains can fail;
  - `Retransmit` is a struct holding the buffer and its length, which keeps
    clippy's `large_enum_variant` quiet.
- **Errors.** A message that names no live handshake is
  `Error::UnknownPeer`, upstream's "non-existent session": another session
  id, the wrong phase, or an expired handshake. `StateError` keeps the
  finer reason. New `Error` variants would break `pq`'s exhaustive
  `reject_event` match for no behavioural gain.
- **Jitter.** `tick` has no RNG. So 16 jitter bytes are drawn from
  `seams.rng` whenever a message is stored, and consumed one per retry,
  which gives 8-bit resolution of upstream's 0.5 jitter factor.
- **RNG draw order in `start`:**
  1. the cookie value, 16 bytes;
  2. `sidi`, 4 bytes;
  3. the Kyber seed, 64 bytes;
  4. the McEliece encapsulation draw;
  5. the jitter, 16 bytes.

  `rp-vectors --initiator` (C7 batch 2) reproduces upstream's draws in
  this order, or the order is changed there and recorded.
- **The envelope mac** is checked before any state or crypto work.
  Upstream checks it after the RespHello's crypto, so this is stricter.
- **Constants**, each with an upstream citation in `initiator_state.rs`
  (rosenpass `9e72f1eb`, `rosenpass/src/protocol/constants.rs`):

  | Constant | Value | Upstream line |
  |---|---|---|
  | retransmit delay, begin | 0.5 s | 53 |
  | retransmit delay, growth | ×2 | 50 |
  | retransmit delay, end | 10 s | 56 |
  | jitter | 0.5 | 60 |
  | reject after | 180 s | 28 |
  | rekey after (initiator) | 130 s | 19 |

  The 180 s is `wg_core::REJECT_AFTER_TIME_NS`'s value, the L8 window.
- **Tests.** 26 new unit tests. McEliece in them is a stand-in
  (`FakeMce`/`FakeDecaps`), because the vectors hold no secret key for
  either side. Real McEliece is covered by the KAT and by P7's oracle
  case against upstream.

## C2: the boot chain without TF-A

### D-4 — C2's member set and the disposition of each member

The command, run at cc83bf1 plus the slice-0 work:

`git grep -lIiE 'tf-a|tfa|fip_images|expected_pcr0|FIRMWARE_VARIANTS|firmware_variant|flash\.bin|flash-image|\bBL(1|2|31|33)\b|libtpm|libeventlog|mbedtls' -- . ':!docs/archive'`

It matches 29 files, and 10 more under `docs/archive`. The archive is the
milestone history: its files stay as they are.

| Member | Disposition |
|---|---|
| `Makefile` | `firmware` builds U-Boot only; the TF-A recipe and its variables go; `firmware`/`firmware_measure` name the two `u-boot.bin` |
| `support/tf-a/build-flags`, `support/tf-a/tf-a-qemu-discrete-tpm.patch`, `support/tf-a/libtpm-fifo-mmio.patch` | delete |
| `third_party/libtpm/`, `third_party/libeventlog/` | delete (only TF-A linked them) |
| `THIRD_PARTY.md` | drop the TF-A, Mbed TLS, libTPM and libEventLog rows |
| `tools/flash-image` | delete |
| `tests/tools/fip_fixture.py` | delete, with its users in `test_measure.py`, `test_package.py`, `test_release.py` |
| `tools/measure.py` | PCR 0's FIP model goes; `expected_pcrs` returns zero for PCRs 0–7 |
| `tests/tools/test_measure.py` | the FIP and PCR 0 fixtures go; a fixture pins PCRs 0–7 at zero |
| `tools/package`, `tools/release.py`, `tools/release/src/manifest.rs` | `flash.bin` → `u-boot.bin` (the release's firmware entry); `kozane_vm_sha256` comes with C4 |
| `tests/tools/test_package.py`, `tests/tools/test_release.py` | follow |
| `tools/repro` | the TF-A artifacts leave the list; the U-Boot ones stay |
| `tools/check-pins` | P24 rewritten (C12); TF-A and FIP pins go |
| `tests/tools/test_check_pins.py` | follow |
| `tools/check-selftest` | the TF-A and firmware-variant injections go; `repro-uboot` and the PCR 0 and TPM-startup cases come in (C2, C12) |
| `tests/integration/run.py` | `qemu_machine` becomes `vm.machine`; `FIRMWARE`/`FIRMWARE_MEASURE` name the two `u-boot.bin`; the firmware-variant cases go; the PCR 3 injection is generalised to PCR 0 |
| `support/u-boot/boot.cmd` | `tpm2 startup TPM2_SU_CLEAR \|\| REFUSE` after `tpm2 init`; the TF-A comment goes |
| `crates/tpm2-wire/src/lib.rs`, `crates/pds/supervisor/src/reset.rs`, `crates/tpm2/tests/swtpm_interop.rs`, `tools/mksecrets/src/tests.rs` | comments only: "TF-A's" → the new chain |
| `docs/PLAN.md` | the M9 row (C13); the M7 row stays history |
| `docker/Dockerfile` | already changed (D-1): no `/opt/tf-a`, no sp804 |
| `docker/keys/microkit-release.asc` | delete. The prebuilt SDK it verified is no longer downloaded. The grep misses it: it names no TF-A term |

The round-1 hint list also named three members the grep does not match,
because none of them names a TF-A term. Each was checked by hand:

| Member | Finding |
|---|---|
| `README.md` | the measured-boot row and the residual risks change with C5 |
| `policy/laws.toml` | no TF-A text; the timer change is C14 |
| `tools/mksecrets/src/main.rs` | no match beyond its tests |

## C8, C9: the client library and the C ABI (batch 1)

### D-5 — decisions beyond C8/C9's text

- **`Initiator` holds no key references** (a change to C7's API). Owning
  them would have needed an unsafe self-referential holder in the client.
  - `InitiatorKeys { spki, spkr }` is passed per call to `start` and
    `handle_resp_hello`.
  - `new(&keys)` keeps only derived values: the initial chaining key, the
    peer id, the two mac keys and the cookie key.
  - Each call checks that the keys it was given are the ones `new` saw.
    The check compares the peer id and `KH(ck_init, spkr)` in constant
    time. A mismatch is `Error::Internal`, and the state stays unchanged.
  - In `handle_resp_hello` the check runs after the mac and the RHI2 step,
    so an unauthenticated datagram never triggers a hash over the whole
    key.
  - `client`'s only `unsafe` is the three libc calls in `lock_memory`,
    each with a SAFETY comment.
- **`Client::new` takes no time,** so it returns `[Scrub]` alone. The
  first `Send` comes from the first `on_timer`.
- **The scrub deadline** is the last authenticated RespHello plus
  `wg_core::REJECT_AFTER_TIME_NS`.
  - There is no deadline before the first exchange or after a scrub: the
    peer holds a random PSK then, and no keypair can exist on it.
  - A due scrub is always returned alone. `on_datagram` drops the
    datagram in that case, and retransmission recovers it. So a scrub can
    never be lost behind an RNG or protocol error.
  - `MAX_ACTIONS` is 2 (`InstallPsk`, then `Send(InitConf)`).
- **Rekey** follows the initiator's `rekey_at` (130 s after EmptyData). A
  handshake that dies returns to Idle and restarts at once.
- **Errors:** `Rng` (fatal to the caller), `Protocol`, `Clock` (time
  running backwards is refused), `InvalidKey`, `Memory` (an `mlock`
  failure), `Full`.
- **The FFI adds status codes:** `KZ_ERR_RNG`, `KZ_ERR_REJECTED`,
  `KZ_ERR_CLOCK` and `KZ_ERR_MEMORY`.
- **The queue.** Its capacity is `KZ_MAX_ACTIONS`, which is one call's
  output, so `on_*` returns `KZ_ERR_BUSY` whenever the queue is not empty.
- **A too-small buffer** returns `KZ_ERR_BUFFER`, writes the needed kind
  and length, and keeps the action queued.
- **A panicked handle is poisoned:** every call except `free` returns
  `KZ_ERR_INTERNAL` from then on.
- **`mlock` covers** the secret key and the whole FFI handle: the PSK
  slots and the handshake's secrets. Pages stay locked after they are
  freed, because `mlock` does not nest. A non-unix build is a
  `compile_error!` for now (the shells, SC47).
- **The C header** is hand-written to cbindgen's style. The cbindgen gate
  (C9) regenerates it once the image carries cbindgen.
- **The C harness** checks the buffer, busy, rejection, clock, panic and
  free paths. The full exchange through the FFI is the Rust-side test
  `exchange.rs`, against real McEliece and Kyber on both sides.
- **valgrind** runs as `--error-exitcode=1 --leak-check=full` with no
  suppression file, and is clean.
- **Residual:** a Rust move of a `Secret` can leave a stale copy on the
  stack. That is not addressed here (S1.14's remainder).
- **Lock:** all 114 external packages in `client/Cargo.lock` match the
  root lock by version and checksum. D12's pin gate is still to be wired.

### D-6 — C2 tooling: decisions beyond the plan's text

- **The swtpm state key** (H2, C4).
  - The harness writes one key per run: `tmp/swtpm.key`, 64 hex digits
    from `secrets.token_hex(32)`, created `O_EXCL` with mode 0600 inside
    the run's 0700 `mkdtemp`, and removed with it.
  - Every swtpm uses that key:
    - `swtpm_setup --keyfile <key> --cipher aes-256-cbc`;
    - the provisioning server: `vm.swtpm(...)` plus `--server` and
      `--flags`;
    - the per-boot `Swtpm`.
  - `tools/provision` only talks to a running swtpm through a TCTI and
    never creates state, so it needed no change.
  - Probed with swtpm 0.7.1:
    - `--keyfile` wants a hex key; a binary key silently produces no
      permall;
    - `file=…,mode=aes-256-cbc` reads the hex file;
    - a wrong key fails `CMD_INIT` with 0x101.
  - `make run` now takes `TPM_KEY`, the operator's key file.
- **The TPM-startup refusal.** Dropping `|| REFUSE` from the startup line
  does not make the loader start: the boot still refuses at the first
  `pcr_extend`, because the TPM never started. So the case asserts that no
  TPM command follows a failed `TPM2_Startup`. The self-test injection
  `tpm-startup-refuse` uses that failure text as its needle,
  `tpm-startup: a TPM command after the failed startup`. The plan's
  needle (`tpm-startup: loader started`) could not fire.
- **The PCR injection** is generalised to any PCR. The sealed-boot case
  runs it for PCR 0 (the plan's "PCR 0 deny") and keeps PCR 3. A boot that
  unseals fails with `pcr0-deny: unsealed …`.
- **P24** requires:
  - exactly one uncommented `tpm2 startup TPM2_SU_CLEAR || REFUSE`, after
    `tpm2 init` and before the first `pcr_extend`;
  - `"-bios"` exactly once in `tools/vm.py` (inside `machine`), and never
    in `run.py`.

  The tree-wide "`-bios` outside vm.py" ban is left to C12's new pin.
- **P25** additionally reads `vm.py`'s `CPU` table by AST:
  `{"tcg": "cortex-a72", "kvm": "host"}`.
- **Counts:**

  | Key | Change | How |
  |---|---|---|
  | MEASURE-FIXTURES | 75 → 66 | run |
  | RELEASE-FIXTURES | 25 → 24 | run |
  | VM-FIXTURES | 22 (new) | run |
  | REPRO-ARTIFACTS | 28 → 22 | reasoned: 2 + 18 PDs + 2 `u-boot.bin` |
  | INTEGRATION-CASES | 134 → 130 | reasoned: −6 firmware-variant cases, +1 PCR 0, +1 TPM startup |

  CHECK-PINS-FIXTURES is still to be measured.

## C14: the generic timer

### D-7 — the timer PD on the physical timer; `audit`'s tick channel later

- **The source fixes the timer.** seL4 16.0.0 sets `CNTKCTL_EL1` once for
  every thread (`src/arch/arm/armv/armv8-a/64/user_access.c`,
  `check_export_arch_timer`). With `EXPORT_PTMR_USER`, any EL0 thread may
  access CNTP_\*, which confirms S2.2 and D13. The kernel itself keeps the
  virtual timer. So `timer` drives the EL1 physical timer, PPI 30
  (`irq="30"`).
  - It programs CNTP_CVAL one counter-frequency period ahead, so it ticks
    once a second.
  - It advances the deadline from the previous deadline, not from now, so
    the rate does not drift.
  - A late interrupt skips the missed ticks instead of bursting them.
- **What changed:**
  - `layout::TIMER_FREQ_HZ` (the sp804's 1 MHz) is gone; the rate comes
    from CNTFRQ_EL0;
  - `TIMER_IRQ` is 30;
  - `kozane.system` and `laws.toml` drop `timer_mmio`.
- **Deferred to the heartbeat (C3):** channel 6 to `audit`. `audit` has no
  handler for it yet, and its event wiring (audit-event, Kani, ct-shape,
  audit-verify) comes with the `Heartbeat` event.
- **Deferred to C12's laws work:** the `tools/laws/tests/fixtures/timer_*`
  pairs. They exercise the laws checker's timer-role rules with their own
  device MR, and change with the non-vacuous exemption.

### P14 / D-8 — guest RAM locking only in the launcher form

- **Observed on gx10:** with `-overcommit mem-lock=on` and a 2 GiB guest,
  QEMU printed nothing for 86 s. The time was almost all system time,
  spent faulting in and locking the guest's RAM. gx10 runs under memory
  pressure (VE23).
- **`vm.machine` therefore adds `mem-lock=on` only in the launcher form**
  (production, H2). The harness form leaves it out: it is a host residency
  property with no effect on the guest, and at about 130 boots per suite
  it would cost hours.
- **Pinned:** a `test_vm` fixture holds the split. VM-FIXTURES is 23.
- **host.md** states the cost: locking takes time proportional to guest
  RAM at every start, and more under host memory pressure.

### D-9 — the PD stack top moves with the EL1 board's 47-bit vspace

- **The symptom.** The first U-Boot boot on the new platform reached the
  PDs, then `pqkey` took a VM fault (label 6) when its stack probe painted
  below `cpu::STACK_TOP`.
- **The cause.** Microkit places each PD's IPC buffer at the top page of
  the user vspace, then a guard page, then the stack. The vspace differs
  between the two boards' `address_space_constants.json`:

  | Board | `vspace_user_top` | `vspace_index_bits` | Stack top |
  |---|---|---|---|
  | `qemu_virt_aarch64` (EL2) | 2^40 − 1 | 10 | `0xff_ffff_e000` (the old constant) |
  | `kozane_virt_aarch64_el1` | 2^47 − 1 | 9 | `0x7fff_ffff_e000` |

  This is one of the board-metadata differences P1 was to record (F1.23).
- **The fix.** `crates/cpu` (the probe) and `tools/laws` (the map check)
  both take `0x7fff_ffff_e000`, each with the reason.
- **Still to do:** C12 pins the two constants equal to each other and to
  the SDK's `address_space_constants.json`, so a board change cannot leave
  them stale again.

## Slice 0: boots on the new platform (P1–P4)

| Probe | Accelerator | Cases | Result |
|---|---|---|---|
| P1, P3 | TCG, `virtualization=on` | raw frames, measured boot, sealed boot (PCR 0 and PCR 3 injections refuse to unseal), tpm startup (refusal) | pass |
| P2, P3, P4 (i) | KVM on gx10, `-cpu host` (Linux 6.17) | raw frames, sealed boot, supervisor (in-guest PSCI reset, fault records) | pass |
| P4 (ii) | TCG, `virtualization=on` | supervisor resets (the `hello` probe and the loader-only boot) | pass |

**C3: row 1 applies.** Both accelerators deliver the supervisor's
in-guest reset, so there is no halt mode and no watchdog restart. The
`Heartbeat` stays: it carries the tick count for C6's rate case, and it
is the operator's liveness signal.

**`query-kvm` is not asserted yet (C6).** The KVM runs above ran with
`KOZANE_ACCEL=kvm` through `vm.machine`.

### D-10 — the serial chardev is not a signal source

- **The symptom.** The first measured boot ended right after U-Boot's
  `DRAM:` line, with `qemu-system-aarch64: terminating on signal 2`.
- **The cause.** `-serial stdio` makes the stdio chardev turn a 0x03 on
  the console into a SIGINT to QEMU. The S-BOOT-5 check sends exactly that
  byte, to prove U-Boot ignores Ctrl-C. The old `mon:stdio` multiplexer
  handled the byte differently.
- **The fix.** `vm.machine` renders
  `-chardev stdio,id=serial0,signal=off -serial chardev:serial0`.
  `violations` refuses a stdio chardev without `signal=off`, and a
  `test_vm` fixture pins that (VM-FIXTURES is 24). The launcher form gets
  the same, so console input can never stop a production VM.

## C3: the heartbeat

### D-11 — the Heartbeat is audit's own line, not a ring event

- **Not an `Event` variant.** A ring code that decoded to "Heartbeat"
  would let a tainted producer print `audit: src=… Heartbeat …` and fake
  liveness while the timer is stopped.
- **Instead:**
  - `audit-event` reserves the name (`HEARTBEAT`). A unit test over every
    u16 code and a Kani harness (`no_code_decodes_as_the_heartbeat`) prove
    that no ring code decodes to it.
  - `audit-core`'s `Heartbeat::tick` decides when a line is due, also with
    a Kani harness.
  - `audit` prints `audit: Heartbeat ticks=<n>` through `Console::line`,
    so the line is hash-chained and checkpointed like every other line.
  - Every ring line starts `audit: src=`, so no producer can print this
    one.
- **Values:**
  - `layout::timer::CH_AUDIT` = 6, `layout::audit::CH_TIMER` = 12 (audit's
    ids 1–11 are taken);
  - `HEARTBEAT_S` = 60: one line a minute, so an idle node signs a
    checkpoint about once an hour.
  - The fault-inject timer variant faults at tick 30, so it never prints a
    heartbeat.
- **run.py:** one adjacency pattern (`peer_endpoint`) now admits up to two
  `checkpoint`/`Heartbeat` lines between the IP and port lines. Every
  other `audit:` count names its `src=`.
- **Counts:**
  - UNIT-AUDIT-EVENT 69, UNIT-AUDIT-CORE 16;
  - KANI-AUDIT-EVENT 7, KANI-AUDIT-CORE 5, KANI-HARNESSES +2;
  - AUDIT-VERIFY-FIXTURES 43.
- **The laws `stack_guard_*` fixtures** moved to the new stack top (D-9):
  `0x7fff_ffff_b000` deny, `0x7fff_ffff_a000` allow.

## C4: the launcher

### D-12 — `kozane-vm`: decisions beyond C4's text

- **Program paths come from a root-owned file.** QEMU's and swtpm's paths
  are read from `/etc/kozane/vm.conf` (`qemu=`, `swtpm=`, and the two
  bridges), not from the environment. The root binary never takes a
  program path from its environment. The tests use the same file under
  `--root-prefix`.
- **Fixed fd layout.** `vm.py` renders the final launcher argv into
  `vm-args.json`:
  - QEMU: firmware 3, TPM 4, outside tap 5, inside tap 6, media 7–14;
  - swtpm: ctrl 3, key 4.

  The launcher moves each resource onto its number. Only swtpm's `dir=`
  is rewritten at run time, and only under `--root-prefix`.
- **Every boot medium goes in a sealed memfd,** not only the firmware.
  `kozane-qemu` cannot reopen a root-owned 0600 file through `/dev/fd/N`,
  and the seal also fixes the bytes QEMU reads.
- **The serial reader** writes `/var/log/kozane/console.log` (root, 0600),
  not the journal, which keeps console access root-only. It sends root
  one byte per heartbeat.
- **`pin-firmware`** also checks the release's `u-boot.bin` against the
  signed `firmware_sha256`. It accepts an equal `RELEASE_SEQ` (a
  re-install) and refuses a lower one.
- **`RLIMIT_MEMLOCK`** is set to unlimited, because QEMU's `mlockall`
  locks its own memory too.
- **`--build-info`** prints `SEAMS=` and `VM_ARGS_SHA256`.
- **The release** carries `kozane-vm`. `release.py make` requires
  `SEAMS=0` from that copy before it signs `kozane_vm_sha256`, and
  `verify` checks it again.
- **The `host/` lock** matches `tools/release/Cargo.lock` for every shared
  crate. It differs from the root lock exactly where `tools/release`
  already does: `cc`, `find-msvc-tools`, and `zeroize` 1.9.1 against
  root's 1.8.1. D12's lock pin compares `host/` with `tools/release`.
- **Make:**
  - `host-launcher` renders `vm-args.json` and builds the release
    binary; `test` and `release` depend on it;
  - `host` is the gate: clippy with and without seams, the seams tests,
    the `SEAMS=` marker check on both builds, and UNIT-HOST 47.
  - Adding `host` to `check` waits for its self-test case (C12).
- **Counts:** RELEASE-FIXTURES 28, UNIT-RELEASE-TOOL 18, UNIT-HOST 47.
- **Not verified yet:**
  - a real QEMU and swtpm started through the launcher (C6's release
    boot);
  - the production credential path and `RLIMIT_MEMLOCK` as real root
    (VE26);
  - the systemd unit (VE28).

## C10: `kzc`, `kzc-psk`

### D-13 — decisions beyond C10, D6 and D7

- **The ownership mark is set after creation.** The kernel ignores
  `IFLA_IFALIAS` in a creating `RTM_NEWLINK`. A `SIGKILL` between the
  creation and the mark leaves an unmarked interface, which the next start
  refuses as foreign (fail-closed, residual).
- **`allowed_ips`:**
  - `/0` is refused: it needs policy routing for the tunnel's own
    traffic, which `kzc-psk` does not set up;
  - host bits and overlaps are refused;
  - routes are `CREATE|EXCL`, so an existing route is never replaced.
- **`client.conf`:** every key is required, a repeat is refused, and
  endpoints are IP literals (no DNS).
- **IPC.** Each `Install`/`Scrub` gets a one-byte ack, and `kzc` waits for
  it before its next action. So a PSK is in place before the InitConf
  leaves.
- **`Install` uses `WGPEER_F_UPDATE_ONLY`,** so it never creates a peer.
- **`NETLINK_CAP_ACK`** keeps the kernel from echoing keys in its acks,
  and the buffers are wiped.
- **The digests printed at start (C13):** `kzc-psk` prints its own and the
  gateway's `wg_pub`; `kzc` prints the gateway's Rosenpass digest.
- **`keygen`** accepts a key directory that already exists (systemd's
  `StateDirectory=` may create it first) and corrects its owner and mode
  through the fd. It creates all four key files `O_EXCL` before writing,
  and unlinks them on failure.
- **`ExecStopPost=`** is `kzc-psk cleanup`, which deletes only a marked
  interface. No shell-out.
- **The units** add sandboxing, `LimitMEMLOCK=8M` and `UMask=0077`. The
  socket's 0660 comes from a `umask(0117)` around the bind.
- **VE28 is narrower than planned.** The image carries systemd 257, so
  `systemd-analyze verify` runs on the units in the tests. What stays
  `blocked-deferred` is systemd's runtime behaviour: dependency
  propagation, `ExecStopPost`, and the `RuntimeDirectory` modes.
- **Tests:**
  - 64 in `client-cli`, 82 in the client workspace;
  - an `unshare -rn` case against a real kernel WireGuard pair and the
    real responder: `wg show` equals the OSK;
  - a `SIGTERM` changes the PSK and resets `latest-handshakes` to 0,
    which shows the keypair is gone;
  - the restart, foreign-interface and peer-uid cells, and I10.4.
- **Red-proofs:** all 11 injections in the plan's table, on scratch
  copies, each fired its needle.
- **For C12:** `Command::new` appears in `client/` test code (the netns
  and C harness tests), so C10's forbidden pattern covers `client/**/src`
  only.
- **For C13:** client.md tells the operator to load the `wireguard` module
  beforehand. Autoloading under `ProtectKernelModules=yes` is unverified.
- **Not locked, and not all wiped (corrected in code review S5):** the PSK's
  final copies, the `Actions` entry dropped in `perform`/`queue` and the
  netlink request `Vec`, are wiped but not mlocked. The bitwise copies the
  moves leave in the dead frames of `on_datagram`, `step` and `perform`
  (FFI: `process`, `queue`) were not wiped at all until the review. Each
  shell now calls `scrub_stack()` once those frames have returned (see the
  code review's S5).

### D-14 — the residue scan window moves with the EL1 board's RAM

- **The symptom.** The `wireguard` case failed after its rotation and L8
  checks, with "scan window does not cover PD memory: live session key not
  found".
- **The cause.** The positive control did its job. `OBJECT_RAM` was the EL2
  board's window, `0x6000_0000` + 32 MiB. On `kozane_virt_aarch64_el1`, RAM
  starts at `0x4000_0000`, and the PD frames span `0x4000_0000` to
  `0x4345_xxxx` (the `Kernel Objects` section of `build/report.txt`).
- **The fix.** `OBJECT_RAM = (0x4000_0000, 0x0400_0000)`.
- **Workers.** A recreated container also loses git's `safe.directory`
  for `/work`, which `release.py`'s `git status` needs. It was set again
  on z1mn and mrx33.

## C7: the initiator (batch 2)

### D-15 — vectors, proofs, pins; the root lock changes once

- **Vectors from upstream.**
  - `rp-vectors --initiator` runs upstream's initiator under
    `TestVectorActive`, and logs liboqs' `randombytes` calls from a
    SplitMix64 stream.
  - New files: `v02-initiator.txt` (10 entries), `spkt-initiator.bin`,
    `skt-initiator.bin` and `spkm-initiator.bin`. The last is needed
    because `spkm.bin` has no secret key on record.
  - Kozane's initiator replays InitHello and InitConf byte for byte, with
    real Kyber and McEliece, and derives upstream's OSK.
  - Upstream's draw order equals D-3's: cookie 16, sidi 4, Kyber 32+32,
    McEliece 2×384. The jitter draw is Kozane's only, and reaches no
    message byte.
  - The existing vector files and seeds are byte-identical, and P33 pins
    them.
- **P34 checks the constants against a committed excerpt.** The dev image
  has no upstream source, so `tests/vectors/upstream-constants.txt` holds
  `constants.rs` lines 19, 28, 50, 53, 56 and 60 verbatim, with the commit
  and the archive's sha256. P34 checks:
  - the excerpt names the Dockerfile's `RP_MASTER_COMMIT` and
    `RP_MASTER_SHA256`;
  - each Kozane constant equals upstream's value;
  - each constant's doc cites its line.

  `RETRANSMIT_DELAY_JITTER_NUM/DEN` (1/2) were added to make the jitter
  checkable.
- **Kani.** Six step lemmas over `initiator_state` from an arbitrary state
  (`src/proofs.rs`), and `rosenpass-core` joins `kani_crates`. Not yet run.
- **bolero.** One target fuzzes the next input after upstream's
  deterministic prefix, seeded from RespHello and EmptyData.
- **The root lock changes once.** The bolero target makes `bolero` a
  dev-dependency of `rosenpass-core`, which adds one line to
  `Cargo.lock`. The Kani cache key hashes `Cargo.lock`, so every key is
  invalidated. As the testing strategy allows, there is one full re-proof
  on z1mn and no further root lock change in M9.
- **Not done: I7.2's residue cases.**
  - The ct-harness is its own build-std workspace, and its libcrux features
    mirror `tls-core`'s exactly.
  - Hosting `rosenpass-core` there would unify `libcrux-ml-kem`'s `kyber`
    feature into the harness. That changes the code ct-shape compares
    symbol for symbol with the shipped PDs.
  - I7.2's evidence today is structural: every transient is a `Secret`,
    wiped on drop. The full design is decided in D-16.
- **Counts:**
  - UNIT-ROSENPASS-CORE 71, KANI-ROSENPASS-CORE 6, KANI-HARNESSES 172;
  - BOLERO-TARGETS 9, MIR-CRATES 19;
  - CHECK-PINS-RULES 33, CHECK-PINS-FIXTURES 389.

## C6, C11: `test-kvm`, `test-kzc`

### D-17 — the two gates, and decisions beyond their text

- **The suites.** `KOZANE_SUITE=kvm|kzc` selects a section of `run.py`; the
  `make test` path is unchanged. Each gate writes its own counts directory
  and checks it against its own manifest:
  - `test-kvm`: KVM-CASES 8;
  - `test-kzc`: KZC-CASES 6, INTEGRATION-ORACLE-CASES 2.
- **The KVM proof:**
  - harness boots assert QMP `query-kvm` before `cont`;
  - the launcher boot (no QMP) asserts `anon_inode:kvm-vm` among QEMU's
    fds.
  - The red-proof also sets `-cpu` to the TCG model, so QEMU starts and the
    `query-kvm` needle is what fires.
- **The expiry case** blocks only the Rosenpass port, with an `ip rule`
  blackhole (the image has no iptables).
  - The scrub came 180.1 s after the last RespHello.
  - Right after it, the ping fails and `latest-handshakes` reads 0 (S1.11,
    T2.7).
- **Cookie evidence.** The gateway coalesces `RpCookieReplySent` and
  `RpCookieAccepted`: a boot prints the first of each. So they are checked
  over the whole boot, and the sniffer attributes them to `kzc`'s
  endpoint.
- **IMAGE identity.** A container cannot name its own image. The record
  is a digest of dpkg's status plus the path, size and mtime of every file
  under `/opt` and `$MICROKIT_SDK`. QEMU's record is its build id.
  - `check-manifest --compare-identity` is the cross-gate check at
    milestone close.
- **iperf3.** The inside tap moves into a nested netns after QEMU attaches
  it. Frames still flow after the move (probed first).
- **Partitions in `selftest-split`:**
  - `kvm` needs `/dev/kvm` and takes the host, solver and proof locks
    without waiting;
  - `kzc` takes the host lock;
  - merge fails on mixed images.
- **`check-selftest`:**
  - `EXTRA_GATES` (`test-kvm`, `test-kzc`);
  - `CASES_FOR_GATE` for `client` {ffi-header}, `host` {vm-launcher-pin},
    `test-kvm` {kvm-dev-missing, kvm-proof, kvm-tick}, `test-kzc`
    {kzc-cookie, kzc-oracle-count}. All 7 fire their needles.
- **`mksecrets client-conf`** writes `client.conf` only.
- **A launcher fix found by the release boot.** On a requested stop, QEMU
  closes the TPM socket, so swtpm exits first. `kozane-vm` read that as a
  failure and exited 1, so systemd would have seen every stop as a
  failure. The decision is now `clean_exit`:
  - after a requested stop, any order is clean;
  - otherwise only QEMU's own success is.

  A unit test pins it (UNIT-HOST 48).
- **Baselines** (not gated):

  | Measure | KVM | TCG |
  |---|---|---|
  | Harness boot to `pq: ready` | 3.3 s | 6.6–16 s |
  | Launcher boot to `pq: ready` (mem-lock included, D-8) | 128–172 s | — |
  | Policy verdict, from QEMU start | 3.7 s | 9.5 s |
  | `kzc` InitHello → RespHello | 0.085 s | 2.0 s |
  | `kzc` InitHello → PSK installed | 0.39 s | 2.3 s |
  | HTTPS, sequential, fresh handshake each | 3.46 req/s | — |
  | WireGuard, iperf3 TCP over `kz0` | 70.8 Mbit/s | — |
  | Tick rate | 1.00001 ticks/s (2 % tolerance) | — |

- **Counts:** CHECK-MANIFEST-FIXTURES 20, SELFTEST-SPLIT-FIXTURES 19,
  CHECK-SELFTEST-FIXTURES 32, UNIT-MKSECRETS 41. UNIT-TESTS is re-measured
  at `make check`.

### D-16 — I7.2's residue cases: a separate harness

The decision on D-15's open item: the initiator's error paths get a
residue harness of their own. It is built with `rosenpass-core`'s
features, so the ct-harness and the ct-shape baseline it shares with the
PDs stay as they are.

- **The harness.** `tools/rp-residue`, its own workspace and lock, built
  natively with the client's release profile. Its lock is pinned to the
  root's by P39 (`pins: rp-residue lock drift`). The stack and arena code
  is copied from the ct-harness, not shared.
- **The cases (RP-RESIDUE-CASES 24).** Each initiator exit runs on a painted
  stack the harness owns, with the initiator in an `mmap` arena:
  - `start` with a refused draw at sidi, Kyber, McEliece and jitter, and
    accepted;
  - `handle_resp_hello`: bad mac, unknown session, expired, RNG, refused
    decapsulation, tampered auth, wrong responder key, and accepted;
  - `handle_empty_data`: unknown session, tampered auth, replayed, and
    accepted;
  - `handle_cookie_reply`: wrong mac, unknown session, and accepted;
  - `tick` past the lifetime;
  - a positive control;
  - `start` and an accepted `handle_resp_hello` with the real KEMs, for
    depth only.
- **The needles.** The seams replay known values shaped like the real ones,
  so the harness knows the cookie, the Kyber secret key and both KEM keys.
  It recomputes ck after IHI8 and tkr from the messages' public fields, and
  checks the model against the messages' tags and the OSK.
- **Found: the stack was not clean.** Measured first without any scrub, the
  production code left copies that no drop wipes, on error paths too. These
  are moved-from `Secret`s (D-5's residual) and libcrux's unwiped state.
  For example:
  - `start` refused at the McEliece or jitter draw left one whole copy of
    the Kyber secret key;
  - an accepted `start` left 2.8 copies of it, and two of the cookie;
  - every `handle_resp_hello` that reached RHI4 left the Kyber key, and one
    or two copies of the McEliece key.
- **The fix: a stack scrub in the client.** `kozane_client::scrub_stack`
  follows tls-core's `scrub_session_stack`: an `#[inline(never)]` function
  that zeroizes a local array of `SCRUB_DEPTH` bytes and `black_box`es it.
  - The client calls it right after every `Initiator` call: `start`,
    `handle_resp_hello`, `handle_empty_data`, `handle_cookie_reply` and
    both `tick`s. It runs on success and on error, before the result is
    acted on. client-ffi and client-cli reach the initiator only through
    `Client`.
  - No root-workspace crate changed. The client gains a `zeroize` edge
    (=1.8.1, already locked).
  - **N.** `SCRUB_DEPTH` is 128 KiB, from the deepest non-paint byte below
    the caller:
    - the 22 stand-in cases reach at most 13 352 bytes;
    - with the real KEMs, `start` reaches 53 576 and an accepted
      `handle_resp_hello` 103 064 (McEliece decapsulation's own 96 KiB
      scrub included).

    128 KiB keeps 28 008 bytes (about 27 %) over the deepest. The caller's
    thread needs that much stack free below the client's frame.
- **What is checked now.**
  - Each case runs twice, each time from a fresh state.
  - Unscrubbed: the depth must stay within `SCRUB_DEPTH`, and the residue
    is counted.
  - Then followed by `scrub_stack`, as the client calls it: the stack must
    hold none of the secrets the call handled (strict; the `RESIDUAL`
    table is gone).
  - The state must hold none of what the exit wipes, all of what it keeps,
    and no more of any other secret than before.
- **The controls.**
  - A secret alive in the caller's frame while the scrub runs below it
    must be found.
  - The unscrubbed runs together must leave residue. This run left 8 430
    windows.
- **Selftest.** Six cases in `rp-residue`, and one in `pins`:
  - `rp-residue-scrub` empties `scrub_stack`;
  - `rp-residue-state-wipe` drops `hs.eski.wipe()`;
  - `rp-residue-control` and `rp-residue-unscrubbed`, one per control;
  - `rp-residue-unit` and `rp-residue-lint`;
  - `client-scrub-site` (`pins`) removes the scrub after `start`.

  The first round's error-wipe injection (forget the cookie when the sidi
  draw fails) is no longer a case. The scrub clears that copy, which a
  scratch run confirmed.
- **P42**, a check-pins tripwire. Each of the six `ini.<method>(` calls in
  `client/crates/client/src/lib.rs` is a `let` with `scrub_stack();` on the
  next line, and no other client source names `Initiator`.
- **Counts:**
  - RP-RESIDUE-CASES 24, UNIT-RP-RESIDUE 4;
  - CHECK-PINS-RULES 41, CHECK-PINS-FIXTURES 424;
  - UNIT-CLIENT 82, unchanged.

## C12: gates and pins

### D-18 — the remaining gates, and decisions beyond C12's text

- **`tools/timer-scan`** (stdlib Python) runs in `package` on the ELFs the
  system file names.
  - It rejects register-form MRS/MSR with op0=3 and CRn=14 for op1 0, 3
    and 4, which also covers CNTKCTL_EL1 and the EL2 timer controls. That
    is stricter than D13's op1=3 class; every real ELF passes it.
  - It allows only reads of CNTPCT_EL0 and CNTFRQ_EL0.
  - `pd-timer` must hold at least one rejected-class instruction (it holds
    5).
  - It prints `TIMER-SCAN-PDS 17`. Only the shipped package in `run.py`
    passes `timer_scan_counts=1`, so the count is written once.
  - TIMER-SCAN-FIXTURES 12.
- **W^X lives in laws' ELF check (Rust).** Its needle starts `laws:`.
  - It refuses an RWX `PT_LOAD`, and a page covered by both an X and a W
    segment.
  - It reads `timer-scan.txt`, which must cover exactly the ELFs laws
    hashes.
  - laws also refuses any MR mapped with `x` (L4). This replaces the old
    rule, which covered shared MRs only.
  - `timer_channel_is_exempt` now requires the timer PD's IRQ and a clean
    scan.
  - The `timer_*` fixtures carry no device MR and IRQ 30, and two fixture
    pairs were added.
- **New `check-pins` rules:**
  - P35: the stack top in `crates/cpu` and `tools/laws` equals the SDK's
    `vspace_user_top` (D-9);
  - P36: I14.1, every `phys_addr` lies in a device node or a `simple-bus`
    window of `kozane-virt.dtb`, and the dtb has no `arm,sp804` node;
  - P37: `"-bios"`, `secure=on` and `mon:stdio` appear only in `vm.py`, its
    test and the pin files;
  - P38: no `Command::new` in `client/**/src`, no `REPLACE_PEERS` in
    `client/`;
  - P39: D12's lock pins: `client` against the root lock, `host` against
    `tools/release`'s;
  - P40: `cfg(feature = "test-seams")` appears only in the two resolver
    modules (the host's seams-gated integration tests are outside `src/`);
  - P41: unit files in `docs/operations` use the canonical subset. The
    client units are checked by `client-cli`'s own test.

  The image has no `dtc`, so the dtb is parsed in Python.
- **16 self-test injections**, each with a failure-only needle, over the
  `pins`, `unit` and `laws` gates. Each was run on its own and fired.
- **Counts:**
  - CHECK-PINS-RULES 40, CHECK-PINS-FIXTURES 421;
  - TIMER-SCAN-FIXTURES 12, TIMER-SCAN-PDS 17;
  - UNIT-LAWS 38, UNIT-FIXTURES-TEST 172;
  - UNIT-TESTS is re-measured at `make check`.
- **`tools/sdk-repro`** (VE27) has two modes:
  - `build` lists the sha256 of every file in a no-cache build of the
    `sdk` stage;
  - `compare` diffs two such lists and prints `SDK-REPRO-ARTIFACTS 3`
    (the kernel, the loader and the tool).

  It runs on gx10 and on z1mn at milestone close.

## Kani

### D-19 — the full re-proof, and one bound

- **The run.** The root lock's one change (D-15) re-proved every crate on
  z1mn: 18 crates in 9.3 h.
- **One harness failed:** audit-event's new
  `no_code_decodes_as_the_heartbeat`. Its name comparison is a memcmp of
  symbolic length, and the harness carried no unwind bound. This is the
  known rule: the bound must cover the memcmp's length.
- **The fix.** `#[kani::unwind(66)]`. The bound covers `decode`'s search
  of the 64-entry `Event::FIXED` and the 26-byte name memcmp, plus the
  loop exit. A first try with 28 covered only the memcmp. It cut the
  search short, and the unwinding assertion failed.
- **The rerun.** `make kani` stopped at that crate, so the rerun proves
  audit-event, auditkey-core, audit-core and rosenpass-core. Every earlier
  crate is a cache hit, because no other Kani crate's sources changed.

## Step 2-5: the self-check

### D-20 — Phase 2 self-check: testing (and security S2-S4)

- **F1 (RT7): every injection row now has a check-selftest case.** Each
  needle is a failure-only line of the gate's own test:
  - `pins`: `i1-1-drift` (a KVM-only device, `vm: tcg and kvm argv
    differ`, now in test_vm.py's failure detail) and `swtpm-key` (no
    `--key`, `vm: swtpm without key`, a new test_vm.py check).
  - `host`: `host-seams-shipped` (`host: shipped launcher has test seams`),
    `vm-launcher-argv` (I4.1 drift through `render_launcher_args`),
    `vm-launcher-seals` (the firmware memfd unsealed),
    `pin-firmware-unsigned` and `pin-firmware-older` (I4.3).
  - `client`: `client-scrub-bound`, `client-startup-scrub`,
    `client-deadline-reset` (I8.1 a/b/c), `ffi-memcheck`, `kzc-symlink`,
    `kzc-loose-mode` (I10.1), `kzc-sigterm-scrub` (I10.2), `kzc-psk-ack`,
    `kzc-psk-zero` (I10.3), `kzc-caps` (I10.4), `units-canonical`,
    `kzc-psk-only-scrub`, `kzc-psk-delete-on-exit`, `kzc-psk-reclaim`,
    `kzc-psk-peer-uid` (D6).
  - `test`: `pcr0-seal`. Both sides seal to PCRs 1-8 (tpm2-wire's
    selection and tpm2's digest), so the good boot still unseals and the
    PCR 0 deny case reports `pcr0-deny: unsealed`.
  - `repro`: `kernel-config-gicv2`. The image's `kernel-config` is pointed
    at the GICv2 fixture: `kernel-config: GIC_V3 missing`.
  - `kzc-cookie`'s anchor was stale (lib.rs scrubs after each initiator
    call now); fixed.
- **I15.1:** `tests/tools/test_sdk_repro.py` (SDK-REPRO-FIXTURES 8, in
  `make pins`). `compare`: equal lists pass with 3 artifacts; a differing
  hash, a missing loader, empty lists and a lookalike path fail. `build`
  runs against a stand-in docker that runs the real in-container listing.
  A find that fails part-way, or a failed `docker run`, writes no list.
  `compare` now matches the path field exactly (`awk`), not as a regex.
- **F2:** `tests/tools/test_kernel_config.py` (KERNEL-CONFIG-FIXTURES 10,
  in `make pins`). The SDK's debug and release configs pass, the GICv2
  fixture fails on GIC_V3 alone, and the release config fails with each
  required line removed.
- **F3:** `client-unit`, `client-lint`, `host-unit`, `host-lint`, as
  rp-residue's.
- **F4 (RT11):** kozane-vm's test roots are removed on drop, a panicking
  test's included: `Node` in launcher.rs, `Drop for Case` in
  pin_firmware.rs, `Scratch` in files.rs and pin.rs.
- **F5 (R50):** units.rs fails without `systemd-analyze`; it no longer
  skips.
- **F6:** a `cnthp_ctl_el2` write (op1 4) deny fixture
  (TIMER-SCAN-FIXTURES 13).
- **F7:** the netlink fake in device.rs panics on an unscripted message.
  Deny tests script the acks a mutant would consume, so the assertion
  judges the mutant, not the fake's panic.
- **F8:** check_launch.py takes the media and their addresses from
  `vm.LAUNCHER_MEDIA` and the new `vm.launcher_addrs()`.
- **S2 (R3):** `resolve::service_creds` refuses a `/dev/kvm` gid of 0 with
  the service-user error. Deny and allow tests (UNIT-HOST 50).
- **S3 (R47): `vm.violations` is an allowlist.**
  - A leading `--` counts as `-`.
  - QEMU options are only the ones `machine()` emits, and swtpm's only the
    ones `swtpm()` emits. They are listed by name without the dash, so
    P24/P25 still find `"-bios"` and `"-cpu"` once.
  - `-serial` must be `chardev:serial0`.
  - `-chardev` is `stdio`, or `socket` with `path=` (harness) or `fd=`
    (launcher).
  - `-netdev` is one of run.py's backends (dgram, socket, user, tap) in
    the harness form, and `tap,fd=` alone in the launcher form.
  - `-device` is checked by its first field or a `driver=` key.
  - `-monitor` is `none` only, and a stray positional is refused.
  - New deny fixtures: `--qmp`, `-mon`, a tcp or telnet serial,
    `driver=virtio-gpu-device`, a pty chardev, vhost-user, a launcher
    `tap,ifname=`, and an unknown swtpm flag (VM-FIXTURES 36).
- **S4 (R44):** `sdk-repro build` runs the in-container listing under
  `set -euo pipefail` and checks `docker run`'s status. It writes
  `<out>.partial` and renames it only on success.

### D-21 — functionality findings, fixed

- **F1 (R39): netlink buffer growth left key copies.** `Msg`'s buffer
  starts at 256 bytes. A request holding `wg.sk` or a PSK, plus several
  `allowed_ips`, grew past that, and `Vec` freed the old allocation
  unwiped.
  - Every write now goes through `Msg::put`. When the buffer must grow, it
    allocates a new one, copies, and wipes the old one before it is
    freed.
  - A test pins that the encoding is unchanged across the growth
    (UNIT-CLIENT 83).
- **F2 (R40): `kzc keygen` printed an entry that `tools/policy` cannot
  parse** (no `allowed_ips`, and a path on the client's machine).
  - It now prints the start of the entry: `rp_pub_path = "rp.pub"` and a
    commented `allowed_ips`.
  - It also prints instructions: the PDP copies `rp.pub` next to
    `peers.toml` and adds the networks and groups. `client.md` says the
    same.
- **F3 (R2): two sources for paths.**
  - The units name `/usr/bin`, and `client.md` now says `/usr/bin`.
  - `keygen` derives its key directories from `PSK_DIR`/`NET_DIR`, the
    paths `kzc-psk` and `kzc` read, instead of restating them.
- **F4 (R29):** `kozane.system`'s comment says INTID 30 (PPI 14), not
  "PPI 30".

### D-22 — a launcher-case teardown that a stop signal could skip

- **Found by** `test_harness_signals.py`, which runs every
  `with signals_held()` teardown in `run.py` with a stop signal raised on
  entry.
- **The fault.** In the KVM release-boot case, the `except SystemExit`
  path only removed the temporary root. So a signal on entry left behind:
  - the launcher and its children;
  - the backend and console handles;
  - the test bridges.
- **The fix.** Both paths now run the same full teardown, as
  `tap_teardown` does.
- **The test** stubs the names the new teardowns use: `others`, a running
  `launcher` whose kill is the recorded one, `bridges`, `root`, `con`.
  HARNESS-SIGNAL-FIXTURES stays 9.
- **The rerun reached `rosenpass-core`.** There three of the six new
  step lemmas (`resp_hello_`, `empty_data_` and `cookie_reply_from_any_state`)
  failed the same way. Their state `==` is a memcmp over the 16-byte
  `jitter` pool, and their bounds (2 and 3) were below it. All three now
  carry `#[kani::unwind(18)]`. The other three passed as written.

### D-23 — one stalled capacity probe in `cookie boot b`, not reproduced

- **Seen once.** `make check` on gx10 at a16ba79 failed one case,
  `cookie boot b`, with `capacity probe: no ARP reply after the probe;
  the queues did not drain`.
  - The flood began, `eth_out` counted 961 `RxNoBuffer`, and `hs` logged
    one `HandshakeDecrypt`.
  - After that, ingress printed nothing: no `WgUnderLoad`, and no reply to
    the 20 ARP requests in the 10 s that followed.
  - A passing run drains 0.6–1.5 s after the probe.
- **Not reproduced.** The case alone passed 10 of 10 times, 5 on gx10 and
  5 on z1mn, each draining in 1.0–1.5 s.
  - The network PDs (`eth-out`, `eth-in`, `ingress`, `pq`) are unchanged
    in M9.
  - The timer PD (C14) was read for a lost tick and none was found: a
    spurious interrupt leaves the compare value armed.
- **Why it stays open.** The run could not tell a slow drain from a
  stalled ingress. A stalled ingress would be a denial of service, so it
  cannot be dismissed as a flake.
- **The change.** On a failed drain, `probe_capacity` now waits a further
  60 s (`PROBE_STALL_S`) before failing. The message then says which it
  was: a reply some seconds late, or none at all. The case still fails
  either way.
- **If it recurs** with no reply at all, it is a liveness bug. It blocks
  the milestone until it is understood.

### D-24 — external security review: three fixes before merge

A security review of fa90c9b, outside the triangulate rounds, found three
issues. All three were confirmed in the code and fixed. Each fix has a
test that fails on the old code, red-proved on a scratch copy.

- **High — `release.py` verified a launcher by path, then ran the path.**
  - The fault: `verify` hashed `kozane-vm` and then opened the same path
    again to run `--build-info`. Whoever can write the release directory
    could swap the file in between, and their binary would then run with
    the verifier's privilege.
  - The fix: `checked_launcher` replaces `require_no_seams` in `make` and
    `verify`.
    - It reads the file once, with `O_NOFOLLOW`, and hashes those bytes.
    - In `verify` it refuses a digest other than the signed one before
      anything runs.
    - It runs the same bytes from a sealed memfd, as
      `/proc/self/fd/<n>`.
    - C4's rule stands: `SEAMS=0` comes from the exact file whose hash is
      signed.
  - Two release fixtures (RELEASE-FIXTURES 30):
    - a stand-in that reports `SEAMS=0` only when run from its read copy;
    - a symlinked `kozane-vm` whose target holds the signed bytes. The old
      code printed `release: verified` for it.
- **Medium — the guest could fill the host's disk through the console
  log.**
  - The fault: the reader appended every console byte to
    `/var/log/kozane/console.log` with no bound. A guest that printed
    without end filled `/var/log`. The failed write then stopped the VM,
    and `Restart=always` turned that into a restart loop.
  - The fix: `serial::Cap` keeps the log within `LOG_MAX` (1 GiB).
    - Past the cap it writes one marker and drops console bytes, never
      heartbeats.
    - Once the file is smaller again (a `copytruncate` rotation), it
      writes the count of dropped bytes first.
    - The length comes from `fstat` on each chunk, so a rotation is seen.
    - `audit`'s seq numbers make the gap a failure in `tools/audit-verify`.
      It is not silent.
  - The tests: four unit tests (below the cap; the marker, then nothing;
    the count after a rotation; no marker past the cap).
  - The docs: `docs/operations/host.md` gives the cap, the markers,
    `copytruncate`, and a separate filesystem or quota for
    `/var/log/kozane`.
- **Medium — the C ABI let callers alias what Rust treats as unique.**
  - The fault, in `kz_client_take_action`:
    - it made `&mut` references from `kind` and `len` while a `&mut`
      handle was also live;
    - it copied into `buf` with `copy_nonoverlapping`.
    - The header did not forbid overlaps, so a call that was valid C could
      be undefined behaviour in Rust.
  - `kz_client_next_deadline`'s `out` and `kz_client_on_datagram`'s input
    could likewise point into the handle.
  - The fix:
    - The outputs are now raw pointers, written once.
    - An overlap is refused with `KZ_ERR_INVALID`. In `take_action` that
      covers any two of `kind`, `len`, `buf[..cap]` and the handle. In
      `next_deadline` it covers `out` against the handle, and in
      `on_datagram` the input against the handle.
    - `kz_client_new` writes `*out` only after its input borrows end.
    - The header says all this (regenerated).
    - The PSK still goes straight from its slot to `buf`, with no local
      copy left on the stack.
  - Six FFI unit tests, five of them refusals, which fail with the overlap
    check removed (UNIT-CLIENT 89).
- **Found while fixing the console log: the reader could win the exit
  race.**
  - The fault: QEMU closing its console on the way out gives the reader
    EOF, and `supervise` could see the reader exit before QEMU did. A
    clean poweroff then failed the boot. This was seen once in six runs of
    `i4_1_…`.
  - The fix: after a clean EOF from the reader, QEMU's own exit decides,
    if it comes within 5 s. Otherwise the boot failed.
  - The tests: the QEMU stub's `console-first` mode closes the console
    0.5 s before it exits. One test expects a clean boot; the old code
    failed it. A second expects QEMU's failure to be reported.
    UNIT-HOST 56.
- **From `/simplify`:** `kv::is_ifname` now refuses `.` and `..`, like
  the client's `interface` and the kernel's `dev_valid_name`.
- **Left as is:** `docker/sdk/kozane-board.patch:43` keeps its trailing
  space. It is a unified-diff blank context line, and removing it changes
  the patch and the SDK build input. Three files lost a blank line at
  their end.

### D-25 — split self-test at e417fce: a racy scrub and a stale mutation

The split self-test at e417fce failed three cases. None of them was a
fault in the gateway.

- **`kzc-cookie` and `kzc-oracle-count`: kzc-psk's scrub left a gap.**
  - The failure: both runs stopped in the cookie prelude with
    `kzc-psk: kz0 has other than one peer: ''`.
  - The cause: `Device::scrub` removed the peer in one netlink request and
    re-added it in a second.
    - Between the two, the interface had no peer. The harness's
      `wg show` landed in that window under the partition's parallel load.
    - A failed re-add would also have left the interface without a peer
      until a restart. That fails closed.
  - The fix: `wg::replace_peer` sends one `WG_CMD_SET_DEVICE` with two
    peer entries.
    - The first is the key with `WGPEER_F_REMOVE_ME`; the removal takes
      every live keypair with it (S1.11).
    - The second is the same key with the fresh PSK, endpoint and allowed
      IPs, so the peer is created again.
    - The kernel applies a request's peers in order under the device's
      update lock, and `wg show` reads under the same lock. So no netlink
      reader sees the interface between the two entries.
    - It is not a transaction (corrected after review). The kernel stops
      at the first failing entry, and does not undo the ones before it.
      So an `ENOMEM` while creating the second entry, or one of its
      allowed IPs, leaves the peer removed.
    - Any scrub error is fatal. `kzc-psk` deletes the interface and exits,
      and `Restart=on-failure` starts it again, so the failure stays
      closed: no traffic, no stale key.
    - What the single request removes is the gap that readers saw, and the
      second request that could fail on its own. Inside the kernel, the
      remove still comes before the re-add.
  - The tests:
    - Layout: `replace_peer_layout`.
    - Device: one request with the remove entry, then the add entry.
      A refused replace is fatal (UNIT-CLIENT 88).
    - The real-kernel netns test still sees the session gone
      (`latest-handshake` 0) and the PSK replaced after a scrub.
    - The selftest mutations `kzc-psk-ack` and `kzc-psk-only-scrub` were
      re-aimed at the new lines, and both still go red with their needles.
  - The docs: `docs/operations/client.md` says the peer is replaced in
    one kernel request.
- **`supervisor-resume`: the mutation no longer resumed anything on the
  EL1 board.**
  - The failure: the mutated supervisor answered the fault with the
    `MessageInfo` it received. One record printed, and then nothing more
    within the boot timeout.
  - The cause is in the kernel:
    - seL4's `handleFaultReply` restarts a thread after a UserException
      only when the reply's label is 0. A VMFault is restarted whatever
      the label.
    - Under M8's hyp-mode kernel, the panic that the fault-inject frame
      causes arrived as label 8, which restarts on any reply.
    - On `kozane_virt_aarch64_el1` it arrives as UserException (label 3),
      so the label-3 reply left the child suspended.
    - The supervisor itself is unchanged: it never answers a fault. Only
      the mutation, which is meant to prove a resumed child would be
      caught, had stopped resuming.
  - The fix: the mutation replies `MessageInfo::new(0, 0)`. That is label
    0 and no message words, so the registers are unchanged and the thread
    restarts at the faulting instruction on either kernel.
- **The commit that closed this.** The self-test ran on the commit that
  corrected these comments and docs. Its `make check` counts are those of
  93d2d07, whose code is the same.

### D-26 — kzc and kzc-psk could lose a stop signal

- **Seen as** the split self-test's `ffi-header` failure at b342ce4.
  - The mutated header was never compared. Before the comparison,
    `make client`'s real-kernel netns test failed with
    `process … did not exit`.
  - The process was the restarted `kzc`, sent SIGINT with 20 s to exit,
    under the partition's parallel load.
- **The cause.** Every loop in `kzc` and `kzc-psk` checks the handler's
  flag (`sys::terminated()`) and then calls `poll`.
  - A signal that lands between the two sets the flag, but `poll` has not
    started, so nothing interrupts it.
  - The poll then sleeps to its timeout. That is the next Rosenpass
    deadline for `kzc`, and forever (`-1`) for `kzc-psk`.
  - A stop request is therefore lost until systemd's SIGKILL. For
    `kzc-psk` that is the case the client guide warns about: the
    interface is left with its last PSK, because `Device`'s drop never
    runs.
- **The fix: a self-pipe in `sys`.**
  - `install_signal_handlers` creates a non-blocking, close-on-exec pipe.
  - The handler sets the flag and writes one byte to the pipe. It saves
    and restores errno around that write.
  - `sys::poll` always waits on the pipe as well, and returns `None` once
    the pipe is readable. The pipe is never drained, so every later poll
    returns at once too.
  - `sleep_ms` is a poll on the pipe alone.
  - No loop changed; they all reach `poll` through `sys`.
- **The test.** `tests/signal.rs` is its own binary, since the handlers
  are process-wide.
  - It raises SIGTERM before `poll` and requires `None` within 1 s from a
    5 s poll.
  - With the old `sys.rs` it slept the full 5 s, and failed with
    `poll: the signal was lost`.
  - UNIT-CLIENT 89.
- **The same patterns elsewhere (swept after the fix).**
  - **A stop flag checked before a blocking wait.**
    - `kozane-vm` blocks its signals and reads them through a signalfd in
      the same `poll` as its children, so it cannot lose one.
    - `mksecrets` only blocks signals around its critical sections; it
      waits on nothing.
    - In `kzc` and `kzc-psk`, no other loop checks `terminated()` and then
      blocks. Their loops reach `poll` through `sys::poll` or
      `sys::sleep_ms`, both fixed here.
    - Not every wait goes through them. `netlink::Socket::call` waits for
      the kernel's reply in `sys::netlink_recv`, a blocking `recvfrom`, and
      the self-pipe does not wake that.
      - That wait checks no flag, so it has no window to lose a signal in.
      - A signal during it still sets the flag, and the next loop check
        acts on it once the reply arrives. So with a kernel that answers,
        a stop during setup or a scrub is not lost.
      - Nothing here guarantees that the self-pipe ends a netlink wait
        itself.
  - **Netlink steps that one request could hold.**
    - `kzc-psk` creates the link and then marks it in a second request,
      because the kernel ignores `IFLA_IFALIAS` in a creating
      `RTM_NEWLINK`.
    - A non-graceful end between the two leaves an unmarked `kz0`, which
      the next start refuses to touch.
      - That covers any end that skips `Device`'s drop: SIGKILL, an OOM
        kill, SIGABRT, SIGSEGV or power loss.
      - It is fail-closed, but it needs `ip link del kz0` by hand.
      - A SIGTERM stop is not lost, so the drop runs and the link is
        reclaimed.
    - This is a residual, since nothing in the kernel API closes it.
    - Every later configuration step runs on a marked link, and `Device`
      deletes the link on any error.
    - `kozane-vm`'s taps are not persistent, so they vanish with its
      descriptors, even on SIGKILL.
  - **Fault replies.** The supervisor is the only PD with a fault handler,
    and it never answers a fault, so D-25's label rule has no production
    reader.
  - **Mutations a platform change could disarm.** In the split self-test
    at b342ce4 (gx10 and z1mn), every case except `ffi-header` (this
    entry) went red for its own needle on the EL1 board. So no other
    mutation was silently disarmed. The final verdict is the self-test at
    the closing commit.

### D-27 — IMAGE compared mtimes, not the toolchain's contents

- **Seen as** the split self-test merge at 0212d1e.
  - Every one of the 312 cases passed on gx10 and z1mn.
  - The merge still refused, with `mixed images`: z1mn's qemu and solver
    instances recorded another IMAGE than gx10's. QEMU's build ID was the
    same on both.
- **What IMAGE is for.**
  - The milestone's verdict joins `make check`, test-kvm, test-kzc and
    the self-test partitions of two hosts. IMAGE shows that they all ran
    on one toolchain: rustc, Kani, Verus, the SDK and QEMU.
  - z1mn gets its image by a manual `docker save | load`, so a stale image
    on a worker is a real risk.
- **The two images were one.**
  - Same `RootFS.Layers` and the same creation time.
  - The 6,874 files have the same paths and sizes, and `dpkg` status is
    the same.
  - Only the mtimes differed. Docker Desktop's snapshotter on macOS keeps
    whole seconds, while gx10's Linux one keeps nanoseconds.
- **The fault.** IMAGE hashed each file's path, size and mtime, as a stand-in
  for its contents. It assumed that `docker save | load` keeps mtimes
  exactly, which the snapshotter does not.
- **The fix, after the owner's review.**
  - A first fix counted mtimes in whole seconds. The owner asked what
    such a check proves, and the answer was nothing direct: an mtime is a
    proxy.
  - `tree_digest` now hashes contents instead: the package database, and
    each file's path with the SHA-256 of its bytes. A symlink is hashed
    by its target.
  - Directory symlinks are included too, which a second review asked for.
    `os.walk` lists a symlink to a directory under `dirs` and does not
    enter it, so the first content digest skipped such links: switching
    `current -> v1` to `current -> v2` kept the digest. Links are now
    taken from both lists. The image has no directory symlinks today, so
    the value did not change.
    - Two hosts agree exactly when they run the same tool bytes.
    - It covers 1.1 GB and takes 0.6–1.0 s.
  - On the live containers the digest is the same on both hosts
    (`4ea251e6…`).
- **The tests: five digest fixtures.**
  - The same bytes with another mtime: one image. On a scratch copy, the
    old mtime digest fails this one.
  - Other bytes of the same size: another image.
  - Another path: another image.
  - A symlink to another target: another image.
  - A directory symlink to another target: another image. HEAD's digest
    fails this one.
  - CHECK-MANIFEST-FIXTURES 25.

### D-28 — code review round 1: decisions beyond the findings' text

- **S2, the programs vm.conf names, are checked by path, not run by fd.**
  - The finding proposed running the checked file through `fexecve` or
    `/proc/self/fd/<n>`. Neither works for every program:
    - The launcher's stand-ins are scripts. A script cannot run from a
      close-on-exec descriptor.
    - Keeping the descriptor open would hand the child an extra fd, which
      the I4.1 inventory refuses.
  - So `files::check_program` closes the window by ownership instead. It
    requires:
    - a plain absolute path, with no `.` or `..`;
    - an executable regular file, not a symlink, not group- or
      world-writable;
    - the file, and every directory from `/` down, owned by one of
      `Resolver::dir_owners`, with each directory not writable by group or
      others unless it is sticky.
  - With every component checked, only those owners could swap the file
    between the check and the exec. In the shipped launcher they are root
    alone (H1's trusted party).
  - Under the test seams with `--user-map`, the input owner and the
    kernel's overflow uid count as owners too. In the launcher tests' user
    namespace real root shows as 65534. An earlier version checked from the
    root prefix down instead, and failed test-kvm, whose real QEMU sits in
    /opt, outside the prefix.
  - The file's own owner check shares that list. Round 1 claimed it could
    not be red-proved with one uid. Round 2 showed it can: a file of ours
    directly in the root-owned, sticky /tmp, checked with owners [0], is
    refused by the file clause alone.
  - Round 2, S8: the sticky allowance is now the caller's `sticky_ok`,
    `resolve::SEAMS`. The shipped launcher refuses every group- or
    world-writable directory, as `check_dir` does.
- **T1, UNIT-HOST counts both runs.** `make host` runs the unit tests
  twice: once without the seams (the shipped configuration), then with
  them. UNIT-HOST (111) is the sum, so a library test counts once per
  configuration.
- **T7, the plan's manifest keys.**
  - UNIT-CLIENT, UNIT-CLIENT-CLI and UNIT-CLIENT-FFI are now separate
    keys, one `cargo test -p` per crate (14, 66, 10). UNIT-CLIENT is
    `kozane-client` alone, no longer the workspace total.
  - RP-INITIATOR-VECTORS is not a separate key. The vector replay is
    `rosenpass-core`'s own unit test (`tests_initiator_vectors`), counted
    in UNIT-ROSENPASS-CORE. Its inputs are pinned by D-15's
    `rp-vectors-pin`.
- **Milestone-close records the testing review asked for.**
  - **VE27.** `tools/sdk-repro build` ran on gx10 and z1mn on 2026-11-04:
    201 files each. `tools/sdk-repro compare build/sdk-gx10.sha
    build/sdk-z1mn.sha` printed `SDK-REPRO-ARTIFACTS 3`, exit 0.
  - **Cross-gate identity.** `tools/check-manifest --compare-identity
    build/counts build/counts-kvm build/counts-kzc` has been run after
    every gate chain since D-24, exit 0 each time. It runs again at the
    closing commit.
- **S5, a client-level residue case is not added.** The shells now scrub
  their stacks after every step. rp-residue drives `Initiator` directly,
  and measuring the shells' frames would need a whole `Client` with a live
  responder in the scan harness.
  - This is a deferral. Its cost justification is in the code review's
    Resolution Status.

### D-29 — code review round 2: decisions beyond the findings' text

- **S6/N2, bare `-device` fields.** In `_device_key_problems`, every field
  after the leading driver must be `key=value`.
  - QEMU 9.0's QemuOpts reads a bare `x` as `x=on` and `nox` as `x=off`,
    and the last value wins. So `force-raw=on,noforce-raw` loads an ELF.
  - An empty field (`,,`) is refused too, which is stricter than QEMU.
  - In the launcher form, a loader's `addr=` must also be one of
    `launcher_addrs()`. S6 asked this as a question; pinning it to the set
    the launcher renders answers it.
- **S7/N5 and TN3, the shells' scrubs.**
  - kzc's per-call closure became `#[inline(never)] fn step`, which makes
    the client call itself. The FFI's `with_handle` is `#[inline(never)]`.
  - So the `Actions` a call returns, and the copies its moves leave, lie
    in a frame that has returned before the caller's `scrub_stack()`.
  - P42 now pins the call sites:
    - each of kzc's three `let r = step(|| …)` is followed by
      `kozane_client::scrub_stack();`;
    - the FFI has exactly two scrubs, each before `code`.
  - Self-test cases `client-shell-scrub-net` and `client-shell-scrub-ffi`
    each remove one call.
  - A client-level rp-residue measurement is still not added. The call
    sites are now gated, so deleting one fails `make check`. Whether the
    scrubbed region holds every copy stays unmeasured at the `Client`
    level, a residual for M10.
- **TN6, the two early returns in host src/tests.rs stay.** P40 forbids
  `feature = "test-seams"` in a crate's `src/` outside resolve.rs. The two
  tests are real in the plain run, which is the one that matters (T1). In
  the seams run they return at once, so 2 of UNIT-HOST's 118 are those
  no-ops.
- **N3, provisioning.** host.md uses `setpriv`, which keeps the key's
  descriptor open, where `sudo` closes it (closefrom). That `setpriv`
  passes fd 3 through was checked in the dev image (util-linux 2.41.5).
  The service user itself was not available there.
- **Self-test TMPDIR.** The new owner tests use `/tmp` by name: the
  self-test sets each instance's TMPDIR to a directory the user owns, so
  `temp_dir()` is not root's there. A run of `vm-launcher-argv` under that
  TMPDIR first failed on exactly this.
- **Round 3 (the owner's review of round 2).**
  - The QemuOpts shape check now covers every QemuOpts option: `-machine`,
    `-chardev`, `-netdev`, `-object`, `-device`, `-tpmdev` and
    `-overcommit`. On all of them a bare field (`x` is `x=on`), an empty
    field or a repeated key (the last value wins) is refused. Without that,
    `secure`, `mux`, `mem-merge=on`, `dump-guest-core=on` and `signal=on`
    went through.
  - The harness's user-net repeats `hostfwd`, its one allowed repeat.
  - `-machine` must be one of the two strings machine() renders. The
    console chardev must be the rendered one exactly. The TPM socket must
    be `socket,id=chrtpm` with `path=` (harness) or `fd=` (launcher) alone.
  - P42 also pins `#[inline(never)]` directly above kzc's `fn step` and
    the FFI's `unsafe fn with_handle`. The scrub's reach depends on both:
    with either inlined, the call's copies sit in the scrubbing frame.
  - The host file tests accept the kernel's overflow uid among the owners,
    so they run in a user namespace where `/` shows as 65534. The two
    tests that need root's sticky /tmp fail there on their precondition,
    loudly.
- **Round 4 (the owner's review of round 3): values bound, not only keys.**
  - Each non-loader `-device` must be one of the four strings written out
    in `_exact_devices`:
    - the rng on bus 0;
    - the TPM on `tpm0`;
    - the outside NIC with `n0`, its MAC and its bus;
    - the inside NIC with `n1`, its MAC and its bus.
    So swapping the NICs' netdevs (the PD's outside and inside slots) is
    refused.
  - A launcher loader must be one of `_launcher_loaders`: medium i on fd
    `max(LAUNCHER_QEMU_FDS) + 1 + i` at `launcher_addrs()[i]`. Swapping two
    media's fds or addresses is refused.
  - Also exact:
    - `-m` is `MEMORY`, and `-tpmdev` is `TPMDEV`.
    - The launcher's `-bios`, both taps (outside as n0, inside as n1) and
      the TPM socket sit on their LAUNCHER_QEMU_FDS numbers.
    - swtpm's ctrl and key sit on their LAUNCHER_SWTPM_FDS numbers.
  - `machine`, `accel`, `cpu`, `m`, `bios`, `serial`, `monitor` and
    `display` are each given once. The machine string and the CPU must be
    those of the given accelerator.
  - These references are written out, not taken from machine(), so a bad
    edit there does not move them.
  - test_vm's launcher fixtures now use the real fd layout. 16 new deny
    fixtures bring VM-FIXTURES to 72.
  - The vm-launcher-argv self-test's second rng is the rendered string, so
    it stays admissible.
  - Under the stricter list, the needles of `i1-1-drift` and `swtpm-key`
    were re-checked.
  - The host file tests no longer depend on the umask: `scratch()` sets
    0755.
  - Root ownership is judged by `root_like()`, which is 0 and the kernel's
    overflow uid. So the tests pass where `/` and `/tmp` show as 65534 to
    a non-root user.
  - Under `unshare -r`, where the test itself is uid 0, the two
    other-uid tests fail on their precondition. No second uid exists there.
- **Round 5 (the owner's review of round 4): required parts, not only
  unrepeated ones.** `_qemu_once_problems` now requires exactly once:
  - each of `_ONCE`;
  - `-overcommit mem-lock=on`, in the launcher form (zero in the harness's);
  - `-tpmdev`, the console chardev and the TPM socket chardev;
  - the TPM device and both NICs;
  - netdevs `n0` and `n1`;
  - in the launcher form, every medium's loader.

  `_count_problems` requires each swtpm option once.

  A dropped `-bios` would have run QEMU's own firmware instead of the
  pinned one, and a dropped `-overcommit` would let guest RAM swap. 23 new
  fixtures, one per dropped part, bring VM-FIXTURES to 95.
- **The vm.py red-proofs were re-run without bytecode.** Every vm.py
  mutation loop so far wrote mutants of one module in quick succession.
  Python reuses a cached `.pyc` when the source's mtime (in seconds) and
  size match, so two equal-size mutants written within one second ran the
  first one's code. This showed up as four different round-5 mutations
  reporting the same failures.
  - All 25 clauses were re-run with `python3 -B` and a cleared
    `__pycache__`. Each reddens its own fixtures.
  - Two device-level clauses, bare fields and repeated keys, reddened
    nothing: round 3's shape check, which runs first for every QemuOpts
    option, catches both. They were removed as unreachable.
- **Round 6 (the owner's review of round 5).**
  - The launcher's swtpm `--tpmstate` must be `dir=/var/lib/kozane/swtpm`
    exactly. Before, a vm-args.json that moved both the argv and its
    `swtpm_state` field was accepted end to end.
  - `VmArgs::parse` now refuses any other `swtpm_state` too
    (`vmargs::SWTPM_STATE`). So the launcher no longer trusts vm.py alone
    for it.
  - The rng halves are paired. The launcher needs exactly one `rng-random`
    backend and at least one rng device; the self-test's second rendered
    device stays admissible. The harness has both halves or neither, as
    `rng=False` renders.
- **A harness race seen while gating round 6.** `cookie boot b` failed
  once in `make check` with `wg setconf wgt49801 … returned non-zero exit
  status 1`, and the harness kept no stderr.
  - `WgGo._configure` waited only for the link.
    - wireguard-go creates the link before it listens on its UAPI socket,
      and `wg` needs that socket.
    - A stale socket left by a run killed in a container restart, of a
      reused pid, is the other candidate.
  - The harness now waits for `/var/run/wireguard/<dev>.sock` too, within
    the same 10 s, and fails with wg's own stderr.
  - The case is the harness's, not the gateway's: the failure came before
    any WireGuard traffic.
