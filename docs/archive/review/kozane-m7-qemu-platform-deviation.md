# Coding Deviation Log: kozane-m7-qemu-platform

Deviations from the locked plan, recorded as they are made. The probe
results and Re-plan R1 are in the plan itself.

## Slice 1 (C1, C2) and the start of slice 2 (C3)

### C1: pins

- **What:** C1 asked for "one `check-pins` rule per new pin". No new rule
  was added. The TF-A and Mbed TLS tarballs are `curl` downloads in the
  Dockerfile, so the existing P1 already covers them: every download must
  be followed by `sha256sum -c`. U-Boot is pinned the same way.
  **Why:** a TF-A-specific rule would duplicate P1.
- **What:** TF-A is pinned by the sha256 of its v2.15.0 tag tarball, not
  by commit digest as the probe notes said. Mbed TLS 3.6.6 is pinned by
  its release tarball, and its tag is the commit TF-A's submodule names.
  **Why:** a content digest pins at least as strongly as a commit digest.
  GitHub might regenerate the tag tarball; if it does, the build fails
  closed, and the pin is renewed by hand.
- **What:** libTPM (`2adab98e`) and libEventLog (`ab03a7c0`) are vendored
  under `third_party/` instead of downloaded. Their licenses and commits
  are recorded in THIRD_PARTY.md.
  **Why:** their only upstream is TrustedFirmware's gitiles, and its
  archives are generated on demand, so their bytes are not guaranteed
  stable. Git content-addresses the vendored copy.
- **What:** `cmake`, `device-tree-compiler` and `libssl-dev` come from the
  same apt snapshot, installed in their own layer after the user is
  created.
  **Why:** fiptool needs the OpenSSL headers, libTPM and libEventLog build
  with cmake, and the fdts need dtc. Adding them to the first package list
  would have rebuilt QEMU, Kani and Verus.

### C2: firmware

- **What:** `tools/flash-image` writes `flash.bin`: BL1 padded to
  `PLAT_QEMU_FIP_BASE` (0x40000), then the FIP.
- **What:** `support/tf-a/build-flags` holds the TF-A flags, and the
  Makefile quotes each one, so `BUILD_MESSAGE_TIMESTAMP="kozane"` reaches
  TF-A as a C string literal.
- **What:** `CROSS_COMPILE=aarch64-none-elf-`, the pinned Arm GNU
  toolchain. **Why:** it is the same compiler on arm64 and amd64 hosts,
  unlike the distribution's native gcc.
- **What:** `make repro` covers 24 artifacts, up from 16: both
  `flash.bin`, `bl1.bin`, `fip.bin` and `u-boot.bin` per variant. The first
  run was green across two tree paths.
- **What:** the plan's "a deny fixture with a varying timestamp goes red,
  naming `bl1.bin`/`fip.bin`" is not in place yet. Today P24 enforces the
  fixed strings statically, with fixtures.
  **Anti-Deferral:** this is the self-test injection for `make repro`
  (slice 6 bookkeeping). Until then, a regression that P24 cannot see (an
  embedded path, say) would surface only in the long run's repro. The cost
  of closing it is one injection that edits `build-flags`.
- **What:** I2.1 is done for `run.py`. `qemu_machine()` is the one
  builder, and it refuses any firmware other than the two images. P24
  checks that `"-bios"` appears only in that builder. `make run` still
  boots the unpackaged loader without firmware.
  **Anti-Deferral:** making `make run` measured needs packaged boot media
  (a descriptor and envelopes) and a per-run swtpm. That is C11's harness
  work (slice 5/6). Until then `make run` is a dev convenience that seals
  nothing and is never a test oracle. Worst case, a developer believes a
  `make run` boot was measured.

### C3: TF-A (P2 passed)

- **P2 result:** BL1 brings up the MMIO TIS (vendor 0x1014, swtpm), calls
  TPM2_Startup, and extends PCR 0 with BL2. BL2 extends BL31 (image 3)
  and BL33 (image 5), each before it runs, and records each in the event
  log. No config entry is loaded, so the closed list is {BL2, BL31, BL33}.
  BL1 refuses any other image, and BL2 refuses any image without metadata.
  Both refusals go through the I3.2 stop.
- **What:** BL1 hashes with `crypto_mod_calc_hash`, not
  `event_log_measure`. **Why:** upstream BL1 on qemu keeps no event log,
  so no hash is registered there.
- **What:** the event log starts in BL2, so it omits BL1's extend of BL2.
  The C4 twin and the replay check prepend that extend.
- **What:** the I3.2 stop (`qemu_dtpm_fail`) prints `KOZANE-MBOOT: <BL1|BL2>
  <step> failed` and drives the secure GPIO power-off pin directly.
  **Why:** BL1 and BL2 have no PSCI, and the upstream panic spins. It was
  observed: a BL1 that could not hash powered off with "QEMU System Power
  off".
- **What:** libTPM gains a FIFO_MMIO backend (`tpm2_fifo_mmio.c`, about 70
  lines). It implements the three register accessors the FIFO core uses.
  The transport pointer `tpm_interface_init` stores is unused over MMIO.
  libTPM's `tpm2.h` uses `size_t` without `<stddef.h>`, an upstream gap,
  so the new files include it first.
- **What:** U-Boot treats an already-started TPM as success, so the old
  `tpm2 startup` line would have passed. It is removed anyway, per C3,
  and P24 forbids it.

## Slice 2 (C3, C4)

### C4: the policy and its twin

- **What:** the plan wrote `--pcrs`/`pcrs` as interfaces without giving
  their encoding. They are encoded as follows:
  - `mksecrets seal` and `check-envelope` take
    `--pcrs HEX,...,HEX`: nine values, PCR 0 first. Any other count is
    refused.
  - The package writes `pcrs` (one hex value per line) and `flash.bin`.
  - The release manifest replaces `pcr8` with `firmware_sha256` and `pcrs`
    (10 keys).
  - The release ships `flash.bin`.
- **What:** tpm2-tools' `tpm2_policypcr -f` refuses nine PCRs. Its
  TPML_DIGEST holds at most eight, the same limit that makes the host
  read PCRs 0-7 and 8 separately.
  So the independent oracle (TE4) reads the values from swtpm itself
  after the boot extends instead of from a file. The result is a stronger
  oracle: the TPM computes the policy digest from its own PCRs.
- **What:** `mksecrets` takes `tpm2-wire` as a normal dependency, not only
  a dev-dependency. It is already in the lock through `tpm2`, so the lock
  is unchanged.
- **What:** ct-harness's `residue.rs` also calls `envelope::seal`. The
  plan's consumer list missed it, and the build found it.
  `make ct` refreshed the C9 pass record for the changed harness.
- **What:** the M5 envelope deny (an envelope sealed to PCR 8 alone) is the
  envelope parser's refusal: the selection field differs. It is covered by
  the tpm2 unit test on the selection bytes. It is not a separate
  integration boot.

### C3: integration

- **What:** each stage's deny changes one printed byte of that FIP entry,
  so the case also proves the changed stage ran:
  - BL2's and BL31's `release):kozane` becomes `Kozane`;
  - BL33's `U-Boot 2025.01` becomes `u-Boot`.
  Each variant is derived from FIRMWARE by the harness and registered,
  and `qemu_machine` refuses any other firmware. The planned forging BL2
  is this case: a BL2 changed in one byte that extends exactly what the
  honest one does.
- **What:** there is no config deny, because P2 found that no config is
  consumed (the closed list is {BL2, BL31, BL33}). The twin refuses a FIP
  with any other entry, as the fixtures in test_measure and test_release
  show.
- **What:** each I3.2 case checks that TF-A printed its stage line, that
  QEMU exited, and that U-Boot never ran. The QMP `guest-shutdown` reason
  is added with C11's harness change.
  **Anti-Deferral:** until then, "exited" cannot tell a power-off from a
  crash. The case's TF-A line names the stop, so the exposure is a
  mislabelled exit, not a missed one.
- **What:** the plan's mutations (consistent drops from the patch and the
  twin) are self-test injections. They belong to slice 6 (bookkeeping),
  with the C2 repro injection.
- **What:** the TPM proxy's PCR 3 injection holds the PolicyPCR until the
  injected extend's response arrives. swtpm takes one command at a time,
  and two back-to-back commands lost the second (observed: a hang).
- **Observed:** with TF-A and swtpm, QEMU's `system_reset` (the wireguard
  reboot case) re-ran BL1. The second boot re-measured, and its
  handshakes worked as before. That covers the swtpm-reset half of P4 for
  a host-initiated reset.

## Slice 3 (C5)

- **What:** no dev EK CA is committed under `support/keys`. The CA is
  made per run by swtpm-localca in the run's directory (the integration
  harness and `test_provision.py`), and `tools/provision` takes its root
  with `--ek-root` and its intermediates with `--ek-intermediates`. A
  deployment passes its TPM vendor's root.
  **Why:** a committed CA key is a key anyone with the repo holds. RM7-10
  is narrowed: the residual is now only that QEMU's TPMs come from a CA
  the harness itself made, not one their vendor runs.
- **What:** the EK is the RSA one at the TCG credential profile's index
  0x01c00002, the one swtpm_setup certifies by default.
- **What:** the SRK's template check and its Name come from one
  adjudicator, `mksecrets check-srk` (`tpm2_wire::srk_point`, the PDs'
  own check, and `tpm2::crypto::name`, the envelope's). That avoids a
  second Python copy (R1, R48).
- **What:** tpm2-tools leave the objects they create loaded, and swtpm
  has few transient slots. `tools/provision` therefore flushes transient
  objects after each create and on every exit, so the TPM is left as it
  was found.
- **What:** three of the five denies substitute one tool's output file
  through a PATH shim: an EK certificate for another TPM, another TPM's
  SRK, and fixedTPM clear. The comparison, the template check and the
  activation they exercise are the real ones. "Another CA" and "no EK
  certificate" are real swtpm setups.
- **What:** every integration TPM is now manufactured by
  `swtpm_setup --create-ek-cert` and provisioned by `tools/provision`.
  The copy check (a copy of the state gives the same SRK) runs through
  `tools/provision` too.

## Slice 4 (C6, C7, C10's rng parts)

### C7: where the DRBG sits

- **What:** each PD's `rng_client::Entropy`, a `drbg::Drbg` the `rng` PD
  seeds, replaces RNDR at the point where RNDR was read: `HedgeHw` and
  `Hardware` samples, `Transport::random` (the unseal's salt),
  `BootEntropy`, and the cookie adapters' `fill`. The PD's existing hedged
  construction stays as the outer layer, unchanged:
  - BLAKE2s(boot seed ‖ ctr ‖ CNTPCT ‖ sample) in hs-core;
  - HMAC(boot seed, ‖ sample) in tls-core and rosenpass-core;
  - BLAKE2s(blob seed ‖ sample ‖ CNTPCT) in the key PDs' boot seeds.

  The DRBG is instantiated with a zero hedge. The PD's own hedge is the
  outer construction's key.
  **Why:** the property C7 locks (an output needs the rng seed and the
  PD's hedge seed; fast key erasure; a reseed that combines) holds with
  the hedge one layer up, and the change stays one line per PD. It also
  covers the planned two-phase instantiation of the key PDs:
  - their salt draws need only the rng seed;
  - their boot seed hashes the blob seed with the DRBG's output.

  So no phase-2 re-instantiation is needed. `ingress` has no outer hedge,
  as planned (RM7-2).
- **What:** the DRBG crate's PRF is a trait, `HmacSha256` for every PD.
  The Kani harnesses use a model PRF that proves the state machine: the
  bound, the wrap, key replacement and reseed reset. The unit tests check
  the real construction against HMAC known answers.
- **What:** a key PD whose `rng` gives no seed calls `tpm2::boot::unseal`
  anyway. Its salt draw fails, so the unseal fails as `UnsealError::Rng`
  (formerly `Rndr`), `tpm` receives Failed and caps without waiting, and
  the PD answers Unavailable with `RngUnavailable` (code 9, formerly
  `RndrUnavailable`). R3 FN-R3-2 is met without a special path.
- **What:** renames:
  - `HedgeHw::rndr` becomes `HedgeHw::random` (tls-core, rosenpass-core);
  - `halt::RNDR` becomes `halt::RNG` (pq, tls);
  - `UnsealError::Rndr` becomes `UnsealError::Rng`;
  - `BootError::RndrUnavailable` becomes `BootError::RngUnavailable`.

  The codes are unchanged. P25 forbids `fn rndr`, so the names had to go.
- **What:** each leaf PD's halt module gains `RNG_UNAVAILABLE` (hs 4,
  pq 7, ingress 7, tls 5). It is audited as `Halted`, with no separate
  event: the rng reason word (quota, device, short, zero, stuck) is not
  audited. Turning these halts into dormant boot stops is slice 5 (C9).

### C6: the rng PD

- **What:** passive, as `tpm` and `key` are, so each request runs on its
  caller's scheduling context; priority 147, above every caller.
  It has no IRQ: one request at a time is polled against a CNTPCT deadline
  (`RNG_POLL_NS`, 100 ms).
- **What:** a missing device, a failed init or unset symbols leave the PD
  up with no device, answering every request `UNAVAILABLE`.
- **What:** the seed travels in four message registers, which fit the
  registers a reply carries without touching the IPC buffer.
- **What:** `rng_dma` is one 2 MiB page, as the NICs' DMA regions are, so
  the virtqueue's physical addresses are contiguous.
- **What:** rng-core keeps its own copy of the CNTPCT token bucket, as
  key-core, pqkey-core and tlskey-core each do. A shared crate would give
  rng-core an edge to a key crate.

### C10: laws

- **What:** the `rng` role is in:
  - a device mr with `rng = true`, pinned at 0x0a000000/0x1000;
  - DMA ownership and `setvar` are allowed;
  - the L1 exemption has key's shape;
  - its peers must be `key` or `untrusted_input`;
  - a key PD may hold one pp channel to tpm and one to rng.

  Eleven fixtures pin these.
- **What:** the rest of C10 (the supervisor, the recursive parser, PD
  counting) is slice 5.

### P6 (partial)

- **What:** on cortex-a72 with the rng PD, the wireguard boot passes all
  14 cases, the MCE handshake cost case among them. The full run's timing
  is recorded below once it completes.

## Slice 5 (C8, C9, C10's supervisor parts, C11's harness)

### C8: the supervisor

- **What:** priority 40, below `audit` (50), as P3 allows: `audit`
  preempts it on the notify and prints the record before the reset. The
  timer-ordering wait is not built.
- **What:** the record page write is the crate's one `unsafe`, so it sits
  in the reset module beside the SMC (`reset::write_record`). The plan
  allows `unsafe` only there, and a second module for one volatile write
  would need its own allowlist entry.
- **What:** the allowlist check is a workspace tool,
  `tools/supervisor-allowlist`, built on `syn` (already locked), run by
  `make pins`. Its rules are S1-S8. The deny fixtures are its unit tests,
  one per plan item; the allow case is the real crate. A listed item's
  associated items (`seL4_ARM_SMCContext::default`) are listed with it.
  Any 32-bit literal with bit 31 set counts as an SMCCC ID, so a second
  ID cannot hide as a plain constant.
- **What:** under the release kernel (hypervisor support on, no
  HARDWARE_DEBUG_API), a panic's abort trap reaches the supervisor as
  label 8, not the debug configuration's 4 (P5). A stack overflow reaches
  it as label 6 (VMFault). The supervisor resets on any label, so this
  changes nothing it does.
- **What:** `fault-inject` triggers:
  - `ingress`: frame A and frame B, each a UDP payload on the WireGuard
    port that is no WireGuard message (A panics, B halts with
    `FAULT_INJECT`, 8).
  - `audit`: faults right after it prints ingress's first
    `WgBadMessage`, a run-time trigger instead of the planned boot-time
    flag. `audit` has an inbound path (ingress's records); a flag would
    need a new MR in the variant's system file and laws.
  - `timer`: has no inbound path at all, so it faults on its 30th tick
    (`FAULT_TICK`), in its own variant image.
- **What:** the variants are packaged by `make package-fault-inject-{net,timer}`.
  The PDs are built with the feature into `$(BUILD)/fault-inject-<v>`;
  the kernel, the C9 harness (`ct_dir`) and the firmware are the main
  build's. Each feature PD carries a `#[used]` marker,
  `KOZANE-FAULT-INJECT-VARIANT`. `tools/release.py` refuses an image that
  holds it, in both `make` and `verify` (`measure.check_not_fault_inject`).
  The selftest injection that builds a release with the feature is
  slice 6.

### C9: boot stops

- **What:** `run_init` closes the one shot on entry, not on return. So a
  `run_init` nested inside init panics too. Kani proves three facts:
  - the first call runs init once;
  - a second call panics, after a first call or after `close`;
  - a nested call panics.
- **What:** every PD enters through `boot_stage::run_init`. The leaf PDs
  that refuse at boot (hs, pq, ingress, tls, data) return
  `pdkit::Stage`; the others call `run_init(|_| start())`.
  - `tls`'s `boot_seed` returns the halt reason, and the caller turns it
    into the boot stop.
  - `inner`, `eth_in` and `eth_out` may enable `boot-stop` but have no
    init refusal to move.
- **What:** each leaf `start` returns `pdkit::Stage<H>` directly, not the
  planned `Result<H, Dormant>`. A refusal is `return
  Stage::Dormant(audit.boot_stop(init, reason))`.
  - The first integration run reset at boot, with `supervisor: fault
    pd=ingress label=6` (VMFault), then `pd=data`: their stacks
    overflowed. The handler, returned by value through `run_init` and
    Microkit's entry, has one more live copy during init. `DataPd` is
    about 57 KiB, and the Result-to-Stage match added another.
  - Even without that match, `data`'s init path measures 174 KiB of
    frames (`start` 114 KiB, `run_main` 61 KiB), so `data` goes from 128
    to 256 KiB (`DATA_STACK_SIZE`; the size assert is now a quarter).
  - `ingress` measures 45 KiB of frames on its init path, against 64 KiB;
    it goes to 128 KiB.
  - Every other PD's init path is at most 7 KiB (tls: 65 KiB of 192 KiB).
- **What:** the C9 link check is a `stage` check in `tools/ct-shape`,
  which already reads every PD ELF's symbols in `make ct-shape` and
  `tools/package`. It requires
  `boot_stage::run_init::<_, <crate>::init::{closure#0}>`, which binds the
  wrapper to the PD's own init, and `<boot_stage::Init>::boot_stop` only in
  `LEAF_ELFS`. It has six fixtures (CT-SHAPE-FIXTURES 65 → 71).
- **What:** the source half is check-pins P26:
  - `boot-stop` appears in no Cargo.toml but the definers (boot-stage,
    pdkit) and the leaf PDs;
  - every PD's single `#[protection_domain]` init body starts with
    `boot_stage::run_init(`;
  - nothing under crates/ names `abort_trap`.

### C10: laws (supervisor)

- **What:** eleven fixtures:
  - the allow case;
  - smc on a child;
  - a PD outside the supervisor;
  - a policy PD missing;
  - two supervisors;
  - a supervisor channel to a tainted PD;
  - a supervisor PPC;
  - a record page `audit` can write;
  - a supervisor owning a device (a policy refusal);
  - a child without an id (a parse refusal);
  - L2 under nesting.

### C11: the harness (part)

- **What:** every boot starts with `-S` and `-no-reboot`, and has a QMP
  socket in a fresh 0700 directory. The harness negotiates QMP, then sends
  `cont`, so no event can precede its reader.
  - A case declares the SHUTDOWN reason it expects: `boot(shutdown=...)`,
    or `child.shutdown` once known, as in measure_boot's refusal branch.
  - `kill()` fails a case, on its success path only, that saw another
    reason or a QEMU exit without a SHUTDOWN.
  - The opt-outs pass `resets=(reason, ...)`: no `-no-reboot`, and
    exactly those RESET reasons. They are S11's monitor `system_reset`
    (`host-qmp-system-reset`) and the supervisor's reboot case
    (`guest-reset`).
  - U-Boot's REFUSE and TF-A's refusals declare `guest-shutdown`.
- **What:** boot-stop cases (no rng, tls key failure, mismatched blob)
  now also assert that no supervisor record was printed.
