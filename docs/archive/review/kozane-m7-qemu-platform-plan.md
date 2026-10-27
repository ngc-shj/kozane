# Plan: kozane-m7-qemu-platform

M7 of [docs/PLAN.md](../../PLAN.md), redefined by the owner on 2026-10-24.
No board combines an MCS-verified kernel, a TPM with firmware-measured boot,
and RNDR. So M7 builds a board-equivalent platform under QEMU, and the
board-only items become recorded residuals:

- SC32: firmware-measured boot, with PCR 0–7 in the seal policy and the EK
  certificate verified at provisioning;
- SC18: an RNG device driver on a CPU without RNDR;
- SC17: the whole-system response to a PD fault;
- an end-to-end boot of the signed release.

Laws L1–L13 are in
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md).
This plan amends L1, L4, L5 and L9 where stated. The M5 contracts it changes
are in [secureos-m5-measured-release-plan.md](secureos-m5-measured-release-plan.md):
"M5 C8" there is the boot command and the measurement model, not this plan's
C8.

Process: contract-first, risk-tiered review, vertical slices with fast
gates, and one solo `make check` at the end. The owner delegated the
decisions ("run to M7, no questions"), so they are recorded here instead of
asked. Finding IDs in brackets (FN = functionality, SE = security, TE =
testing, round 1) point to
[kozane-m7-qemu-platform-review.md](kozane-m7-qemu-platform-review.md).

## Project context

- **Type:** `mixed`. A seL4/Microkit image (no_std Rust PDs), host tools,
  firmware builds, and libraries.
- **Test infrastructure:** unit, Kani, Verus, bolero, the M4 C9/C10 gates,
  QEMU integration and the gate self-test, all behind a local `make check`.
  There is no CI (SC9).
- **Verification environment constraints.** New IDs continue from VE13.
  - **VE2** (existing): QEMU has no root of trust.
  - **VE6** (narrowed by C3): previously U-Boot was the first code to run
    and nothing measured it. Now TF-A BL1 runs first and extends the TPM
    with BL2 before running it.
  - **VE14:** BL1 sits in QEMU's secure flash and stands in for the boot
    ROM. Whoever writes the flash image (the harness) replaces the CRTM.
  - **VE7** (existing): swtpm has no bus and no vendor EK chain. The EK
    certificate comes from a dev CA, so C5 proves the provisioning flow, not
    a vendor's root (RM7-10).
  - **VE15:** virtio-rng is fed by the QEMU host's `/dev/urandom`. The
    driver and the fail-closed paths can be verified. Entropy quality
    cannot.
  - **VE16:** the CPU model is `cortex-a72` (no FEAT_RNG, Armv8.0, the
    RPi4's core). All timing is TCG's. Budgets and timeouts set under
    `neoverse-n2` are re-measured on it (P6).
  - **VE5** (existing): there is no verified board (RM7-9).

### QEMU-verifiable vs board-only

| Area | verifiable-local | board-only (residual, not deferred) |
|---|---|---|
| Firmware-measured boot | BL1 extends BL2, BL2 extends every FIP image and config it consumes, each before use; PCR 0–8 in the seal policy; a changed BL2, BL31, U-Boot or config cannot unseal (C3, C4) | an immutable boot ROM as the CRTM (RM7-1); TPM bus and reset-line attacks (RM5-5) |
| EK / SRK binding | EK cert verified against a pinned CA; the recorded SRK bytes bound to that EK by credential activation (C5) | a vendor EK root (RM7-10) |
| Entropy | the virtio-rng driver, the seed path, the hedge, the fail-closed paths and RNDR's absence, on a CPU without RNDR (C6, C7) | entropy quality (RM7-2) |
| Fault policy | every PD stop reaches the supervisor; a boot-phase stop is recorded and stays stopped, any other fault is recorded and resets (C8, C9) | a hardware watchdog for hangs that do not fault (RM7-3) |
| Release | the signed release, provisioned and booted end to end, PCRs read from the TPM after the shipped boot (C11) | NIC line rate; SC28's InitConf latency on silicon (RM7-8) |

Anti-Deferral for the board-only column: no board exists (owner decision,
2026-10-24). The cost is in each residual's "worst case" line.

## Objective

The signed release boots on a QEMU platform shaped like a real board:

- firmware measures the bootloader and its own later stages into the TPM
  before running them, and the seal policy binds the secrets to that;
- entropy comes from a device driver, hedged with the sealed seeds, with no
  RNDR anywhere;
- a PD fault resets the system, and a deliberate boot-time refusal stays an
  audited, stable stop.

One test boots that release exactly as an operator would.

## Threat model additions

| ID | Adversary | Capability |
|---|---|---|
| A10 | Firmware-media attacker | Rewrites any FIP entry: BL2, BL31, U-Boot with its compiled-in command, and the configs. Cannot rewrite BL1 (VE14). Before M7 this attacker defeated measured boot (VE6). After C3/C4 they boot but cannot unseal. |
| A11 | Remote fault trigger | Any input that makes a tainted PD fault, panic or halt at run time. Today that kills one service for good. After C8 it resets the whole system (RM7-6). |
| A7 | (existing) TPM bus | Unchanged. RM5-5 stays a residual. |

## Feasibility probes (slice 0)

Each probe runs on the real toolchain before the contracts that depend on
it are built, and its observations are recorded in the deviation log. If a
probe refutes a premise, only the contract it names goes back to `pending`
and is re-planned. No contract has a silent fallback.

| ID | Question | Pass condition | Refutes |
|---|---|---|---|
| P1 | Does the current image boot with `-machine virt,secure=on,virtualization=on -cpu cortex-a72` and upstream TF-A (`BL33` = U-Boot) in place of `-bios u-boot.bin`, with the boot media still loaded by `-device loader` and virtio-rng on `virtio-mmio-bus.0`? | VPN and HTTPS readiness lines appear. The sp804 timers (QEMU patch), the secure-world devices and the rng slot do not overlap any mapped page. | C2, C6 (slot), C7 (CPU) |
| P2 | Can TF-A extend the MMIO TIS on QEMU `virt` from BL1 and BL2 through a FIFO_MMIO backend under `drivers/tpm`, with the page mapped non-secure? Which FIP ToC entries do BL1 and BL2 load or parse? Is a QEMU-generated DTB measured? Are PCR 1–7 touched? Where does the event log land? | BL1 starts the TPM and extends BL2 into PCR 0, and BL2 extends the rest. The consumed-entry list, the PCR 1–7 values and the event-log address are recorded [SE3, FN12]. | C3, C4 |
| P3 | Microkit 2.3.1 rules for children. **Tool level, done 2026-10-27:** a parent at priority 10 with children at 200 and 150 (one passive) and `smc="true"` is accepted. The SMC cap is unbadged, and the parent's CNode holds each child's TCB cap. **Run time, still open:** does a child fault reach a lower-priority parent's `fault()`? What are rust-sel4's `fault` and SMC APIs at rev 86a0dbf? | The child fault is delivered, and the API names are recorded. | C8 (ordering, API) |
| P4 | Does PSCI SYSTEM_RESET from a PD (seL4 → TF-A BL31) end QEMU under `-no-reboot` with QMP `SHUTDOWN` reason `guest-reset`? Without that flag, is swtpm reset, so the second boot re-measures and unseals? Can TF-A power off on a measurement failure (reason `guest-shutdown`)? | Reset ends QEMU with that reason. The second boot reaches readiness. TF-A's power-off is observable. | C3 (I3.2 terminal), C8 |
| P5 | What do `panic!`, `pdkit::halt` and an abort do today in a rust-sel4 Microkit PD: fault or spin? Which fault label and syndrome reach a parent for `brk #imm` and for `udf`? | Observed and recorded. | C9 |
| P6 | Do the TCG budgets hold on `cortex-a72`? This covers RM6-8's HS_CAP, the load-sensitive VPN boots, `BOOT_TIMEOUT_S` and `LINE_TIMEOUT_S` with TF-A's boot time, and the two-boot case [TE17]. | Each is re-measured, with the numbers recorded. | C7 (values only) |

## Decisions (recorded, not asked)

- **D1: TF-A extends the TPM directly. Event-log replay by U-Boot is
  rejected.**
  - Under replay, PCR 0 is reported by the very U-Boot it describes. A
    replaced U-Boot (A10) replays the expected digests and unseals, so VE6
    is not narrowed. Replay buys the plumbing and none of the security.
  - Direct extend needs a FIFO_MMIO backend in TF-A's `drivers/tpm` (the
    FIFO logic is shared with the SPI backend), a platform mapping, and the
    BL1/BL2 wiring (P2). It is an in-repo patch over a pinned TF-A release.
  - Rule followed: when in doubt, security first.
- **D2: virtio-drivers 0.13's MMIO transport and virtqueue are reused, but
  not `VirtIORng::request_entropy`** [FN3].
  - The crate is already in `Cargo.lock` for `netdrv`. A second virtio
    stack would duplicate code we own (R1).
  - `request_entropy` spins until the device completes. A PPC handler must
    run in bounded time, so `rng` submits and polls the queue itself
    against a CNTPCT deadline (C6).
- **D3: one platform, and no RNDR.**
  - The CPU model becomes `cortex-a72`, which has no FEAT_RNG, and RNDR is
    removed from every PD (C7). A leftover RNDR raises UNDEF, which C8
    turns into a reset, so execution enforces the removal as well as the
    check.
  - Keeping RNDR behind a flag would double the image matrix for no
    deliverable. PSTATE.DIT does not exist on Armv8.0; M4 R-M2 already
    records it as unchecked.
- **D4: two outcomes for a stopped PD** [FN1, SE9].
  - **Boot stop.** A PD refuses during `init` for a deterministic,
    configuration-shaped cause: no key, no boot seed, no rng, no clock, a
    config hash mismatch. The supervisor records it and does nothing more:
    the PD stays stopped and the rest serves. This is today's audited
    refusal (M5 scenario 3, M6's "tls halted before listening, the VPN
    handshakes"). Resetting would only loop, because the next boot
    reproduces the cause.
  - **Fault.** Any other stop, at any time: an exception, a panic, or a
    run-time halt. The supervisor records it and calls PSCI SYSTEM_RESET.
    The PD's state is unknown, and a fresh boot re-measures and re-unseals.
  - **Who may boot-stop** [R2 FN-N1, SE-N3]: only leaf PDs, the ones no
    PD calls: `hs`, `pq`, `ingress`, `tls`, `data`, `inner`, `eth_out` and
    `eth_in`.
    - The PPC callees (`rng`, `key`, `pqkey`, `tlskey`, `tpm`) never
      boot-stop. On an init failure they stay up and answer `Unavailable`,
      as `key` does today. That way their callers reach their own boot stop
      instead of blocking forever.
    - `audit` and `timer` never boot-stop either.
    - A boot stop from a non-leaf child is handled as a fault.
  - **The class is the PD's own choice.** A boot stop can only be raised
    through the `pdkit` init context (C9). A compromised PD can still
    choose a stop over a reset. That gives it nothing a deliberate spin
    does not (RM7-3), because a stopped PD is never resumed.
  - **Transient seed failures** get a bounded retry before they become a
    boot stop (`RNG_INIT_TRIES`, C7) [R2 SE-N5].
  - **The cost** is A11 amplification (RM7-6): a run-time fault an
    attacker can reach in `tls` now takes the VPN down for one boot time,
    repeatably. Per-PD restart is SC41.

## Contracts

The control classes follow R49. "Gate" means a fail-closed verification
gate unless stated otherwise. Every forbidden pattern below names the gate
that enforces it. Each has a deny fixture with an exact ID and an allow
fixture (the real tree, plus a comment or docs mention that must not trip
it) [TE11, FN8].

### C1 — Dev image: TF-A and mbedTLS sources (Minor tier; mechanical)

- **What is added:** the sources of a tagged TF-A release and the mbedTLS
  release its measured boot needs. Each is a sha256-checked tarball,
  fetched once and built offline, as U-Boot is already built (M5 C1). The
  swtpm-localca and openssl binaries C5 uses come from the pinned apt
  snapshot.
- **Control class:** gate (`check-pins`), adjudicated by the pinned
  digests.
- **Acceptance:** `make pins` is green with one rule per new pin, and each
  rule goes red on a fixture that drops its pin.

### C2 — Reproducible firmware (Major tier)

- **Images:** `make firmware` builds two images from the pinned sources,
  the in-repo TF-A patch (C3) and one build-flag file [FN2, TE1]:
  - `flash.bin` (shipped), with BL33 = `u-boot-shipped`;
  - `flash-measure.bin`, with BL33 = `u-boot-measure`, the M5 measure
    variant. It is used only by the M5 cases.

  Each image is BL1 at offset 0 plus the FIP at its fixed offset.
- **Fixed flags:** `MEASURED_BOOT=1`, `DISCRETE_TPM=1` with C3's MMIO
  interface, `MBOOT_TPM_HASH_ALG=sha256`, a fixed
  `BUILD_MESSAGE_TIMESTAMP`, and no `DEBUG`.
- **Invariants:**
  - **I2.1:** every QEMU boot in the repository goes through one argv
    builder in `run.py`, and the Makefile's `run` uses the same firmware.
    That builder refuses a `-bios` other than the two firmware images.
    There is no unmeasured dev path. The builder also starts a per-run
    swtpm, `make run` included, because without a TPM BL1 refuses
    [R2 FN-N5].
  - **I2.2:** both images are a pure function of the git tree and the dev
    image digest. Their bytes decide PCR 0 (C4).
- **Member set:** `tools/repro`'s artifact list (today `loader.img`,
  `report.txt` and the PD ELFs: `sed -n '31,34p' tools/repro`) gains
  `flash.bin`, `flash-measure.bin`, `bl1.bin`, both `fip.bin` files, and
  both U-Boot binaries [FN11].
- **Control class:** gate, adjudicated by byte equality across two trees
  at different paths.
- **Checks:**
  - The argv builder's assertion: a `run.py` boot with `-bios u-boot.bin`
    must go red, and today's tree would. The allow case is the real tree.
  - A `check-pins` rule positively requires `BUILD_MESSAGE_TIMESTAMP` with
    a fixed value in the flag file. A missing flag file is a refusal, not a
    pass [TE11].
- **Acceptance:** `make repro` covers the firmware. A deny fixture with a
  varying timestamp goes red, naming `bl1.bin` or `fip.bin`.

### C3 — Firmware measures before it uses (Critical tier)

- **Attacker:** A10. They rewrite any FIP entry but not BL1 (VE14).
- **Behaviour:**
  - BL1 initialises the TIS, calls `TPM2_Startup(CLEAR)` and extends
    PCR 0 with BL2 before jumping to it.
  - BL2 extends PCR 0 with each FIP entry it loads or parses, before using
    it. The closed list comes from P2 (images and configs).
  - BL2 writes the TCG event log and hands it to BL33. The log is
    informational, for SC31 and the replay check; the seal does not depend
    on it.
  - U-Boot no longer issues `TPM2_Startup` and never replays a log (D1).
- **Invariants:**
  - **I3.1:** every FIP entry BL1 or BL2 consumes, whether executed or
    parsed, is extended into PCR 0 before it is consumed. The loader,
    kernel and PDs are PCR 8's, as in M5 C8 [FN13, SE3].
  - **I3.2:** any TPM error in BL1 or BL2 (init, startup, extend) stops
    the boot. The stop prints one fixed error line and powers off, so
    nothing boots unmeasured. Startup returning anything other than
    `TPM_RC_SUCCESS` is an error, `TPM_RC_INITIALIZE` included [SE8]. The
    stop is permanent until the next reset.
  - **I3.3:** PCR 0 cannot return to its post-reset value without a
    platform reset, and a platform reset re-runs BL1. That is the TPM's
    rule (RM5-5 on a board).
- **Control class** [SE2]:
  - **Enforceable boundary:** BL1's extend of BL2. A10 cannot alter BL1,
    and the TPM holds the result.
  - **Measured, not trusted:** BL2's own extends. A BL2 that skips them
    still changes PCR 0 through BL1's extend.
  - **Fail-closed gate:** I3.2.
  - **Adjudicator:** the swtpm PCR values.
- **Forbidden patterns** (`check-pins`, over `support/u-boot/`):
  - `tpm2 startup` in `boot.cmd`. Reason: startup is BL1's.
  - `CONFIG_MEASURED_BOOT=y` or `CONFIG_EFI_TCG2_PROTOCOL=y` in
    `kozane.config`. Reason: no replay (D1).
- **Acceptance (integration):** PCRs are read host-side, from swtpm after
  the shipped boot, with the selection that generalises `read_pcr8`
  (`grep -n 'def read_pcr8' tests/integration/run.py`) [FN2, TE1]. A
  failed PCR_Read is a named failure.
  - **Allow:** after the shipped boot, PCR 0–7 equal the C4 twin's values
    for `flash.bin`, and the event log replays (host side) to PCR 0. The
    unmodified `flash.bin` unseals (C11).
  - **Deny, one case per stage, each `KeyUnavailable`** [TE2, SE2, R2
    SE-N1, TE-N1]. Each case boots, extends, and does not unseal.
    - **A forging BL2:** changed code that extends exactly the closed
      list of the twin in the tree under test, built from that list, the
      honest BL2's digest included. Only BL1's extend stops it. Because the
      forger follows the twin, it omits BL2 under the BL1-drop mutation
      [R3 TE-R3-1, SE-P1].
    - BL31 changed by one byte, with every extend intact.
    - BL33 changed by one byte (a different boot command), with every
      extend intact.
    - One consumed config changed by one byte, with every extend intact
      [SE3].
  - **Deny, I3.2, one case per path** [TE3, R2 TE-N6]. The A7 proxy
    fails one TPM command, selected by its command code and occurrence. It
    asserts the failed command's code, and for the BL2 case it asserts that
    BL1's extend before it succeeded. A mismatch is a setup failure.
    - Cases: the TPM2_Startup failure, BL1's extend, and BL2's first
      extend.
    - Oracle: the TF-A error line, carrying a stage token (`BL1`/`BL2`,
      `startup`/`extend`), as a failure-only needle. Then QMP
      `SHUTDOWN guest-shutdown` (P4). There is no silence window.
    - Allow pair: the same proxy with the failure off boots to readiness.
  - **Mutations: a consistent drop from both the patch and the twin's
    closed list, then a re-seal.** That is the realistic regression, in
    which both adjudicators agree a stage is unmeasured. Each mutation is
    run, and each turns its own deny into an unseal, which is recorded.
    - BL1's extend dropped: the forging-BL2 deny unseals.
    - BL31 dropped from BL2's extends: the BL31 deny unseals.
    - BL33 dropped: the BL33 deny unseals.
    - The config dropped: the config deny unseals.

    Allow pair: on the unmutated tree, every deny stays `KeyUnavailable`.

### C4 — PCR 0–8 seal policy and its host twin (Critical tier)

- **Constants:** two constants, split [FN5].
  - The **policy selection** is sha256, PCRs {0..8} (bitmap `ff 01 00`).
    PolicyPCR and the envelope's selection field use it.
  - The **cap-read selection** is sha256, PCR 8. The cap's PCR_Read and
    its response check use it.
  - **I4.2:** the cap-read selection is a subset of the policy selection,
    and the twin's selection equals the policy selection. Both are asserted
    in `tpm2-wire` and in `measure.py`.
- **Policy:**
  - PolicyPCR(policy selection) ∧ PolicyAuthValue, as in M5 C11.
  - The cap stays one extend of PCR 8 after the last unseal.
- **Twin:** `measure.expected_pcrs(firmware, desc, image)` → PCR 0–8.
  - PCR 0 is the extend chain over the C3 closed list, computed from the
    C2 artifacts. A FIP holding an entry outside the list is refused
    [SE3].
  - PCR 1–7 take the values P2 recorded (zero expected).
  - PCR 8 is computed as in M5.
- **Consumers (each changes)** [FN5]:
  - `tpm2::crypto::policy_pcr_digest`, which takes 9 PCR values;
  - `mksecrets seal` and `check-envelope`, where `--pcr8` becomes
    `--pcrs`;
  - `tools/package`, which gains a firmware input that `expected_pcrs`
    reads. Its `pcr8` output becomes `pcrs`, and its outputs gain the
    `flash.bin` those PCRs came from. `release.py make` copies that file,
    and the manifest's firmware fields come from the copy. A package whose
    `flash.bin` differs from the one its `pcrs` were computed from is
    refused [R2 FN-N4];
  - `tools/release.py make/verify`;
  - `run.py` (`PCR_READ_8` and the C3 cases);
  - the `tpm2-wire` Kani harnesses over PolicyPCR and PCR_Read, re-run
    with no harness dropped.
- **Release manifest:** adds the firmware digests and the expected PCR 0.
  `verify` recomputes both from the released `flash.bin` and extends the
  existing pcr8 check to the full policy digest. It runs once, not as a
  second, parallel check.
- **Invariant I4.1:** an envelope unseals only when PCR 0–8 equal the
  twin's values for the released firmware, descriptor and image.
- **Control class:** enforceable boundary, evaluated by the TPM. The twin
  is a fail-closed gate on agreement (R48).
- **Acceptance:**
  - **Allow:** the C11 boot unseals. The cap's PCR_Read still checks
    PCR 8 only.
  - **Independent digest:** the package's policy digest for `ff 01 00`
    equals `tpm2_policypcr`'s (pinned tpm2-tools) against swtpm holding
    the twin's values [TE4].
  - **Deny, TPM-level:**
    - The A7 proxy injects one PCR_Extend of PCR 3 before the policy
      session's `TPM2_PolicyPCR` [TE4, R2 TE-N2]. The result is
      `KeyUnavailable`.
      - The proxy logs every response code. The case asserts the
        following, and anything else is a setup failure [R3 TE §3]:
        - the injected extend returned 0;
        - StartAuthSession, PolicyPCR, PolicyAuthValue, Import and Load
          returned 0;
        - Unseal returned exactly 0x99D (TPM_RC_POLICY_FAIL, session 1),
          not 0x9A8 (TPM_RC_PCR_CHANGED).
      - Mutation: drop PCR 3 from both the policy selection and the twin.
        The case then unseals.
      - Allow: the same proxy without the injection unseals.
    - An envelope for another firmware build → `KeyUnavailable`.
  - **Deny, parser-level:** an M5 PCR 8-only envelope is refused by the
    envelope parser's selection check. This is stated as a parser refusal,
    not as the TPM's [FN-A1].
  - **Twin mutation:** drop PCR 0 from the twin, and C3's allow case goes
    red, naming PCR 0.

### C5 — EK-verified SRK at provisioning (Major tier)

- **Inputs:** the swtpm instance, the pinned dev EK CA (`support/keys`, a
  dev key as RM5-1 is; RM7-10), and an empty per-run output directory.
- **Flow, in order. The tool fails at the first failing step** [SE6]:
  1. Verify the EK certificate's chain to the pinned CA. Check that the
     certificate's public key equals the TPM's EK public.
  2. Read the SRK's TPM2B_PUBLIC once. Check it against
     `SRK_PUBLIC_PREFIX` (fixedTPM, fixedParent, restricted, decrypt), the
     existing `tools/package` check.
  3. Compute the SRK's name on the host from those bytes.
  4. TPM2_MakeCredential (host) to the certificate's EK public, naming
     that name. Then TPM2_ActivateCredential (TPM), and compare the
     secret.
  5. Only then write those same bytes, atomically, as the SRK record that
     `tools/package` seals to.
- **Invariant I5.1:** no envelope is sealed to SRK bytes other than the
  ones activated against an EK that chains to the pinned CA.
- **Control class:** gate at provisioning, adjudicated by the X.509 chain
  check and the TPM's ActivateCredential. Any tool error, missing input or
  unreadable certificate is a refusal with a named cause.
- **Isolation** [TE13]:
  - Everything lives in one per-run directory, removed in `finally`: the
    swtpm-localca config and state, the second CA, both swtpm states, and
    the output.
  - A directory that survives the removal fails the case, as with
    `Swtpm`.
- **Acceptance:**
  - **Allow:** the provisioned state, with the record byte-equal to the
    activated public.
  - **Deny, each exits non-zero, writes no record, and its needle names
    the cause:**
    - an EK cert from another CA;
    - an EK cert that does not match the TPM's EK;
    - no EK cert;
    - an SRK public from a second swtpm (activation fails);
    - an SRK public with fixedTPM clear.
  - A new manifest counter covers the C5 fixtures and joins the `pins`
    count.

### C6 — `rng` PD: virtio-rng driver and seed oracle (Critical tier)

- **Attacker:** a tainted caller issuing arbitrary requests. The device
  (the QEMU host) is trusted for entropy (VE15) but not for descriptor
  contents (L7).
- **Interface:**
  - A new role, `rng`. One PD owns the virtio-rng transport, pinned on
    `virtio-mmio-bus.0` (page 0x0a000000, which no other device uses), and
    its DMA MR [FN4].
  - The transport mode is the QEMU default the NICs already use. No
    global `force-legacy` change.
  - One PPC label, `Seed`. It returns 32 bytes in message registers, or
    `Unavailable`.
  - **Without a working device:** a failed init or a missing device
    leaves `rng` up, answering every `Seed` with `Unavailable` (D4). It
    never boot-stops.
- **Invariants:**
  - **I6.1:** a `Seed` reply holds 32 bytes the device returned for this
    request. The bytes are never repeated to any caller, never zero-filled
    and never partial. `Unavailable` covers:
    - a short completion;
    - a device error;
    - no completion before the CNTPCT deadline `RNG_POLL_NS` (`limits`),
      including a completion at exactly the deadline [FN3, SE7];
    - an all-zero block;
    - a block whose fingerprint equals the previous block's.

    The last two are a stuck-output check, not SP 800-90B: the device
    output is already conditioned. A fingerprint is a hash; the previous
    block itself is never kept.
  - **I6.5** [R2 SE-N4]:
    - Completions are matched to requests by token.
    - A completion that arrives after its request's deadline is discarded,
      zeroized and never returned to anyone.
    - A descriptor and its buffer are not reused until the device has
      returned them.
    - If no descriptor is free, the answer is `Unavailable`.
  - **I6.2:** no copy of a returned seed is kept. The buffer and the
    message registers are zeroized after the reply (L12).
  - **I6.3:** the quota is per caller, keyed by the kernel channel id, and
    charged before the device is touched [SE7].
    - Separate buckets: draining one never empties another.
    - Each `key`-role caller's boot requests are reserved in its own
      bucket.
  - **I6.4:** device-reported lengths are bounds-checked before any copy,
    with a Kani harness on the copy path (as `netdrv`).
- **Callers:** exactly the C7 PD member set. That is the tainted `hs`,
  `pq`, `ingress` and `tls`, and the `key`-role `key`, `pqkey` and
  `tlskey`. Each has at most one channel to `rng`, `pp="true"` on its own
  end.
- **Taint and laws (C10):**
  - `rng` stays untainted under an L1 exemption shaped like `key`'s.
    - Every channel to it has `pp="true"` and `notify="false"` on the
      peer end.
    - It maps only its device page and its DMA MR.
    - It has no channel other than those from its callers.
  - L5 gains the rng page.
  - Priority: `rng` sits above every caller (the Microkit PPC rule).
- **Control class:** enforceable boundary (capability layout, C10) for who
  reaches the device. The code properties I6.1–I6.4 are covered by unit
  tests and Kani.
- **Acceptance:**
  - **Unit, deny next to allow:**
    - stuck, zero, short and deadline cases. A completion one poll before
      the deadline is served. The deadline itself is `Unavailable`.
    - quota: a tainted caller at exactly its quota is served, and the next
      request is `Unavailable`. A `key`-role caller still gets a seed
      after a tainted caller is drained [TE9].
  - **Kani:** the copy path over arbitrary used-ring lengths.
  - **Unit, late completion:** request A times out and then completes
    late. Request B is served only from its own completion.
  - **Integration, after slice 5** [TE6, R2 TE-N7]: a boot without the rng
    device.
    - The audit shows `Unavailable`.
    - The supervisor gives boot-stop records with the rng reason class for
      exactly `hs`, `pq`, `ingress` and `tls`. A missing or an extra record
      fails the case.
    - `key`, `pqkey` and `tlskey` stay up, answering `Unavailable`.
    - There is no handshake and no TLS (L9).
    - In slice 4 the interim oracle is the same set of `Halted` lines.
  - **Integration, allow:** a boot with the device serves.

### C7 — Hedged DRBG in every consumer; RNDR removed (Critical tier)

- **Member set (R42)** [FN10]:
  - PDs: `grep -rlE 'cpu::(rndr|fill_random)' crates/pds` returns `hs`,
    `ingress`, `key`, `pq`, `pqkey`, `tls` and `tlskey`.
  - Primitive: `grep -rl 's3_3_c2_c4_0' crates tools support` returns
    `crates/cpu/src/lib.rs`.
  - Hardware-trait members:
    `grep -rnE 'fn (rndr|random)\b|HedgeHw|HedgedEntropy|Hedged' crates --include=*.rs`.
    The known members are:
    - hs-core `HedgedEntropy` and `Hardware::random`;
    - rosenpass-core `kem::Hedged` and `HedgeHw::rndr`;
    - tls-core `Hedged`;
    - the boot seeds in key-core and pqkey-core;
    - tlskey-core's boot seed and its per-signature `extra`;
    - tpm2 `Transport::random`.
  - Phase 2 re-derives the set, and any delta is a finding.
- **Construction (locked)** [SE4]:
  - One no_std DRBG crate replaces every member above. Its PRF is a keyed
    hash the consumers already link. Slice 4 picks one of HMAC-SHA256 or
    keyed BLAKE2s-256 and uses it everywhere.
  - State K, 32 bytes, and a draw counter `ctr`.
  - **Draw**, one 32-byte block per `ctr`:
    - out = PRF(K, "out" ‖ ctr ‖ CNTPCT), then K ← PRF(K, "next" ‖ ctr),
      then ctr += 1.
    - A longer draw takes one block per `ctr`, with K replaced after each
      block.
    - `ctr` and CNTPCT are fixed-width u64 LE, and the labels are distinct
      fixed strings [R2 SE-N6].
  - **Reseed:** K ← PRF(K, "reseed" ‖ rng_seed). This combines with the
    old K; it never assigns K.
  - **Instantiate:** K = PRF(hedge_seed, "init" ‖ rng_seed). The
    `hedge_seed` is [SE5]:
    - for `key`, `pqkey` and `tlskey`, their blob seed, as today;
    - for `hs`, `pq` and `tls`, the boot seed they already receive from
      their key PD;
    - for `ingress`, none. Its K is PRF(0³², "init" ‖ rng_seed). This is
      accepted because of the impact: a predictable cookie secret defeats
      only the cookie DoS gate. Rotation is not a mitigation, because it
      draws from the same DRBG [R2 SE-N6].
  - **Two phases for `key`, `pqkey` and `tlskey`** [R2 FN-N2]. The unseal
    itself needs randomness (the salted session's ephemeral) before the
    blob seed exists.
    - **Phase 1:** K0 = PRF(0³², "pre" ‖ rng_seed). It serves only the
      unseal's salt draw.
    - **Phase 2:** after the unseal, K = PRF(blob_seed, "init" ‖ K0).
    - Any draw other than the salt in phase 1 is an error, and a unit test
      pins it.
    - If the unseal fails, no phase-2 K exists, and every later draw is
      refused (`Unavailable` to callers).
    - K0 is zeroized once phase 2 derives K, and also when the unseal fails
      [R3 SE-P2].
    - A phase-1 failure (no rng seed) still goes through the existing
      unseal entry as the entropy error. That way `tpm` receives Failed and
      can cap PCR 8 without waiting out its barrier. On success, Done is
      still sent [R3 FN-R3-2].
- **Invariants:**
  - **I7.1:** no PD executes RNDR. `cortex-a72` enforces this by faulting
    (D3), and the forbidden pattern enforces it too.
  - **I7.2:** an output needs an instantiation, this boot, from both an
    rng seed and the PD's hedge seed. The only exceptions are `ingress` and
    phase 1's salt draw.
    - Instantiation tries `Seed` up to `RNG_INIT_TRIES` times.
    - After the last failed try:
      - a leaf PD boot-stops (D4);
      - a key-role PD stays up and answers `Unavailable`.
    - Draws 0 to `RESEED_DRAWS`−1 after the last successful reseed
      succeed.
    - Draw number `RESEED_DRAWS` needs a successful reseed first;
      otherwise it fails, and the handshake or signature is refused (L9)
      [TE19].
  - **I7.3:** a wrap of `ctr` fails the draw.
- **L9 amended:** "no rng seed and hedge seed this boot, or no reseed
  within `RESEED_DRAWS` → no handshake".
- **Control class:** enforceable boundary for I7.1 (the CPU faults). The
  code properties are covered by Kani and unit tests.
- **Forbidden patterns** (`check-pins`):
  - `s3_3_c2_c4_0` and `cpu::rndr|cpu::fill_random|fn rndr`, scanned over
    `crates/` (I7.1).
  - `neoverse-n2` anywhere outside `docs/` (D3).
- **Budgets:** the L13 values change only through `laws.toml`, with the
  P6 measurement recorded (RM6-8 restated).
- **Acceptance:**
  - **Kani:**
    - K changes on every draw.
    - The reseed output depends on both the prior K and the seed.
    - A failed reseed at the bound fails the draw.
    - No wrap.
  - **Unit:**
    - The same rng seed with different hedge seeds gives different
      output, with the same pair as the allow side [SE5].
    - The `RESEED_DRAWS` boundary on both sides.
  - **Mutation (slice 5, needs C8)** [TE15]: plant a raw `s3_3_c2_c4_0`
    read in `hs`'s handshake path. The first handshake faults, and the
    case's needle names the supervisor's reset record.

### C8 — `supervisor` PD: fault → audit → PSCI (Critical tier)

- **Attacker:** A11 (it makes any child stop) and any tainted PD. Neither
  reaches the supervisor except through the kernel's fault message.
- **Structure:**
  - The `supervisor` is the Microkit parent of every other PD. Member set
    (R42): `grep -c '<protection_domain' system/kozane.system` gives 14
    today. With C6's `rng` there are 16 PDs and 15 children [FN11].
  - C10 checks that the children equal every other PD.
  - `fault()` reads the child id, the fault label and, for a user
    exception, the syndrome word (P5). Nothing else.
- **Action:**
  - **Boot stop** (C9's dedicated exception, from a leaf child only):
    write the record (`child`, `boot-stop`, reason class), notify `audit`,
    and leave the child stopped. No reset.
    - The reason class is decoded from the `brk` immediate through a
      closed enum.
    - An unknown immediate, or a boot stop from a non-leaf child, takes
      the fault path [R2 SE-N3].
  - **Records** go into a ring of at least one slot per child. Overflow is
    counted, and the count is printed with the next record. So the boot
    stops of scenario 3, all at once, are not lost [R2 SE-N5].
  - **Any other fault:**
    1. Write the record (`child`, `label`).
    2. Notify `audit`.
    3. Let `audit` drain. If P3's run-time check confirms fault delivery
       to a lower-priority parent, the supervisor runs just below `audit`,
       and `audit` preempts it on the notify. Otherwise the supervisor
       waits for one `timer` tick longer than `audit`'s period.
    4. Call PSCI SYSTEM_RESET (0x84000009).
  - **Exception:** when the faulting child is `audit` or `timer`, step 3
    is skipped.
  - No fault is ever replied to, so the child stays stopped.
- **Supervisor reach:** it holds every child's TCB cap and an unbadged
  SMC cap (P3, observed). It is therefore in every PD's TCB, `key`
  included (RM7-5). What it may use is constrained by an allowlist, not a
  denylist [SE1]:
  - **Every path node is checked** [R2 SE-N2]: `use` items, expression
    paths and type paths, fully qualified ones included. A path rooted in
    `sel4` or `sel4_microkit` must be on a fixed list: the handler and
    fault types, the audit record writer, and the reset module.
  - `unsafe`, `Cap::from_bits`, `Cap::from_cptr`, `CPtr`, any
    `sel4::cap::Tcb` or `.tcb()` use, the whole `tcb_*` method family, and
    the SMC invocation may appear only in the one reset module.
  - That module builds exactly one SMCCC function ID, SYSTEM_RESET.
    SYSTEM_OFF is not used.
  - The fault-to-action function is pure and Kani-exhaustive over (label,
    syndrome, child).
- **Invariants:**
  - **I8.1:** every non-boot-stop fault ends in SYSTEM_RESET within a
    bound derived from the L13 budgets in the chosen ordering, as recorded
    by P3. In the timer ordering, I8.1 depends on a live `timer`. A fault
    in `timer` skips the wait [SE10].
  - **I8.2:** no child is resumed after any stop.
  - **I8.3:** the audit record precedes the reset whenever `audit` and
    `timer` have not faulted and `audit` has budget. This is best-effort;
    I8.1 holds regardless.
  - **I8.4:** the supervisor maps no device and holds no secret MR. Its
    only shared MR is the record page, mapped `r` in `audit`. Its channels
    are the outward notification to `audit` (`notify="false"` on audit's
    end) and, in the timer ordering, the tick from `timer`. It has no PPC.
- **Taint and laws (C10):**
  - A new L1 exemption for role `supervisor`, of exactly the I8.4 shape.
  - L4 permits child `protection_domain` and `smc` only on the
    `supervisor`.
- **Control class:**
  - **Enforceable boundary:** who can reset the machine. No other PD has
    `smc`, and C10 checks that.
  - **Best-effort tripwire:** what the supervisor does with its caps. The
    allowlist check runs over the supervisor crate's source.
    - Known bypasses: macros that expand to unlisted paths, and code in a
      dependency the crate already uses.
    - Recovery: the crate is small, reviewed, and Kani-proved on its one
      decision function.
    - This is recorded as RM7-5.
- **Allowlist check (`check-pins`):** deny fixtures, each with an exact
  ID:
  - `.tcb()` outside the reset module;
  - `tcb_resume`, `tcb_write_registers` and `tcb_suspend`;
  - `Cap::from_bits` and `from_cptr` outside the reset module;
  - a fully qualified `::sel4::cap::Tcb` in an expression;
  - a second SMC function ID;
  - `unsafe` outside the reset module.

  The allow case is the real crate. A crate the check cannot parse is a
  refusal that names it. The check is path-aware: it parses the crate with
  a Rust parser, not a regex.
- **Variant:** cargo feature `fault-inject`, in a selftest variant image
  only.
  - `ingress` faults on magic frame A and runtime-halts on frame B.
  - `audit` and `timer` fault on a boot-time flag [TE8].
  - The release build refuses the feature, and a selftest injection
    building the release with it must fail, naming the feature [TE12].
- **Acceptance (integration):** every boot runs with `-no-reboot` and a
  QMP socket (C11's harness change). The cases:
  - **Inject A:** the record names `ingress`, then QMP reports
    `SHUTDOWN guest-reset`. The audit needle is gating only in the
    preemption ordering, and informational in the timer ordering [TE7].
  - **Inject A without `-no-reboot`** (the one opt-out): a second boot
    reaches readiness, re-unseals and serves.
  - **Inject in `audit`, then in `timer`:** `guest-reset`, with no
    record required.
  - **Mutation: `fault()` resumes.** The mutation keeps the record write
    and replaces only the reset with a reply [R2 TE-N8]. It is detected by
    positive evidence: a second record for `ingress` (the resumed child
    re-faults), or `ingress` answering after frame A. A wall-clock bound is
    a hang guard only.
  - **Kani:** a boot stop from each non-leaf child, and an unknown
    immediate, both map to the fault path.
  - **Boot stop:** a placeholder-secrets boot gives the `tls` boot-stop
    record. The VPN still handshakes (the existing M6 case, re-asserted
    with the record).

### C9 — Every PD stop reaches the supervisor, in the right class (Major tier)

- **Member set:** every PD binary in `$(pds)`, and every halt call site:
  `grep -rn '\.halt(' crates/pds` gives 25 sites today.
- **Interface:**
  - A boot stop is available only on an `Init` context [R2 FN-N3,
    SE-N3, TE-N5].
    - `Init` lives in a host-buildable crate in `host_crates`. It has a
      private constructor, and no `Clone`, `Copy` or `Default`.
    - The entry wrapper lives in that same crate [R3 FN-R3-1]:
      `run_init<T>(f: impl FnOnce(&Init) -> T) -> T`. `pdkit`'s PD entry
      calls it from Microkit's `init` for every PD and re-exports nothing
      else. A PD that enters through `#[protection_domain]` directly is a
      `check-pins` deny, so every PD's `init` consumes the one shot
      [R4 FN-R4-1, R4-2].
    - The wrapper is one-shot. A static flag closes when `run_init`
      returns, and also on pdkit's first handler entry. A later call raises
      the generic fault instead of creating an `Init`. So a handler that
      calls `run_init` at run time resets the system rather than
      boot-stopping.
    - `Init` is borrowed, not `'static`, so `f` cannot keep it.
    - The boot-stop `brk` immediate is emitted only in that crate. A
      `check-pins` rule enforces this, with a fixture. The asm is gated on
      `target_os = "none"`, and the doctests and the host tests are
      target-independent (x86_64 hosts included) [R3 TE-R3-3].
    - Key-role, `rng`, `tpm`, `audit` and `timer` ELFs must not contain the
      boot-stop symbol (C9 link check).
  - Every existing init-time halt site moves to it. Run-time halts, the
    three in `tls` among them, stay on `pdkit::halt`.
  - A boot stop executes a dedicated `brk` immediate. Any other stop path
    (`halt`, panic, abort) executes the generic one, and the shared abort
    hook routes panics there if P5 shows rust-sel4 spinning.
- **Invariants:**
  - **I9.1:** every stop routed through `pdkit` or the panic/abort hook
    reaches the supervisor as a fault of the right class.
  - **I9.2:** a boot stop is unreachable after `init` returns, because
    rustc enforces the lifetime.
- **Control class:** code property, linked in every PD. A spin or a
  blocked wait that never stops is not covered (RM7-3) [SE10].
- **Link check:** the M4 C10 ELF check gains a rule: every `$(pds)` ELF
  contains the hook symbol. Red-proof: one PD built without it. Allow: the
  real tree [TE12].
- **Acceptance:**
  - Inject B gives `Halted`, then the reset record, then `guest-reset`.
  - The C6 no-device boot gives boot-stop records.
  - Doctests in the `Init` crate, counted under its UNIT key:
    - `compile_fail,E0597` or `E0521` for keeping `Init` past `init`;
    - `compile_fail,E0451` or `E0603` for constructing it;
    - a host unit test that a second `run_init` takes the fault path, and
      that the first takes the boot-stop path. A first call made after the
      flag has closed on handler entry also takes the fault path;
    - an allow doctest in which `init` uses it.

    Red-proof: make it `'static` or public, and the compile-fail doctest
    goes red.
  - The link check gains a deny: `key` linking the boot-stop symbol.

### C10 — Laws checker amendments (Critical tier; a gate other contracts lean on)

- **Parser** [FN6]:
  - The SDF is parsed recursively, children included. Every existing law
    is evaluated on every PD at any depth.
  - The checker counts the parsed PDs. A count different from the policy's
    declared PD set is a refusal, not a pass.
- **Changes:**
  - roles `rng` and `supervisor`, with their exemptions (C6, I8.4);
  - L4: child `protection_domain` and `smc` only on the `supervisor`, and
    its children equal every other PD;
  - L5: the rng page;
  - the rng caller set: at most one channel each, `pp` on the caller end;
  - priority ordering: `rng` above its callers, and the supervisor where
    P3 places it.
- **Control class:** gate, adjudicated by the same parser and the same
  file Microkit consumes.
- **Acceptance:** every deny fixture has an exact ID and an adjacent allow
  fixture [TE10].
  - **Existing laws under nesting:** one existing deny fixture per law
    (L1, L2, L3, L5, L13), rewritten as a nested child. It must still give
    the same ID.
  - **`{L4}` denies:**
    - `smc` on `audit`;
    - a child PD outside the supervisor;
    - a PD missing from the supervisor's children.
  - **`{L1}` denies:**
    - the supervisor with a channel from `ingress`;
    - the supervisor with a PPC;
    - the record page mapped `rw` in `audit`;
    - `rng` sharing an MR with `hs`;
    - `rng` with `notify="true"` on a peer end;
    - `key` → `rng` without `pp`;
    - `hs` → `rng` without `pp`;
    - `key` with two channels to `rng`;
    - `data` → `rng`.
  - **`{L5}` denies:**
    - a second PD mapping the rng page;
    - the rng MR on a NIC page;
    - `rng` mapping a second device;
    - the supervisor mapping a device.
  - **`{L13}` deny:** `rng` below one of its callers.
  - **Allow:** `kozane.system` passes.

### C11 — End-to-end release boot (Major tier)

- **Flow, in the order the tools require** [FN9]:
  1. Provision with C5.
  2. `make package` seals to that SRK at PCR 0–8.
  3. `make release` builds the signed manifest over the image, the
     descriptor and `flash.bin`. `loader_img_sha256` binds every PD byte,
     so no per-PD field is added.
  4. `tools/release verify` checks the signatures, the firmware digests
     and the policy digest.
  5. One QEMU command boots exactly the verified files.
- **The boot:** the shipped `flash.bin`, swtpm, virtio-rng, `cortex-a72`,
  `-no-reboot`, and QMP. The harness asserts that the sha256 of `-bios` and
  of each `-device loader` file equals the verified manifest [TE14].
- **Assertions:**
  - PCR 0–7 read host-side equal the manifest's twin values. PCR 8 equals
    the twin's value plus the cap.
  - A WireGuard+Rosenpass handshake and an HTTPS request are served.
  - No supervisor record appears anywhere in the whole log after serving.
    Inject A is the positive pair that proves records print [R2 TE-N9].
- **Harness change for every existing case** [TE5]:
  - `boot()` passes `-no-reboot`, `-S` and a QMP socket by default.
    - The socket is a UNIX socket, mode 0700, in the per-run directory,
      never TCP. It is removed in `finally`, and a failure to create it is
      a named refusal [R2 SE-N7].
    - `cont` is sent only after `qmp_capabilities`, so an early SHUTDOWN
      cannot be lost [R2 TE-N4].
  - Each case declares its expected SHUTDOWN reasons, empty by default
    [R2 TE-N3]:
    - the M5 REFUSE and measure cases expect `guest-shutdown`;
    - the S11 `system_reset` case is a second named opt-out of
      `-no-reboot`;
    - both opt-out cases assert their QMP `RESET` events exactly
      [R3 TE-R3-2]. S11 expects one `host-qmp-system-reset`, and "Inject
      A without `-no-reboot`" expects one `guest-reset`.
  - The failure rules:
    - A reason outside the declared set fails the case, naming the last
      supervisor record.
    - QEMU EOF without a SHUTDOWN event is a named failure, never a pass.
  - Red-proofs:
    - A REFUSE case that gets `guest-reset` goes red.
    - A QEMU killed mid-boot reports "no SHUTDOWN event".
  - Red-proof: the `fault-inject` image under one ordinary serving case,
    with frame A sent, goes red.
- **Control class:** gate (a selftest case and `make check`).
- **Acceptance:**
  - The case is green.
  - Deny: `verify` refuses a manifest with one firmware digest flipped.
  - Deny: a boot of a package sealed to the wrong SRK gives boot-stop
    records for exactly `hs`, `pq` and `tls`, and no handshake
    [R2 FN-N6, TE-N7].
  - Deny: a `fault-inject` image differs from the manifest's
    `loader_img_sha256`.
  - Each deny has a failure-only needle.

## Consumer-flow walkthroughs

- **C4 twin → `mksecrets seal` (via `tools/package`):** it reads
  `{pcr[0..8]}` and computes the PolicyPCR digest over the policy
  selection, then ∧ PolicyAuthValue. The result becomes the sealed
  object's authPolicy, and the envelope records the policy selection.
- **C4 twin → `tools/release.py`:** `make` reads `{firmware digests, pcr0,
  pcrs}` from the package and writes them into the manifest. `verify`
  recomputes the firmware digests and PCR 0 from `flash.bin`, then the
  policy digest, and compares both with the manifest and the envelope.
- **C4 twin → `run.py`:** it reads `{pcr[0..8]}` and compares them with
  the host-side PCR_Read after the shipped boot. It reads the event log at
  the P2-recorded address for the replay check.
- **C6 → C7 DRBG:** it reads `{status, seed[32]}`. On `Seed` it reseeds
  or instantiates by combining (C7). On `Unavailable` it applies I7.2.
- **C8 record → `audit`:** it reads `{child id, class, label or reason}`
  and maps the child id to a PD name through the `crates/layout` table.
  That table's test checks it against the `id`s in `kozane.system`
  [FN11]. It prints one line.

## Testing strategy

| Layer | What | Classification |
|---|---|---|
| Unit / Kani | DRBG (C7), supervisor decision (C8), rng copy, stuck, deadline and quota (C6), tpm2-wire selections (C4) | verifiable-local |
| Compile-fail | `Init` context cannot escape `init` (C9) | verifiable-local |
| Laws | C10 fixtures, exact-ID, deny+allow, existing laws re-run under nesting | verifiable-local |
| Pins / repro / ELF | C1 rules; the C2 firmware in `make repro`; C2, C3, C7 and C8 source rules; the C9 hook-link rule | verifiable-local |
| Provisioning | C5 allow + five denies, per-run isolated | verifiable-local |
| Integration | C3 stage denies and I3.2 paths, C4 TPM-level denies, C6 no-device boot, C7 planted-RNDR mutation, C8/C9 inject and boot-stop cases, C11 end to end | verifiable-local |
| Self-test | one injection per new gate; existing injections re-targeted | verifiable-local |
| Board-only | RM7-1…RM7-10 | residual (no board, owner decision) |

Bookkeeping, a slice obligation [FN7, TE16]:

- Re-target or retire every existing `check-selftest` injection whose
  needle text a slice rewrites:
  - `policy_pcr_digest(pcr8)`;
  - `tls-core` `self.hw.rndr()`;
  - the `tls` PD attribute strings and its `<map>` indentation, which
    nesting moves;
  - the boot.cmd edits after `tpm2 startup`.
- Prove each re-targeted injection red by running it. An injection whose
  needle text is absent is a self-test error.
- Update the manifest counters (PDs 14→16, lint and MIR crates, repro
  artifacts, Kani harnesses, integration cases, the C5 counter) and the
  selftest-split enrolment of every new boot.

Kani never runs in parallel with another Kani run. During development
only the gates for what changed run. `make check` runs once, alone, at
the end.

## Residuals (RM7)

- **RM7-1.** BL1 is the CRTM, and on QEMU it is replaceable (VE14).
  - Worst case: whoever writes the flash defeats measured boot. On QEMU,
    that is the harness.
  - Close on a board: a boot ROM.
- **RM7-2.** Entropy quality is the host's (VE15).
  - Worst case: a weak host RNG. Every PD except `ingress` keeps the
    sealed hedge seed, so a predictable rng seed alone does not make its
    output predictable.
  - `ingress`'s cookie secrets do become predictable, which affects only
    the cookie DoS gate.
  - The key PDs' phase-1 salt draw (C7) is unhedged, as today's
    RNDR-plus-CNTPCT salt is [R3 SE-P2]. Worst case, a weak rng together
    with RM5-5: a passive bus snooper derives the salted session's key and
    reads the KEK. On QEMU there is no bus.
- **RM7-3.** No watchdog. A PD that hangs or spins without stopping is not
  detected; i6300esb would need PCI enumeration, about a week.
  - Worst case: one service stops for good, as today.
- **RM7-4.** A fault in the supervisor goes to the monitor, which only
  prints it.
  - Worst case: the fault policy is lost until reboot. Its inputs are
    three kernel-supplied words.
- **RM7-5.** The supervisor holds every child's TCB cap and an
  unrestricted SMC cap. It is in every PD's TCB, constrained by the C8
  allowlist tripwire and Kani.
- **RM7-6.** A11 amplification. Any run-time fault an attacker can reach
  resets the whole system, repeatably (D4).
  - Mitigation: the no-panic lints and the parser proofs.
  - A deterministic run-time fault right after boot loops.
  - Close: per-PD restart (SC41).
- **RM7-7.** RM5-5 is unchanged: TPM bus and reset-line attacks.
  Board-only.
- **RM7-8.** NIC line rate and SC28's InitConf latency need silicon. SC28
  is closed as this residual.
- **RM7-9.** No verified-platform claim. Microkit is MCS-only, and
  AArch64 MCS proofs are not expected before Q3/27.
- **RM7-10.** The EK CA is a dev CA in the repo [SE11].
  - Worst case: whoever holds its key mints an EK certificate that passes
    C5. C5 proves the flow, not the vendor root.
  - Close on a board: the TPM vendor's root.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC17 | Closed by C8/C9 (the watchdog part is RM7-3) | M7 |
| SC18 | Closed by C6/C7 | M7 |
| SC28 | Closed as RM7-8 | — |
| SC31 | Explicit TPM2_Quote (the C3 event log is its input) | unscheduled |
| SC32 | Closed by C2–C5, except the board TIS bus (RM7-7) | M7 |
| SC33 | Anti-rollback NV counter (RM5-4) | unscheduled |
| SC39 | Upstreaming the TF-A FIFO_MMIO backend | unscheduled |
| SC40 | First public release: create the repo and push `main` plus the signed tag only, with the owner's go | after M7 |
| SC41 | Per-PD restart instead of whole-system reset (RM7-6) | unscheduled |

## User operation scenarios

1. **Operator provisioning.**
   - The C5 tool verifies the EK chain, activates, and records the SRK
     bytes.
   - `make package` seals to PCR 0–8. `make release` and `verify` follow.
   - The operator copies `flash.bin`, the image, the descriptor and the
     envelopes.
2. **A10 swaps U-Boot** for one that skips PCR 8.
   - The device boots, and PCR 0 differs, so the envelopes stay sealed.
   - `key`, `pqkey` and `tlskey` answer `Unavailable`, and `hs`, `pq` and
     `tls` give boot-stop records.
   - The system stays up, refusing, with no reset loop. Peers see no
     handshake.
3. **The host has no virtio-rng.**
   - `rng` answers `Unavailable`. `hs`, `pq`, `ingress` and `tls` give
     boot-stop records, and the key PDs stay up, refusing.
   - No handshake and no TLS (L9). The audit names the cause.
4. **A crafted frame faults a tainted PD at run time** (a bug).
   - The audit records the PD, and the system resets and serves again
     after one boot time.
   - Repeated, it is a DoS (RM7-6).
5. **Release verifier.** `tools/release verify` runs on the manifest and
   the device's `flash.bin`. The signatures are valid, and the firmware
   digests and the PCR 0–8 policy digest match.

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Dev image: TF-A + mbedTLS pins | locked |
| C2 | Reproducible firmware, one argv builder | locked |
| C3 | Firmware measures before it uses | locked |
| C4 | PCR 0–8 seal policy and host twin | locked |
| C5 | EK-verified SRK bytes at provisioning | locked |
| C6 | `rng` PD and seed oracle | locked |
| C7 | Hedged DRBG; RNDR removed | locked |
| C8 | `supervisor` PD and PSCI reset | locked |
| C9 | Every PD stop reaches the supervisor, classed | locked |
| C10 | Laws checker amendments | locked |
| C11 | End-to-end release boot | locked |

Slice order:

0. Probes P1–P6 (P3's tool-level part is done).
1. C1, C2: the firmware boots the current image.
2. C3, C4: measured boot and the policy.
3. C5.
4. C10 (the rng parts), C6, C7.
5. C10 (the supervisor parts and the recursive parser), C9, C8, then
   C11's harness change.
6. C11, the solo `make check`, then the long selftest run.
