# Plan: kozane-m9-kvm-client

M9: Kozane runs as a virtual appliance under KVM, and has a client of its
own. The owner's goal (2026-11-01) is something people can operate. For
longevity, QEMU/KVM is the production platform instead of a board. The
owner fixed the scope on 2026-11-03:

- the gateway runs under KVM, on a defined and pinned host configuration,
  with a threat model that states the host is trusted;
- a Rosenpass initiator and a portable client library, with a Linux CLI.
  The library is the base for the Windows, macOS, iOS and Android clients
  after M9.

Transparency logs and witness cosignatures are M10 (SC45), research only
here. This plan narrows two items of the owner's wording (D10, D11) and
widens one (D9: Kozane builds its own SDK, which the platform forces).

"Mn Cn" cites the milestone's plan; laws L1–L14 are in
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md).
Bracketed IDs point to
[kozane-m9-kvm-client-review.md](kozane-m9-kvm-client-review.md) (F
functionality, S security, T testing; round.number).

Process: contract-first, risk-tiered review, vertical slices with fast
gates, one solo `make check` at the end, then the split self-test.

## Project context

- **Type:** `mixed`. seL4/Microkit image (no_std Rust PDs), host tools,
  firmware, a client library with a CLI.
- **Test infrastructure:** unit, Kani, Verus, bolero, laws, ct/ct-shape,
  MIR, repro, QEMU integration and the gate self-test, all behind a local
  `make check`. No CI (SC9).
- **Verification environment constraints.** New IDs continue from VE20.
  - **VE2, VE5, VE7, VE14–VE20** (existing) unchanged.
  - **VE21: KVM only on gx10.** z1mn and mrx33 run Docker Desktop on
    macOS. Its Linux VM has no `/dev/kvm`. `test-kvm` (C6) is
    `verifiable-local` on gx10. Everything else runs under TCG on any
    worker.
  - **VE22: nested virtualization is not enabled on gx10.** `kvm-arm.mode`
    is unset, although the host kernel carries KVM's NV trap handlers. An
    EL2 guest needs a host reboot with `kvm-arm.mode=nested` and FEAT_NV2
    hardware. That is the owner's call → SC46. `blocked-deferred`.
  - **VE23: gx10 memory pressure.** Swap is full while the local LLM
    server runs. KVM guests run one at a time, and never alongside Kani
    (C6's partition lock).
  - **VE24: no Windows, macOS, iOS or Android shells in M9.** The FFI is
    tested from a C harness on Linux → SC47. `blocked-deferred`.
  - **VE25: kernel WireGuard in the workers' user namespaces.** The
    reviewer saw it work on gx10; z1mn and mrx33 (LinuxKit 6.12) are
    unverified. P10 records each host. The `kzc` cases have their own
    gate, `test-kzc`, with its own manifest, so the TCG `make check`
    counts never depend on the host [T2.5, F2.11].
  - **VE26: one uid in `unshare -r`.** Cells that need a second uid cannot
    be created. That covers I10.1's "another owner", and D6's
    `kozane-net`-cannot-open-`wg.sk`. Both are unit-tested against an
    injected `fstat`/`open` result. The real cells are
    `blocked-deferred`: the image has no setuid `newuidmap`, and adding
    one widens the container. The capability model is tested under
    `setpriv --securebits +noroot,+noroot_locked,+no_setuid_fixup`, so
    uid 0 behaves like the unit user [T3.4].
  - **VE28: no systemd in the container.** These are checked only by
    review and by client.md's install test on a real host:
    - the units' sandboxing directives and `ExecStopPost=`, if
      `systemd-analyze` cannot be carried in the image;
    - the dependency directives (`BindsTo=`, `PartOf=`, `Upholds=`,
      `Type=notify` ordering).

    In the harness, the I10.2 restart cells emulate the restart: they
    cover the processes' own start and reconnect paths, not systemd's
    propagation [T6.1]. `blocked-deferred`.
  - **VE27: SDK reproducibility is a host-side gate.** The SDK is built in
    a Dockerfile stage, which `make repro` inside the container cannot
    rebuild. `tools/sdk-repro` runs on the host: two `docker build
    --target sdk`, on gx10 and on z1mn, compared. It prints
    `SDK-REPRO-ARTIFACTS 3` (kernel, loader, tool), checked against a
    committed expectation. It is `verifiable-local` and a milestone-close
    gate, not part of `make check` [T2.3, T3.18]. No M9 gate host runs the
    amd64 image, so the SDK stage is arm64 only in M9 [F3.8, T3.17].

## Objective

1. The same signed release image boots under KVM (`-accel kvm`, gx10) and
   under TCG (every worker) on one pinned machine, with stock QEMU. It
   seals, unseals and serves VPN and HTTPS as today.
2. The supported host configuration has one source. The harness and the
   shipped launcher both derive from it.
3. The threat model and README state what a trusted host means.
4. A Rosenpass initiator in `rosenpass-core` interoperates with upstream
   rosenpass and with the gateway.
5. A sans-IO client library with a C ABI, and a Linux CLI that owns a
   kernel WireGuard interface and keeps its PSK fresh.

## Threat model changes

| ID | Change |
|---|---|
| H1 | **The host is trusted** (new assumption): the hypervisor, QEMU, swtpm and its sockets and state, the launcher and its pin file, and the host admin. A host admin can read guest memory and unseal. This is not defended. |
| H2 | **What the seal protects.** A boot of other media through the pinned firmware cannot unseal. A copy of the media against another swtpm state cannot either. The firmware is outside the seal: any first-stage EL1 code can extend PCR 8 with the public genuine digests [S1.1]. On the supported path, the launcher's firmware pin (I4.2) stops a substituted `u-boot.bin`. Stolen VM files stay protected only if the swtpm state key is off the VM's storage, and guest RAM never reaches host storage (C4) [S1.2, S2.10]. |
| H3 | **The external network attacker** (A1–A9) is unchanged. It is the adversary Kozane exists for. |
| A10 | (changed) **Firmware-media attacker.** The firmware is a host file (`-bios`), pinned by the launcher. |
| A17 | **Malicious or buggy virtio device model** (part of the host, trusted under H1). L7 still protects the parsing PDs from malformed frames. |
| A18 | **Stolen client device.** The thief holds the client's Rosenpass and WireGuard keys. Revocation is M8's bundle under the 15-minute SLA. Group rules bound the reach until then. |
| A19 | **Co-resident guest.** Cross-VM microarchitectural and dedup channels. host.md requires a dedicated host; otherwise SMT off, pinned cores, no KSM (RM9-6) [S1.10, S2.10]. |
| A20 | **Compromised tainted PD against the timer.** With C14, the timer is a system register that seL4's EL0 export opens to every PD. A PD that executes a timer write could freeze or flood the tick that L8 and L13 rely on. Closed by D13's code-property gate [S2.2, F2.4]. The supervisor, which holds every child's TCB, is a declared trusted exception [S3.2]. |

## Feasibility probes (slice 0)

Each probe runs on the real toolchain before its contracts are built.
Observations go to the deviation log. A refuting probe sends only the
named contracts back to `pending`. There is no silent fallback.

| ID | Question | Pass condition | Refutes |
|---|---|---|---|
| P1 | Kozane's EL1 GICv3 kernel (P9) boots to `pq: ready` under TCG with exactly D2's `tcg` argv. Record the SDK board metadata that differs from the EL2 board (`platform_gen.json` RAM base, `vspace_user_top`, vspace object size, kernel load address) | Boots; every PD ready | C1, C2, C15 |
| P2 | The same image under KVM on gx10, `-cpu host`; `query-kvm` enabled | Boots; time recorded | C1, C6 |
| P3 | Without TF-A, U-Boot runs `tpm2 init` and `tpm2 startup TPM2_SU_CLEAR` over `tpm-tis-device`, under TCG and KVM. PCR 8/9 equal the twin, and `tpm` unseals with swtpm started with `--key` | All as stated | C2, C4 |
| P4 | The supervisor's PSCI `SYSTEM_RESET` (seL4's SMC cap) from EL1: (i) under KVM on gx10, recording the host kernel; (ii) under TCG with `virtualization=on`, where QEMU's PSCI takes SMC and Microkit's loader drops from EL2 to EL1 | (i), (ii) each recorded as RESET or not | C3 |
| P5 | gx10: FEAT_NV2 from the ID registers, FEAT_RNG; whether KVM lets QEMU hide FEAT_RNG from `-cpu host` | Recorded | D3, SC46 |
| P6 | Stock QEMU 9.0.0 builds at the image's pins. `virt-9.0` exists, and its `dumpdtb` has no `arm,sp804` node | Recorded | C1, C14 |
| P7 | A host-only initiator on `rosenpass-core` derives the same OSK as upstream (master and 0.2.3) as responder, and as the gateway | OSKs equal | C7 |
| P8 | Wall-clock of today's `make test` on the slowest host of the `qemu` partition, and its projection after C2, C11 and C14 | < 3 h (`CASE_TIMEOUT_S` 4 h) | Testing schedule |
| P9 | Microkit 2.3.1's `build_sdk.py` with seL4 16.0.0 in a Dockerfile stage, for an EL1 board with `KernelArmGicV3`, MCS, one core, P12's timer export. Record every build input: pip packages, cargo lock, cross-compiler, and whether the build runs QEMU to produce the DTB. gx10's KVM disables GICv2 emulation, so the shipped GICv2-only kernels cannot run there [F1.1, F2.6, S2.12] | Builds; inputs recorded; gx10 and z1mn builds identical | C15 |
| P10 | Kernel WireGuard creation (`RTM_NEWLINK` type `wireguard`) and `WG_CMD_SET_DEVICE` after `CTRL_CMD_GETFAMILY`, inside `unshare -rn`, on gx10, z1mn and mrx33 | Recorded per host | C10, C11 |
| P12 | The ARM generic timer from the timer PD. Which timer seL4's EL1 MCS kernel exports to EL0, and the resulting `CNTKCTL_EL1`. Whether the export is per thread (expected: global). Its PPI as a Microkit IRQ. That Microkit 2.3.1's tool maps non-X ELF segments execute-never: record the source line, and add a fault check that executes from an RW page [S3.1]. Ticks at the expected rate under TCG and KVM | Ticks correct; `CNTKCTL_EL1`, scope and XN recorded | C14, D13 |
| P13 | A minimal Kani step lemma on `initiator_state` fits 40 GiB and 1 h | Proves | C7 |
| P14 | QEMU's `-overcommit mem-lock=on` for a 2 GiB guest with `--ulimit memlock=-1` in the container, on gx10, z1mn and mrx33 (today's limit is 8192 KiB, which fails) [F2.1, T3.16] | Boots | C1, D8 |

P11 (a host H-CRTM into PCR 0) is withdrawn: see D1. P4, P9 and P12 are
the main risks. If P9 fails, C1, C6, C14 and C15 stop. The fallback is
SC46 (EL2 under nested KVM), which needs the owner's host decision.

## Decisions (recorded)

- **D1. U-Boot stays the measuring stage. TF-A leaves; no edk2; no host
  H-CRTM.**
  - Under KVM there is no EL3, so M7's BL1/BL2 chain cannot run.
  - edk2, or U-Boot hashing itself, would be self-measurement of a
    host-supplied file. A substituted firmware extends the genuine hash
    [S1.1].
  - A host-side H-CRTM through swtpm (round 2's P11) is withdrawn:
    - Under H1 it binds nothing the launcher pin does not already bind:
      anyone who can bypass the launcher is the host.
    - It needs QMP in the launcher (`-S`, then `cont`).
    - It loses PCR 0 on every in-guest reset, because QEMU re-INITs the
      TPM [F2.2, F2.3, S2.4, T2.9].
  - U-Boot keeps PCR 8 (descriptor, image) and PCR 9 (slots) (M5 C8,
    M8 C4). PCRs 0–7 stay in the seal policy at zero. That is a guard on
    the firmware the operator runs, not a measurement of it.
  - Lost: M7 C3/C4's firmware measurement by the guest's secure world,
    and SC32 as M7 closed it (RM9-1).
- **D2. One pinned machine, stock QEMU.**
  - The machine is `virt-9.0,gic-version=3,mem-merge=off,dump-guest-core=off`.
  - Accelerators:
    - `kvm`: `-cpu host`. Production. `virtualization=on` is never used.
    - `tcg`: `-cpu cortex-a72` (no FEAT_RNG, M7 D3).
  - `virtualization=on` is added only to the TCG reset cases, if P4 (ii)
    is needed. Every other TCG boot enters at EL1 as production does
    [F2.13, S2.9, T2.17].
  - No patched device: sp804 leaves (C14). The dev image builds QEMU
    9.0.0 without the coliasgroup patch.
  - Versioned machine types keep the guest ABI fixed across later QEMU
    releases. That is what makes "QEMU ≥ 9.0 with `virt-9.0`" a durable
    requirement.
- **D3. The EL1 kernel.**
  - seL4's verified AArch64 configurations run the kernel in EL2
    ([verified configurations](https://docs.sel4.systems/projects/sel4/verified-configurations.html):
    "verified configurations for the AArch64 architecture with
    hypervisor mode enabled. The seL4 kernel runs as hypervisor in EL2").
  - Kozane's configuration differs from them in three ways: EL1, MCS
    (proofs in progress), and QEMU `virt` (not a verified platform). The
    ASSUMED row says all three [S2.13].
  - EL2 under nested KVM is SC46.
  - The RNDR source gate P25 stays. On a FEAT_RNG host, a stray RNDR would
    run instead of faulting unless P5 can hide the feature (RM9-2).
- **D4. Upstream rosenpass stays the independent oracle.** The responder
  and the initiator share `rosenpass-wire` and `crypto`, so a shared bug
  would interoperate with itself. The oracle cases are:
  - gateway ↔ upstream initiator (existing);
  - `kzc` ↔ upstream responder, master and 0.2.3 (new). Upstream has no
    endpoint for the `kzc` peer, so it only responds.

  Each oracle case prints a runtime line when it asserts equal OSKs.
- **D5. Sans-IO core.**
  - `kozane-client` owns no socket, timer or file.
  - It draws randomness from the OS itself, through the pinned
    `getrandom` crate (getrandom(2), BCryptGenRandom, SecRandomCopyBytes).
    An OS RNG failure is an error, never a fallback. Entropy is not I/O in
    this sense, and a caller cannot weaken it [S2.6].
  - The caller passes the time, from a clock that counts suspend
    (`CLOCK_BOOTTIME` on Linux) [F1.14].
- **D6. Two units, two uids: `kozane-psk` owns the interface;
  `kozane-net` parses the network.** [S1.6, S2.5, S3.5]
  - `kozane-psk.service` runs `kzc-psk` as user `kozane-psk`:
    - `AmbientCapabilities=CAP_NET_ADMIN`,
      `CapabilityBoundingSet=CAP_NET_ADMIN`;
    - it holds `wg.sk`;
    - it reads its settings from root-owned files: the interface, the
      address, the peer, `allowed_ips`.
  - `kozane-net.service` runs `kzc` as user `kozane-net`:
    - `CapabilityBoundingSet=` (empty);
    - it holds only `rp.sk` and the pinned gateway Rosenpass key;
    - it parses Rosenpass from the network.

    No fork is shared. A compromised parser cannot read `wg.sk` or write
    the settings.
  - They talk over a unix socket in `kozane-psk`'s `RuntimeDirectory`.
    `kzc-psk` accepts only a peer whose `SO_PEERCRED` uid is `kozane-net`.
    It accepts only `Install(psk[32])` and `Scrub` messages, and anything
    else ends the connection. When the connection closes, `kzc-psk`
    scrubs, then accepts one new connection [F4.6].
  - **The socket** [F5.2, S5.3]:
    - `kozane-psk.service` runs with `Group=kozane-net`, so both its
      `RuntimeDirectory` (mode 0750) and the socket (mode 0660) get group
      `kozane-net`;
    - it is `Type=notify`, and sends `READY=1` after the bind;
    - `kozane-net.service` declares `BindsTo=`, `After=` and `PartOf=` on
      `kozane-psk.service`, and `kozane-psk.service` declares
      `Upholds=kozane-net.service`, so a restart of either brings both
      back;
    - `kzc` also retries its connect.
  - client.md states a systemd floor of 249, for `Upholds=` [F6.3].
  - **The unit files** use a pinned canonical subset: one line per
    directive, no `~`, no repeats. The harness's parser is exact on that
    subset [T5.3]. The VE28 path reads back the directory as
    `kozane-psk:kozane-net 0750` and the socket as 0660.
  - `kzc-psk` adds the peer with a `getrandom` PSK in the same message
    that creates it. A peer never exists without a PSK [S4.4].
  - **Interface lifecycle** [F3.3, S3.6]:
    - `kzc-psk` creates the configured WireGuard interface
      (`RTM_NEWLINK`), marked with `IFLA_IFALIAS` `kozane-psk`.
    - At start, it deletes a leftover interface that carries the mark,
      and refuses one that does not.
    - It deletes the interface on every exit path. `ExecStopPost=` deletes
      it again.
    - It sets the address, routes, private key and the one peer, and
      touches nothing else. No `REPLACE_PEERS`. No shell-out [F2.18].
  - A scrub removes the peer (`WGPEER_F_REMOVE_ME`) and re-adds it with a
    random PSK. That drops WireGuard's live keypairs [S1.11].
  - Every netlink request carries `NLM_F_ACK`. Each reply is checked for
    errno, sequence and port. A failure, or a failed `getrandom`, is
    fatal: the helper exits non-zero and never installs zeros. The
    buffers are wiped [S1.7].
  - Hardening, in both units:
    - `NoNewPrivileges=yes`, `LimitCORE=0`, sandboxing;
    - `PR_SET_DUMPABLE=0`;
    - `mlock` and `MADV_DONTDUMP` on key and PSK memory [S2.11].

    client.md forbids `setcap`.
- **D7. Where client keys live.**
  - Keys:
    - `/var/lib/kozane-psk` (`wg.*`), 0700, owned by `kozane-psk`;
    - `/var/lib/kozane-net` (`rp.*`), 0700, owned by `kozane-net`.
  - `kzc keygen` runs once as root at install. It creates both
    directories, writes the keys, and `fchown`s each to its user
    [F3.7].
  - The settings and the pinned gateway keys live under `/etc/kozane`,
    root-owned only [S3.5].
  - The keys are not encrypted at rest on Linux in M9 (RM9-3).
- **D8. The dev container.**
  - `run` gains `--ulimit memlock=-1` (P14).
  - On a host with `/dev/kvm`, it also gains `--device /dev/kvm` and
    `--group-add $(stat -c %g /dev/kvm)`.
  - The container is recreated once after the C15 image rebuild, built
    with `--network host`. z1mn and mrx33 get the memlock flag only.
- **D9. Kozane builds its own Microkit SDK.**
  - Why: the shipped kernels are GICv2-only [F1.1].
  - What: a Dockerfile stage pins Microkit 2.3.1 and seL4 16.0.0 by
    commit and SHA-256, and also pins every other input P9 records:
    - `pip install --require-hashes`;
    - `cargo build --locked`;
    - the cross-compiler by digest;
    - QEMU, if the build runs it: the same stock 9.0.0 [S2.12, F2.6].
  - Only the arm64 image builds it in M9 (VE27).
  - VE27 checks its reproducibility.
- **D10. The libvirt domain leaves M9** (SC51). libvirt cannot express
  the pinned virtio-mmio slots or the loader media natively. It runs
  swtpm itself, and its translation needs an unproven normaliser
  [F1.7, T1.5, S1.3].
- **D11. Existing integration cases keep upstream rosenpass** (SC52).
  They observe upstream's `key_out` timing and drive Python WireGuard
  peers. M9 adds `kzc` cases on kernel WireGuard instead [T1.1, F1.8].
- **D12. The client is its own workspace,** `client/`, with its own
  `Cargo.lock`.
  - Release profile: `panic = "unwind"`. The dev-profile opt-level 3 for
    `mce460896` and `libcrux-ml-kem` is copied from the root [F2.16].
  - The root lock does not change, so the Kani keys survive [T1.8].
  - The second lock gets the root's gates [S2.7, T2.13]:
    - `audit-gate`, with the root's ignore policy;
    - clippy, with the deny list;
    - a pin: every crate shared with the root lock resolves to the same
      version and checksum.
- **D13. Timer ownership becomes a code property** [S2.2, F2.4].
  - seL4's EL0 export of the generic timer is one EL1 register for all
    threads. No capability can confine it, so L5's single-owner rule
    cannot hold for it.
  - Replacement, enforced by the build on the shipped release ELFs:
    - **The scan, by encoding class, not by name** [S3.1, F3.1, T3.1].
      It reads every aligned 4-byte word in the executable segments of
      every PD ELF except `timer`.
      - Rejected: any register-form `MRS` or `MSR` with op0=3, op1=3,
        CRn=14.
      - Allowed: `MRS CNTPCT_EL0` and `MRS CNTFRQ_EL0` only. Every PD
        reads the counter through `cpu::now_ns`, and the supervisor reads
        it for its drain.
      - Every write is rejected, and so is every other read, CNTVCT and
        the `SS` variants included.
    - **W^X, gated rather than assumed** [S3.1]. In every PD ELF, no
      `PT_LOAD` segment is both W and X, and no page is covered by both an
      X segment and a W segment. P12 records that Microkit's tool maps
      non-X segments execute-never.
    - **Laws** forbid executable permission on any MR.
  - With these, a compromised PD has no timer-write instruction to reach,
    by code reuse or otherwise, and cannot create one. That makes it an
    enforceable property, not a tripwire.
  - **Where the scan runs** [F3.5, T3.2, F4.4, T4.5]:
    - in `package`, on the release ELFs it ships;
    - laws' ELF check moves into `package` after it, and reads
      `build/timer-scan.txt`.
  - **What it reports:**
    - `TIMER-SCAN-PDS <n>`: the number of PDs scanned, which is every PD
      but `timer`;
    - it is written to the counts only by the shipped release package in
      `make test`; other package calls write only the file;
    - its positive control: the `timer` ELF must contain at least one
      rejected-class instruction.
  - **The supervisor** holds every child's TCB, so it is a declared trusted
    exception [S3.2, S4.3, F4.3, T4.4].
    - Its TCB use is confined by the existing `tools/supervisor-allowlist`
      (M7 C8), in rust-sel4's terms.
    - Only `tcb_suspend`, for C3 row 2's halt, is added, and only in the
      reset module.
    - Resume, register writes, `set_sched_params` and `set_space` stay
      rejected.
  - The laws note for L5 records the amendment. The counter export (PCNT)
    stays on, because every PD reads the counter.

## Contracts

### C1 — Platform: EL1 kernel, pinned machine (Critical tier)

- The `Makefile` board is `kozane_virt_aarch64_el1` (C15).
- `kernel-config` asserts these, beside the existing single-core and MCS
  checks:
  - hypervisor support is off;
  - GICv3 is on;
  - SMC calls are allowed;
  - P12's export set.

  Its red-proof input is a committed GICv2 `gen_config.h` fixture
  [T2.16].
- `tools/vm.py` is the machine's single source:

  ```
  machine(accel, firmware, tpm, netdevs: (outside, inside),
          rng=True, media=(), reset_case=False, launcher=False) -> list[str]
  swtpm(state_dir, key_file, ctrl, launcher=False) -> list[str]
  ```

  - **Fixed in `machine`:**
    - D2's machine string;
    - memory, and `-overcommit mem-lock=on`;
    - a non-mux serial chardev, `-monitor none`, `-display none`;
    - the virtio-mmio bus numbers, the MACs, and the device order;
    - the TPM: `tpm-emulator` on a ctrl chardev, with the data channel
      passed over ctrl (no server socket).
  - **Two forms** [F5.4, S5.1, T5.5]:
    - the harness form (`launcher=False`): `tpm`, `ctrl` and `netdevs` are
      socket paths and netdev specs;
    - the launcher form (`launcher=True`): they are fds. The TPM chardev is
      `socket,fd=M`, swtpm's ctrl is `type=unixio,clientfd=N`, and the
      netdevs are `tap,fd=K` (C4).
  - **Per run:**
    - the accelerator (`tcg` or `kvm`; anything else raises);
    - the firmware path;
    - `tpm` (machine) and `ctrl` (swtpm);
    - the netdev backends;
    - the media.
  - **Deviation flags:**
    - `rng=False` drops only the RNG device (the M7 deny case);
    - `reset_case=True` adds `virtualization=on`, for `tcg` only (D2).
  - **`swtpm`:** `socket --tpm2`, the ctrl channel in the form above (the
    harness form uses `path=…,mode=0600`), the state directory, and the
    state key: `--key file=…,mode=aes-256-cbc` in the harness form, and
    `--key fd=N,mode=aes-256-cbc` in the launcher form, from the fd the
    root launcher opened [S6.1]. Never `type=tcp` or `port=` [S2.3].
- The harness's `Swtpm` builds its argv by calling `vm.swtpm`, as
  `qemu_machine` calls `vm.machine` [T3.12].
- **Harness-only additions** live in `spawn_qemu` and never in `machine`
  or the launcher [F2.9]:
  - `-S` and a QMP socket;
  - `-no-reboot`;
  - the HMP `-monitor unix:…` that the residue scans and S11's reset use.
- **Invariants.**
  - I1.1 (`vm.machine`): for equal per-run arguments, the `tcg` and `kvm`
    argv differ only in `-accel` and `-cpu`. `reset_case` is the one
    other permitted difference, and only for `tcg`.
  - I1.2: no `machine` or `swtpm` argv contains any of these:
    - `secure=on`;
    - `virtualization=on`, except under `reset_case` with `tcg`;
    - `mon:`, `mux=on`, `-qmp`, or a `-monitor` other than `none`;
    - `-s`, `-gdb`, `-semihosting`;
    - `type=tcp`, `port=`;
    - in the launcher form: `path=`, `helper=`, `br=`, and any `file=`
      other than `file=/dev/fd/<n>`. The launcher passes the boot media
      the same way as everything else: as root-opened fds, through
      `-device loader,file=/dev/fd/<n>`. An allow fixture holds a
      launcher-form argv with media [S7.1];
    - a device outside the declared list.
- **Control class:** a fail-closed verification gate over our own
  launcher and harness. The adjudicator is the argv list. It is not a
  boundary against the host (H1).
- **Forbidden patterns.**
  - `pattern: secure=on`. Reason: the TF-A machine is gone.
  - `pattern: mon:stdio`. Reason: HMP on the console.
  - `pattern: "-bios"` in tracked files other than `tools/vm.py`. Reason:
    one adjudicator. The launcher is a build output (C4) [F2.12].
- **Acceptance.**
  - P1, P2 and P14 pass.
  - `test_vm.py` checks I1.1 and I1.2 (VM-FIXTURES).

### C2 — Boot chain without TF-A (Critical tier)

- `make firmware` builds only U-Boot: `qemu_arm64` plus Kozane's config,
  run as `-bios` at EL1.
- These leave the build:
  - the TF-A stage, `support/tf-a/`;
  - `third_party/libtpm`, `third_party/libeventlog`;
  - the Dockerfile's `/opt/tf-a`.
- `boot.cmd` first runs `tpm2 init || REFUSE`, then
  `tpm2 startup TPM2_SU_CLEAR || REFUSE`. The rest is unchanged.
- `tools/measure.py`:
  - PCR 0's FIP model goes;
  - `expected_pcrs` returns zero for PCRs 0–7, and PCRs 8 and 9 as
    before.
- The release carries `u-boot.bin` in place of `flash.bin`, hashed in the
  signed manifest.
- **Invariants.**
  - I2.1: PCR 8 and PCR 9 each come from the two adjudicators, `boot.cmd`
    and `measure.py`, as pinned by `measure-twin` and `measure-pcr9-twin`.
  - I2.2: the seal policy names PCRs 0–8, with the twin's values.
- **Control class:** PCR 8 is a fail-closed verification gate. Its
  adjudicator is the TPM policy session, and it covers media booted
  through the pinned firmware. The firmware itself is not bound by the
  seal (H2, RM9-1).
- **Member set** for "names TF-A, the FIP, PCR 0's model or
  `flash.bin`":

  `git grep -lIiE 'tf-a|tfa|fip_images|expected_pcr0|FIRMWARE_VARIANTS|firmware_variant|flash\.bin|flash-image|\bBL(1|2|31|33)\b|libtpm|libeventlog|mbedtls'`

  The round-1 hint list must be inside it: `docker/Dockerfile`,
  `third_party/`, `THIRD_PARTY.md`, `boot.cmd`, `tpm2-wire`,
  `supervisor/reset.rs`, `mksecrets`, `tpm2/tests/swtpm_interop.rs`,
  `tools/flash-image`, `policy/laws.toml`, `docs/PLAN.md`, the README.
  Each member's disposition goes into the deviation log before C2 locks.
- **Forbidden patterns.**
  - `pattern: fip_images|expected_pcr0`. Reason: the model is gone.
  - `pattern: support/tf-a`. Reason: out of the build.
- **Acceptance.**
  - P3 passes.
  - The PCR 0 deny case: `TpmProxy`'s injection, generalised from PCR 3
    to PCR 0, must keep the boot from unsealing.
  - The TPM-startup refusal case: with `fail_nth=(CC_STARTUP, 1)` the
    boot must REFUSE and power off, and the loader must never start.
  - The M7 firmware-variant cases are deleted, and the manifest is
    lowered in the same commit.
  - `tools/repro` lists the U-Boot artifacts in place of the TF-A ones.

### C3 — Reset and halt on EL1 (Major tier)

- The supervisor's sequence is unchanged: record, then `FAULT_DRAIN_NS`,
  then reset (M7, M8 D-20). How the reset lands depends on P4:

| P4 outcome | Production (`kvm`) | TCG | Supervisor cases assert |
|---|---|---|---|
| (i) passes | an in-guest reset: RESET on QMP | with (ii): `reset_case=True`, RESET. Without (ii): the reset cases run only in `test-kvm`; TCG keeps the record-only checks | RESET |
| (i) fails | the node halts: every PD stops, and the supervisor spins. The launcher's watchdog restarts QEMU when no `Heartbeat` audit line arrives for `WATCHDOG_S`, or when QEMU exits | as production, under the same harness watchdog | SHUTDOWN by the watchdog, then a fresh boot |

- The launcher has no QMP in any row. It reads the serial chardev through
  a pipe, tees it to its log, and watches for the heartbeat [S2.4, F2.2].
- **The heartbeat, always** [F3.2, T3.6, T4.3]:
  - The timer gains channel 6 to `audit`. C14's channel list grows by
    one, and the laws fixtures follow.
  - `audit` prints a `Heartbeat ticks=<n>` event every `HEARTBEAT_S` (a
    `layout` constant).
  - Operators get liveness from it, and C6's tick-rate case reads it.
  - **`ticks=`** is the number of channel-6 notifications that `audit`
    has handled. Notifications coalesce when `audit` is not scheduled for
    longer than a tick, so the count can only undercount. The tick-rate
    case runs on an idle node, and its tolerance covers that [F5.3].
  - **Wiring, always** [F5.1, T5.1]:
    - the new event joins `audit-event`, its Kani harness, ct-shape's
      symbols, `audit-verify` and `docs/operations/audit-map.md`;
    - every case and self-test needle that counts `audit:` lines in a
      window is re-checked against `HEARTBEAT_S`.
- **Only if row 2 applies:**
  - **The halt.** The supervisor stops every child (`microkit_pd_stop`, as
    parent) before it spins, so `timer` and `audit` stop too.
  - **The threshold.** `WATCHDOG_S` is set from the largest heartbeat gap
    measured across a full TCG `make test` on P8's host, the at-capacity
    flood cases included, with the slack recorded. A remote flood that
    starves `audit` must not reach the threshold [S5.4].
- host.md states the minimum host kernel: the version P4 (i) passed on.
- **Control class:** availability, not a security boundary. A failed
  reset leaves the data plane closed.
- **Acceptance.**
  - The row that P4 selects holds.
  - One supervisor reset case runs in `test-kvm`.
  - If row 2 applies, the watchdog is tested on two branches, each with
    its own needle:
    - a real halt through a fault-inject image: the heartbeat stops and
      QEMU keeps running;
    - a stub QEMU that exits [T2.8].

### C4 — Supported host configuration (Major tier)

- **`kozane-vm` is a compiled Rust binary**, in its own `host/` workspace
  with its own lock (D12's gates apply) [F3.4, S3.4].
  - Its argv comes from `build/host/vm-args.json`. `tools/vm.py` renders
    that file, and the binary embeds it at build time, so `vm.py` stays
    the one source.
  - It links the release verifier from `tools/release`, which gains a
    `lib` target. The release manifest gains a `kozane_vm_sha256` entry,
    and `tools/release` and `release.py` are changed for it [F4.5].
  - It is installed on the host once, by the operator [S4.5]. The
    operator builds `tools/release` from the owner-signed git tag at the
    pinned commit, verifies the release with it, and then compares
    `kozane_vm_sha256`. C5 records this bootstrap as ASSUMED. After that, the release's update path never replaces the
    launcher, the verifier or the pin. The launcher never runs code from
    a release [S3.3].
- **The privilege flow** [S3.4, S4.1, S4.2, F4.1, S4.6]:
  - `kozane-vm` starts as root. It opens the pin file, the swtpm key and
    the firmware. It creates every cross-uid resource itself:
    - a socketpair for the TPM, passed to swtpm as
      `--ctrl type=unixio,clientfd=N` and to QEMU as
      `-chardev socket,id=chrtpm,fd=M`, so no socket path exists;
    - the tap devices, attached to the bridges and passed to QEMU as
      `-netdev tap,fd=K`.
  - Before dropping privilege, it raises `RLIMIT_MEMLOCK` for QEMU and
    gives `kozane-qemu` the kvm group.
  - It then starts swtpm as `kozane-swtpm` and QEMU as `kozane-qemu`, each
    with no capabilities and `no_new_privs`, and passes them the fds.
  - The serial pipe is read by an unprivileged child running as
    `kozane-qemu`. That child reports one byte per heartbeat to the root
    parent. Root never parses guest output.
  - `vm.machine(..., launcher=True)` and `vm.swtpm(..., launcher=True)`
    render these fd forms. The harness uses the path forms. I1.2 forbids
    `path=`, `helper=` and `br=` in the launcher forms.
- **Test seams** [T4.1, F4.2]:
  - A `test-seams` cargo feature adds two options: `--root-prefix`, for
    the fixed paths, and `--user-map`, which maps each service user to the
    current uid.
  - The shipped binary is built with
    `cargo build --release -p kozane-vm --locked` and no `--features`
    [S5.2, T5.2].
  - `kozane-vm --build-info` prints `SEAMS=0` or `SEAMS=1`, from a `cfg`
    constant. Where the check runs [F6.2]:
    - in `make release` and `release-verify`: it requires `SEAMS=0` from
      the exact file whose hash goes into `kozane_vm_sha256`;
    - in `make check`: a pin runs on a `make host` build that uses the
      release command line, and `pins` depends on that build. The pin
      requires `SEAMS=0` from that build, and `SEAMS=1` from the test
      build as the positive control.
  - A pin confines `cfg(feature = "test-seams")` to one resolver module,
    which handles only path and user resolution.
  - The `setresuid`, `setgroups` and `fchown` calls are unit-tested
    against injected results. The real cross-uid cells are VE26.
- **The firmware pin** [S1.1, S2.1, S2.14, S3.3]:
  - The launcher copies `u-boot.bin` into a memfd, seals it
    (`F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW`), hashes it, and compares
    the hash with the pin. A mismatch refuses. QEMU gets
    `-bios /dev/fd/N` on that memfd.
  - The pin is `/etc/kozane/firmware.pin`: the hash and the release's
    `RELEASE_SEQ`, root-owned, 0600.
  - `kozane-vm pin-firmware <release>` is the only writer. With its own
    verifier and the operator's pinned release keys, it checks the
    manifest's signatures. It refuses a release whose `RELEASE_SEQ` is
    below the pinned one, then writes the new hash and sequence.
- **swtpm** runs as `vm.swtpm` renders it:
  - its ctrl is one end of the launcher's socketpair (`clientfd=`), so
    no socket path exists;
  - the state encrypted with `--key`, whose key file is under
    `/etc/kozane`, off the VM's storage.
- **Provisioning** produces the encrypted state and the pin together
  [F2.10]:
  - `tools/provision` runs `swtpm_setup --keyfile`;
  - the harness's `swtpm_setup` and `swtpm_server` pass the same key. The
    harness generates that key per run, and it is never committed;
  - the per-boot `Swtpm` copies the encrypted state.
- `docs/operations/host.md`:
  - QEMU ≥ 9.0 with `virt-9.0`, stock;
  - KVM on arm64 with GICv3;
  - the host kernel floor (C3);
  - swtpm;
  - a dedicated host; otherwise SMT off, pinned cores, KSM off (A19);
  - no snapshots, swap off or encrypted, hibernation off (H2);
  - `LimitMEMLOCK=` covering guest RAM (P14);
  - console access root-only;
  - the bridges;
  - the restart policy (C3).
- **Invariants.**
  - I4.1: `kozane-vm` is run with `QEMU` and `SWTPM` pointed at
    argv-recording stubs [T1.4, T3.13].
    - The recorded argv must equal `vm.machine("kvm", …)` and
      `vm.swtpm(…)`. The firmware argument is compared as `/dev/fd/N`.
    - The stub checks that fd: `F_GET_SEALS` shows all three seals, and
      the content hash equals the pin.
    - The stub checks that the TPM fd is a connected `AF_UNIX` socket,
      that the netdev fds are open taps, and that the swtpm key fd is an
      open regular file.
    - Under the test seams, the stub sees the current uid. The
      `kozane-qemu` uid and the empty capability sets are VE26 cells,
      unit-tested.
  - I4.2: `kozane-vm` refuses a firmware whose hash differs from the pin.
  - I4.3: `pin-firmware` refuses a release whose manifest does not verify,
    or whose `RELEASE_SEQ` is below the pin. It leaves the pin unchanged.
- **Control class:**
  - In the build: a fail-closed gate on I4.1.
  - In production, under H1: I4.2 and I4.3 are fail-closed checks on the
    supported path.
- **Acceptance.**
  - `test-kvm`'s release-boot case boots through `kozane-vm`.
  - The release-boot case also checks that the swtpm state is encrypted.
    On a copy of the state, swtpm runs without `--key`, then the check
    sends `swtpm_ioctl -i` and `TPM2_Startup`, which must fail. With the
    key, the same sequence must succeed [T2.20, T3.15].
  - I4.1, I4.2 and I4.3 have injections (see the table).

### C5 — Threat model and residuals (Major tier)

- The README's "What is established" table:
  - the ASSUMED kernel row names EL1, MCS and QEMU `virt` (D3);
  - a new ASSUMED row: the host (H1);
  - the measured-boot row: PCR 8/9 from U-Boot, and the firmware pinned
    by the launcher but not measured.
- The README's residual risks and `docs/` threat model gain:
  - H1, H2, A17–A20;
  - RM9-1…RM9-8;
  - L5's timer amendment (D13).
- The launcher's first-install bootstrap (C4) is recorded as ASSUMED.
- "Do not deploy" stays until M12 (SC48).
- **Acceptance.** Each new claim cites its contract and test, or says
  ASSUMED.

### C6 — KVM gate and baselines (Major tier)

- `make test-kvm` writes `build/counts-kvm` and checks them against
  `tests/manifest-kvm.txt`. `make check` reads neither [T1.2, T2.15].
- Without `/dev/kvm`, `test-kvm` fails; it does not skip.
- Proof that KVM ran [T1.3, T2.1]:
  - harness boots: QMP `query-kvm` reports `{"enabled": true, "present": true}`;
  - the `kozane-vm` boot (no QMP): the harness checks that QEMU's
    `/proc/<pid>/fd` holds an `anon_inode:kvm-vm`.
- The cases:
  - a release boot through `kozane-vm`;
  - a seal and an unseal;
  - a `kzc` session;
  - an HTTPS request;
  - a policy-update boot;
  - one supervisor reset;
  - the tick rate [T2.12, T3.11, T4.3]:
    - The observable is the `ticks=` field of two `Heartbeat` lines,
      against the host's monotonic clock between them.
    - The tolerance is recorded with its measured headroom.
    - The red-proof is a 2× tick divisor.
- `selftest-split` gains a `kvm` partition. It requires `/dev/kvm`, and
  takes the `qemu` host lock and the proof lock (`tools/proof-lock`). It
  never runs beside the `solver` partition on that host. A fixture proves
  the exclusion [T2.6].
- `check-selftest` gains `EXTRA_GATES = {"test-kvm", "test-kzc"}`, which
  joins the gates it expects cases for. A fixture shows that an extra gate
  with no cases fails [T3.7].
- **Image identity** [T2.4, T3.8]:
  - Each gate run writes `IMAGE <digest>` and `QEMU <build-id>` records
    into its counts.
  - `check-manifest` learns this record type and fails on a missing
    record or a second value (CHECK-MANIFEST-FIXTURES rises).
  - `selftest-split merge` requires one value.
  - At milestone close, a final check compares the records of the
    `make check`, `test-kzc` and `test-kvm` counts directories.
- Milestone close requires a green `test-kvm` on gx10, besides the TCG
  `make check`, `test-kzc` and VE27.
- **Baselines** are measured, not gated. They go into the deviation log
  for TCG and KVM:
  - time to `pq: ready`;
  - `policy` verification;
  - handshake latency;
  - HTTPS requests/s;
  - WireGuard throughput with iperf3, run between the outside netns and
    an inside netns on the inside tap. If that topology fails, the
    metric is dropped and the reason recorded.
- **Acceptance.** Every case listed above passes, and every row of the
  injection table that targets this gate reds.

### C7 — Rosenpass initiator (Critical tier)

- `crates/rosenpass-core` gains two files.
  - `initiator_state.rs`: a pure state core with no crypto. Its states
    are Idle → SentInitHello → SentInitConf → Established, plus the
    retransmission counters and deadlines. It is proven with Kani.
  - `initiator.rs`: the protocol over that core.
- `Initiator::new(spki, spkr)`. Its methods:
  - `start(now, seams) -> Result<InitHello, Error>`;
  - `handle_resp_hello(msg, now, seams) -> Result<(InitConf, Osk), Error>`;
  - `handle_empty_data(msg, now) -> Result<(), Error>`;
  - `handle_cookie_reply(msg, now) -> Result<(), Error>`;
  - `tick(now) -> Option<Retransmit>`.
- `seams` is the existing `Seams` (decapsulation of the initiator's own
  key, Kyber, McEliece, RNG).
- The OSK is released when the RespHello authenticates, as upstream's
  initiator does. EmptyData only stops retransmission [F1.9, S1.15].
- Constants follow upstream `9e72f1eb`, pinned by a fixture to upstream's
  file and line. The client's L8 window is `wg_core::REJECT_AFTER_TIME_NS`.
- `lib.rs` lifts SC22. The crate stays `#![no_std]` with its deny list.
- The initiator's secret key is `rp.sk`, as C10 defines it [F2.17, F3.9].
- **Invariants.**
  - I7.1: an OSK leaves only from `handle_resp_hello`, after
    authentication.
  - I7.2: transient secrets are in `Secret` and are wiped on every exit,
    errors included (L12).
  - I7.3: an error leaves the state core unchanged.
- **Control class:** a fail-closed verification gate. The adjudicator is
  `crypto`'s AEAD and MAC, shared with the responder.
- **Acceptance.**
  - P7 passes.
  - `tools/rp-vectors --initiator` captures one exchange into new files:
    `v02-initiator.txt`, `skt-initiator.bin`, `spkt-initiator.bin`, and
    the responder key it used if that is not `spkm.bin`. The initiator
    replays its messages byte for byte. A pin holds the hashes of the
    existing vector files and the rosenpass-wire corpus seeds [T2.18].
  - Initiator cookie handling is checked against upstream's
    `cookie.txt` [T2.11].
  - Kani step lemmas cover every `initiator_state` transition (P13).
    `rosenpass-core` joins `kani_crates`, and MIR-CRATES rises to 19 with
    it.
  - Each error (wrong responder key, tampered RespHello, replayed
    EmptyData, unknown session id) has a deny/allow unit pair. Each pair
    asserts the error and the unchanged state.
  - Residue cases cover the error paths.
  - A bolero target runs after a deterministic prefix, with its corpus
    seeded from the vectors.

### C8 — Client library `kozane-client` (Critical tier)

- `client/crates/client`: std, no I/O (D5).
- Its API:
  - `Client::new(Config, Box<Keys>) -> Result<(Client, Actions), Error>`;
  - `on_datagram(now, &[u8]) -> Result<Actions, Error>`;
  - `on_timer(now) -> Result<Actions, Error>`;
  - `next_deadline() -> Option<u64>`.
- `Actions` is fixed-capacity (`MAX_ACTIONS`) and never drops. Its kinds:
  - `Send(Datagram)`, at most `MAX_DATAGRAM` bytes, always to
    `Config.rp_endpoint`;
  - `InstallPsk(Secret<32>)`;
  - `Scrub`, which has no payload.
- `Config` holds:
  - `rp_endpoint` (a socket address);
  - `gw_rp_pub` (`SPK_LEN` bytes);
  - `gw_wg_pub` (32 bytes).

  The WireGuard endpoint is the shell's concern, not the core's [F2.7].
- **Invariants.**
  - I8.1 (the client mirror of L8):
    - `Client::new` returns `Scrub` before any `Send`.
    - Afterwards, `Scrub` is emitted when no RespHello has authenticated
      for `REJECT_AFTER_TIME_NS` [F2.19].
    - With D6's remove-and-re-add, no WireGuard keypair outlives that
      bound, and none exists before the first exchange.
  - I8.2: the gateway's keys come only from `Config`. There is no trust on
    first use.
  - I8.3: `Actions` never carries the Rosenpass secret key.
- **Acceptance (simulated clock).**
  - No `Scrub` at bound − 1 tick; `Scrub` at the bound and at bound + 1.
  - A RespHello at T < bound pushes the deadline.
  - The first action is `Scrub`.
  - An OS RNG failure, through a test seam, returns an error and emits
    no `Send`.

### C9 — C ABI `kozane-client-ffi` (Major tier)

- `client/crates/client-ffi`, built as `cdylib` and `staticlib`.
- `include/kozane_client.h` is generated by cbindgen (added to the image).
  - A gate regenerates it and compares byte for byte.
  - The C harness compiles against it with `-Wall -Werror`.
- Its functions:
  - `kz_client_new(const kz_config*, const kz_keys*, kz_client** out)`.
    - `kz_config` is `#[repr(C)]`: `rp_endpoint` as `kz_sockaddr`
      (family, 16-byte address, port), `gw_wg_pub[32]`, and a pointer
      plus length for `gw_rp_pub`.
    - `kz_keys` is pointers plus lengths. The keys are copied once into a
      boxed, mlocked `Secret`.
  - `kz_client_on_datagram(h, uint64_t now, const uint8_t* buf, size_t len)`;
  - `kz_client_on_timer(h, uint64_t now)`;
  - `kz_client_next_deadline(h, uint64_t* out)`, which returns
    `KZ_NONE` when there is no deadline;
  - `kz_client_take_action(h, uint8_t* buf, size_t cap, int* kind, size_t* len)`;
  - `kz_client_free(h)`.
- `KZ_MAX_DATAGRAM` and `KZ_MAX_ACTIONS` are header constants.
- **Rules.**
  - `catch_unwind` on every export. Under D12's profile, a panic returns
    `KZ_ERR_INTERNAL`.
  - No foreign callback.
  - Too small a `cap` returns `KZ_ERR_BUFFER`, and the action stays
    queued.
  - A full queue makes `on_*` return `KZ_ERR_BUSY`, and nothing is
    processed.
  - Queued PSKs sit in fixed, mlocked slots, wiped on take and on free.
  - The header states that the caller wipes the key buffers it passed
    in.
  - For `Scrub`, the shell performs D6's remove-and-re-add itself
    [F2.14].
- **Acceptance.**
  - The C harness (`client/tests/ffi/`) completes a full exchange
    against the host-only responder.
  - valgrind runs with `--error-exitcode=1` and no suppressions.
  - A panic seam in the shipped profile returns `KZ_ERR_INTERNAL`.
  - The header gate reds on a renamed function and on a retyped argument.

### C10 — Linux CLI `kzc`, `kzc-psk` (Major tier)

- **Key formats (defined here once)** [F2.17, F3.6]:
  - `rp.sk`: the liboqs-layout McEliece 460896 secret key, `LIBOQS_SK_LEN`
    bytes, which `mksecrets` writes today;
  - `rp.pub`: the raw `SPK_LEN` public key;
  - `wg.sk` and `wg.pub`: raw 32 bytes each.
- **`kzc keygen`**, run once as root (D7) [S1.5]:
  - creates `/var/lib/kozane-psk` and `/var/lib/kozane-net` with `mkdirat`
    0700, opened `O_DIRECTORY|O_NOFOLLOW`;
  - writes each key with `openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)`,
    `fchmod` 0600 (0644 for `.pub`), `fchown` to its unit's user, and
    `fsync`;
  - refuses to overwrite, and wipes its buffers;
  - prints the M8 `peers.toml` entry: the Rosenpass digest
    (`secret_blob::blake2s` over `rp.pub`) and the base64 `wg_pub`.
- **Settings.** `/etc/kozane/client.conf` is line-based `key = value`,
  parsed in-tree, and unknown keys are rejected. Its keys:
  - `interface`, `address`;
  - `wg_listen_port`, `wg_endpoint`;
  - `rp_listen_port`, `rp_endpoint`;
  - `gw_wg_pub`, `gw_rp_pub_path`;
  - `allowed_ips`.

  `kzc-psk` reads the interface and WireGuard keys. `kzc` reads the `rp_*`
  keys and `gw_rp_pub_path`.
- **Invariants.**
  - I10.1 (fail-closed; adjudicator: `fstat` on each fd):
    - directories are opened `O_DIRECTORY|O_NOFOLLOW`, and files
      `openat(…, O_NOFOLLOW)`;
    - the key directory is 0700 and owned by the euid. Secret keys are
      0600, owned by the euid. Public keys are 0644;
    - `client.conf` and `gw_rp_pub_path` are owned by root, and neither
      group- nor world-writable [S3.5];
    - all of them are regular files;
    - ancestors above the leaf may be symlinks; the leaf may not.
  - I10.2 [T3.19]:
    - `kzc` exiting (any signal, or a normal exit) closes the socket,
      and `kzc-psk` scrubs;
    - `kzc-psk` exiting deletes the interface;
    - a `SIGKILL` of `kzc-psk` leaves the marked interface until the
      next start deletes it, or until the gateway's L8 window ends
      (RM9-4).
  - I10.3: `kzc-psk` accepts only `Install(32)` and `Scrub`, and only from
    `kozane-net`'s uid. Netlink errors and `getrandom` failures are fatal
    and never install zeros.
  - I10.4 [S3.7]:
    - `kzc` (`/proc/<pid>/status`): `CapEff`, `CapPrm`, `CapInh`, `CapAmb`
      and `CapBnd` are 0, and `NoNewPrivs` is 1;
    - `kzc-psk`: `CapBnd` ⊆ {`CAP_NET_ADMIN`}, and `NoNewPrivs` is 1.
- **Forbidden patterns.**
  - `pattern: Command::new` in `client/`. Reason: D6.
  - `pattern: REPLACE_PEERS`. Reason: D6.
- **Acceptance.**
  - Against the gateway under TCG (P10 hosts): a ping crosses, and the PSK
    read back with `wg show <if> preshared-keys` changes every rekey.
  - **The scrub drops the session** [T2.7]. The harness blocks only the
    gateway's Rosenpass port, so WireGuard stays reachable, and lets the
    bound pass. A ping must fail right after the scrub.
  - The `keygen` digest equals an independent Python blake2s.
  - **The I10.1 matrix:**
    - allow: the modes above; a symlinked ancestor; a 0644 `rp.pub`; a
      root-owned 0644 `client.conf`;
    - deny: 0640 and 0604 secret keys; a 0750 or 0777 key directory; a
      symlinked leaf key; a symlinked key directory; a symlinked
      `client.conf`; a group-writable `client.conf` or `gw_rp_pub_path`; a
      `client.conf` owned by a non-root euid (via injected `fstat`, VE26)
      [T4.7]; a non-regular file;
    - another owner, and the cross-uid cells: VE26.
  - **I10.2**, each case:
    - `SIGTERM` to `kzc` only → the peer is re-added with a PSK that is
      not the last OSK;
    - `SIGTERM` to `kzc-psk` only → no interface;
    - `SIGTERM` to both → no interface;
    - `SIGKILL` of `kzc-psk`, then a unit restart → the restart succeeds
      and the old PSK is gone;
    - `kzc` restarts → `kzc-psk` scrubs and then accepts the new
      connection;
    - `kozane-psk` restarts → both units come back, and the peer has a
      fresh random PSK;
    - `kozane-psk` alone (no `kzc`) → the peer's PSK reads back non-zero
      and not an OSK.
  - **I10.3:** a scrub against a vanished interface exits non-zero. A
    connection from another uid is refused, unit-tested via VE26.
  - **I10.4** [T4.2]:
    - The capability sets read back as stated.
    - The harness derives its `setpriv` flags by parsing the shipped unit
      files: `AmbientCapabilities`, `CapabilityBoundingSet` and
      `NoNewPrivileges`. It runs under VE26's noroot securebits.
    - The injection edits the unit file.
    - `systemd-analyze verify` checks the units if the image can carry
      it. Otherwise the units' sandboxing and `ExecStopPost=` are VE28.
  - A foreign interface of the configured name (no mark) makes `kzc-psk`
    refuse. A marked leftover is deleted and recreated.

### C11 — `test-kzc`: integration cases for `kzc` (Major tier)

- `make test-kzc` uses its own counts directory and
  `tests/manifest-kzc.txt`. It runs on the hosts that P10 admits [T2.5,
  F2.11].
- The cases run on kernel WireGuard driven by `kzc`, against the gateway
  under TCG:
  - a session;
  - rotation;
  - expiry: the gateway becomes unreachable, and at the bound the peer
    is re-added with a random PSK;
  - the startup scrub;
  - revocation through an M8 bundle update;
  - a cookie boot under the existing below-capacity flood [T2.11, T3.5].
    The case asserts, through the existing cookie and mac2 audit lines,
    that the gateway sent a CookieReply to `kzc`'s endpoint, and that the
    InitHello it accepted came from that endpoint after the reply. The
    red-proof: `kzc` ignores CookieReply, and the case must fail.
- The oracle cases (D4) are host-only, `kzc` ↔ upstream responder, master
  and 0.2.3. They print an equality line, counted as
  `INTEGRATION-ORACLE-CASES`.
- **Keys and enrollment** [T2.10, T3.14, F3.6]:
  - Every `kzc` peer's keys are made by `kzc keygen` itself.
  - The harness adds `keygen`'s `rp.pub` and `wg_pub` to `peers.toml`, and
    the bundle is signed through `tools/policy`, so the C10 → M8
    enrollment walkthrough is exercised.
  - `mksecrets` writes only `client.conf`.
- `selftest-split` gains a `kzc` partition on the P10 hosts. It takes the
  `qemu` host lock, and the exclusion fixture covers it [T3.3].
- `check-selftest`'s `EXTRA_GATES` lists `test-kzc` (C6).
- **Acceptance.**
  - All cases pass.
  - The affected `it_boots` self-test cases run in this slice's gate.

### C12 — Gates follow the platform (Major tier)

- `tools/check-pins`:
  - **P24 is rewritten.** It requires `tpm2 startup` in `boot.cmd`, drops
    the TF-A flags clause, and anchors "`-bios` exactly once" to
    `tools/vm.py`.
  - **P25's platform clause** names `vm.machine`'s CPU arguments.
  - **New pins:**
    - C1's forbidden patterns;
    - I14.1;
    - the existing rp vector hashes;
    - the upstream constant fixture;
    - C10's forbidden patterns;
    - the header gate;
    - D12's shared-crate lock pin.
  - `tests/tools/test_check_pins.py` and the `pins` count regex in the
    Makefile are updated.
- **`tools/laws`, `policy/laws.toml`:**
  - the timer PD loses `timer_mmio` and gains its PPI;
  - D13's no-executable-MR rule;
  - laws' ELF check, in `package`, reads `build/timer-scan.txt` and
    checks D13's W^X segment rule;
  - `timer_channel_is_exempt` is made non-vacuous: it requires the timer
    PD's IRQ and a clean scan result [F2.4];
  - the five `tools/laws/tests/fixtures/timer_*` pairs are updated.
- **`tools/check-selftest`:** an injection for each row of the table
  below, with failure-only needles.
- **Acceptance.** Each new gate fails on its injection.

### C13 — Documents (Minor tier)

- `docs/PLAN.md`: the M9 row.
- `docs/operations/host.md` (C4).
- `docs/operations/client.md`:
  - the two systemd units (D6, D7);
  - `keygen`, run once as root;
  - enrollment:
    - the digest and `wg_pub` go to the PDP;
    - the M8 approval checklist adds an out-of-band confirmation of the
      digest with the named employee;
  - Config provenance: the node prints its Rosenpass digest and WireGuard
    key at boot, the operator publishes them, and `kzc-psk` prints the
    pinned digests at start [S1.9];
  - no `setcap`.
- The README's building and running section: TCG and KVM.

### C14 — Timer on the ARM generic timer (Critical tier)

- The `timer` PD programs the generic timer that P12 shows exported to
  EL0, through its PPI. It reads the rate from `CNTFRQ`.
- `layout::TIMER_FREQ_HZ`, the sp804's 1 MHz constant, goes or becomes
  the tick period derivation [F2.5].
- The tick contract to the clients is unchanged: channel ids 1–5 and the
  tick rate. Channel 6 to `audit` is added (C3).
- Ownership is D13's.
- **Member set:** `git grep -lIiE 'sp804|90d0000|timer_mmio|TIMER_FREQ_HZ'`.
  - Expected members: `crates/layout`, `crates/pds/timer`,
    `system/kozane.system`, `policy/laws.toml`,
    `tools/laws/tests/fixtures/timer_*`, `docker/Dockerfile`.
  - Each member's disposition is logged before C14 locks.
- **Invariants.**
  - I14.1: no `.system` names a device that stock `virt-9.0` lacks. A pin
    checks this against `dumpdtb`. Its precondition is that the `dumpdtb`
    has no `arm,sp804` node, otherwise the pin fails [T2.4].
  - I14.2 (D13): outside `timer`, the scan finds no rejected-class
    instruction. Inside `timer`, it finds at least one.
- **Control class:** I14.2 is an enforceable code property, given W^X
  (D13). The adjudicator is the ELF's executable segments.
- **Acceptance.**
  - P12 passes.
  - The TCG suite's timing cases pass on stock QEMU.
  - `test-kvm`'s tick-rate case passes.

### C15 — Kozane's Microkit SDK (Critical tier)

- A Dockerfile stage builds the SDK (D9) for the arm64 image.
  `MICROKIT_SDK` points at it [T4.9].
- The image also changes:
  - QEMU without the sp804 patch;
  - no TF-A;
  - additions: cbindgen and iperf3.
- It is rebuilt once, early. It is transferred to z1mn and mrx33 by
  `docker save | load`, and compared by `RootFS.Layers`.
- **Invariant I15.1** (VE27): `tools/sdk-repro` builds `--target sdk` on
  gx10 and on z1mn, and the kernel, the loader and the tool are
  byte-identical.
- **Acceptance.**
  - P9 passes.
  - `make kernel-config` pins C1's assertions.
  - `sdk-repro` reds on an injected build-time string in the stage.

## Consumer-flow walkthroughs

- **C8 `Actions` → `kzc` → `kzc-psk`.**
  - `Send.bytes` goes to the UDP socket bound to `rp_listen_port`,
    toward `rp_endpoint`.
  - `InstallPsk(psk)` goes over the unit socket as `Install`. `kzc-psk`
    sends `WG_CMD_SET_DEVICE` on `interface` for peer `gw_wg_pub` with
    `WGPEER_A_PRESHARED_KEY`, checks the ack, and wipes.
  - `Scrub` goes over as `Scrub`. `kzc-psk` sends `REMOVE_ME` for
    `gw_wg_pub`, then re-adds the peer with `wg_endpoint`, `allowed_ips`
    and a `getrandom` PSK, and checks both acks.
- **C8 `Actions` → C9 FFI.** `take_action` copies the kind plus up to
  `KZ_MAX_DATAGRAM` bytes for `Send`, 32 bytes for `InstallPsk`, or no
  bytes for `Scrub`. The shell holds its WireGuard settings itself.
- **C10 `keygen` → M8 `tools/policy`.** `peers.toml` reads `rp_pub_path`
  (the raw `SPK_LEN` file `rp.pub`) and `wg_pub` (base64). `keygen` prints
  both, and `rp-digest` hashes the same bytes.
- **C11 `mksecrets` → `kzc-psk` and `kzc`.** It writes `client.conf`
  only.
- **`keygen` → `mksecrets`/`peers.toml` (harness).** The harness reads
  `rp.pub`, and the printed `wg_pub`, into the gateway's `peers.toml`.
- **C1 `vm.machine` → the harness and `kozane-vm`.**
  - Both take the argv list as is.
  - The harness adds only its listed extras.
  - The launcher adds nothing. I4.1 runs it to compare.

## Testing strategy

**Slice gates:**
- unit tests, Kani on new harnesses only (one at a time, ≤ 40 GiB), bolero,
  laws and pins;
- `make test` under TCG on z1mn;
- `make test-kzc` on a P10 host;
- `make test-kvm` on gx10, under the proof lock;
- in slices that edit `run.py` anchors, the affected self-test cases.

**Kani:** the root lock is not expected to change (D12). If it does,
there is one re-proof tail on z1mn (about 13 h), and no second change.

**Final, at one commit:**
- a solo TCG `make check`;
- `test-kzc`;
- `test-kvm` on gx10;
- VE27's `sdk-repro`;
- the split self-test, with its `kvm` and `kzc` partitions.

**Injections** (failure-only needles: each is text printed only on the
failure path) [T2.2, T2.14]:

| Gate | Injection | Needle |
|---|---|---|
| I1.1 | a KVM-only device | `vm: tcg and kvm argv differ` |
| I1.2 | `-gdb tcp::1234`; `type=tcp` in swtpm; `path=` in `vm.machine(launcher=True)` | `vm: forbidden argument` |
| test seams | build the release `kozane-vm` with `--features test-seams` | `pins: kozane-vm built with test seams` |
| kernel-config | the GICv2 fixture | `kernel-config: GIC_V3 missing` |
| I14.1 | reinstate `timer_mmio` | `pins: device not in virt-9.0` |
| I14.2 deny | an `msr cntp_cval_el0, x0` in `ingress`; an `mrs x0, cntvctss_el0` | `timer-scan: rejected instruction outside timer` |
| I14.2 allow | drop `MRS CNTPCT_EL0` from the scanner's allowlist | `timer-scan: rejected instruction outside timer` (in `ingress`'s `cpu::now_ns`) |
| I14.2 control | strip the timer access from `timer` | `timer-scan: no timer access in timer` |
| I14.1 precondition | a dtb with an `arm,sp804` node | `pins: dtb is not stock virt-9.0` |
| W^X | an RWX `PT_LOAD`; overlapping X and W pages | `laws: writable executable segment` |
| supervisor TCB | a rust-sel4 `tcb_resume()` call | the allowlist's failure line for the call |
| D13 MR rule | an `x` MR | `laws: executable MR` |
| PCR 0 seal | seal to PCRs 1–8 | `pcr0-deny: unsealed` |
| startup refusal | drop `\|\| REFUSE` | `tpm-startup: loader started` |
| repro | drop U-Boot's `SOURCE_DATE_EPOCH` | `repro: u-boot-shipped/u-boot.bin differs` |
| I15.1 | a build-time string | `sdk-repro: differs` |
| I4.1 | one-device drift | `vm-launcher: argv differs` |
| I4.1 seals | pass an unsealed memfd | `vm-launcher: firmware fd not sealed` |
| swtpm key | drop `--key` from `vm.swtpm` | `vm: swtpm without key`; the encrypted-state check: `swtpm-state: plaintext` |
| I4.2 | remove the hash compare | `vm-launcher: unpinned firmware ran` |
| I4.3 | skip the manifest verify; skip the sequence check | `pin-firmware: unsigned release pinned`; `pin-firmware: older release pinned` |
| KVM proof | `-accel tcg` in `kvm` | `kvm: not enabled` |
| `/dev/kvm` precondition | `KOZANE_KVM_DEV` seam set to a missing path | `test-kvm: no /dev/kvm` |
| P24 | delete `tpm2 startup` | `P24 support/u-boot/boot.cmd` |
| rp vectors | edit `v02.txt` | `pins: rp vectors changed` |
| upstream constants | change one constant | `rp-constants: drift` |
| initiator vectors | flip a recorded draw | `initiator: vector mismatch` |
| I7.3 | a deny path skips the restore | `initiator: state advanced on error` |
| I7.2 | remove one wipe on an error path | the residue case's failure line |
| I8.1 a | `>=` → `>` | `client: no scrub at bound` |
| I8.1 b | no startup scrub | `client: send before scrub` |
| I8.1 c | no deadline reset | `client: unexpected scrub` |
| header | rename / retype an argument | `ffi: header differs` |
| valgrind | an uninitialised read | `ffi: memcheck errors` |
| I10.1 a | drop `O_NOFOLLOW` | `kzc: symlink accepted` |
| I10.1 b | drop the mode check | `kzc: loose mode accepted` |
| I10.2 | no SIGTERM scrub | `kzc: psk survived exit` |
| I10.3 a | ignore the ack | `kzc-psk: scrub unconfirmed` |
| I10.3 b | `getrandom` seam fails, install proceeds | `kzc-psk: zero psk installed` |
| I10.4 | in `kozane-net.service`, drop the empty `CapabilityBoundingSet=` and add `AmbientCapabilities=CAP_NET_ADMIN` | `kzc: capabilities held` |
| unit subset | a repeated directive, or a `~` | `units: non-canonical unit file` |
| D6 re-add | a PSK-only scrub | `kzc: session survived scrub` |
| D6 lifecycle | skip the delete on exit; refuse a marked leftover | `kzc-psk: interface left after exit`; `kzc-psk: restart refused` |
| D6 peer uid | skip the `SO_PEERCRED` check | `kzc-psk: foreign peer accepted` |
| cookie case | `kzc` ignores CookieReply | `kzc-cookie: no cookie path` |
| KVM tick | a 2× tick divisor | `kvm-tick: rate outside tolerance` |
| oracle count | move one oracle case to `kzc` | `INTEGRATION-ORACLE-CASES: N-1 < manifest N` |
| D12 lock pin | bump a shared crate in `client/Cargo.lock` | `pins: client lock drift` |
| partition locks | start `kvm` beside `solver`; `kzc` beside `qemu` | `selftest-split: kvm beside solver`; `selftest-split: kzc beside qemu` |
| EXTRA_GATES | an extra gate with no cases | `check-selftest: no cases for test-kzc` |
| image identity | two digests in one merge; a missing record | `selftest-split: mixed images`; `check-manifest: IMAGE missing` |
| sdk-repro count | compare nothing | `sdk-repro: SDK-REPRO-ARTIFACTS 0 < 3` |
| C3 row 2 (only if it applies) | the watchdog never restarts; a stub QEMU exit is ignored | `watchdog: halted node not restarted`; `watchdog: exit not restarted` |

**Manifest keys and wiring** [T2.13]:
- **New keys:**
  - UNIT-CLIENT, UNIT-CLIENT-FFI, UNIT-CLIENT-CLI;
  - KANI-ROSENPASS-CORE;
  - VM-FIXTURES;
  - TIMER-SCAN-PDS;
  - RP-INITIATOR-VECTORS;
  - INTEGRATION-ORACLE-CASES (in `manifest-kzc.txt`);
  - KVM-CASES (in `manifest-kvm.txt`);
  - KZC-CASES (in `manifest-kzc.txt`).
- **Raised or changed keys:**
  - UNIT-ROSENPASS-CORE, KANI-HARNESSES, BOLERO-TARGETS;
  - MIR-CRATES (18 → 19);
  - UNIT-MKSECRETS, UNIT-SWTPM-INTEROP, UNIT-LAWS;
  - UNIT-AUDIT-EVENT, KANI-AUDIT-EVENT, CT-SHAPE-SYMBOLS,
    AUDIT-VERIFY-FIXTURES (the `Heartbeat` event);
  - PROVISION-, RELEASE- and PACKAGE-FIXTURES;
  - MEASURE-FIXTURES (lowered);
  - REPRO-ARTIFACTS;
  - CHECK-PINS-RULES and CHECK-PINS-FIXTURES;
  - INTEGRATION-CASES;
  - CHECK-SELFTEST-FIXTURES.
- **Make targets:**
  - `make client` and `make host` (build, unit, clippy, audit on
    `client/Cargo.lock` and `host/Cargo.lock`) run in `check` before
    `test`.
  - `CASES_FOR_GATE` gains `client` and `host`. `EXTRA_GATES` holds
    `test-kzc` and `test-kvm` [T4.6].

## Residuals (RM9)

- **RM9-1.** The firmware is not measured. On the supported path it is
  pinned by the launcher. Outside it, any EL1 first stage can forge
  PCR 8. Close: an EL2 or board platform with a measured root (SC46).
- **RM9-2.** On a FEAT_RNG host, a stray RNDR runs instead of faulting
  (P25 remains).
- **RM9-3.** Client keys are not encrypted at rest on Linux. Close: the
  OS keystores (SC47).
- **RM9-4.** A `SIGKILL`ed `kzc-psk` leaves its marked interface, with
  the last PSK, until the next start deletes it, or until the gateway's
  L8 window ends.
- **RM9-5.** The host is trusted (H1). Confidential VMs are not supported
  by seL4 today.
- **RM9-6.** Co-resident guests (A19) on a host shared against host.md.
- **RM9-7.** The kernel configuration (EL1, MCS, QEMU `virt`) is covered by
  no seL4 proof.
- **RM9-8.** The generic timer is confined by a code property (D13), not
  by a capability. A kernel or toolchain bug that emits a timer access
  outside `timer` is caught only if it lands in a scanned segment.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC45 | Transparency log and witness cosignatures | M10 |
| SC46 | EL2 under nested KVM (VE22), with a measured firmware root | unscheduled; the owner's host decision |
| SC47 | Windows, macOS, iOS, Android shells; platform keystores | after M9 |
| SC48 | External audit; removing "Do not deploy" | M12 |
| SC49 | Who publishes the mobile clients (App Store 5.4 and Play's VpnService need an organization; the owner's Apple account is Individual) | owner, before SC47's mobile part |
| SC50 | x86_64 and DMA isolation through a vIOMMU | M10+ research |
| SC51 | A libvirt domain (D10) | M10 |
| SC52 | Moving the existing upstream-client cases to `kzc` (D11) | unscheduled |
| SC31, SC42–SC44 | Unchanged from M8 | as recorded |

## User operation scenarios

1. **Deploy on a KVM host.**
   1. On a dedicated host, install QEMU ≥ 9.0 and swtpm. Install
      `kozane-vm` after checking it against the release signatures.
   2. Create the swtpm key under `/etc/kozane`.
   3. Run `kozane-vm pin-firmware <release>`.
   4. Provision.
   5. Run `kozane-vm` from a systemd unit.

   The node prints its release, policy version and key digests.
2. **Enroll a client.**
   1. Install the two units, and run `kzc keygen` once as root.
   2. Send the digest and `wg_pub` to the PDP.
   3. An approver confirms the digest with the employee out of band, and
      two approvers approve (M8).
   4. Put the published gateway digests and keys in `/etc/kozane`.
   5. Start the units. `kzc` prints the pinned digests.
3. **A laptop is stolen (A18).** Revocation under the 15-minute SLA. Group
   rules bound the reach until then.
4. **The gateway becomes unreachable.** At the L8 bound, `kzc-psk` removes
   and re-adds the peer with a random PSK, and traffic stops.
5. **A firmware file is swapped on the host.** `kozane-vm` refuses to
   start. A forged release cannot change the pin.
6. **A compromised `ingress` tries to stop the tick.** Its ELF holds only
   counter reads, no timer write, and it cannot create executable memory
   (D13).

## Carried-Forward Plan Findings

None. Every finding of rounds 1–7 is reflected in this plan. A slice-0
probe that refutes an assumption sends only its named contracts back to
`pending` (see Feasibility probes).

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Platform: EL1 kernel, pinned machine | locked |
| C2 | Boot chain without TF-A | locked |
| C3 | Reset and halt on EL1 | locked |
| C4 | Supported host configuration | locked |
| C5 | Threat model and residuals | locked |
| C6 | KVM gate and baselines | locked |
| C7 | Rosenpass initiator | locked |
| C8 | Client library `kozane-client` | locked |
| C9 | C ABI `kozane-client-ffi` | locked |
| C10 | Linux CLI `kzc`, `kzc-psk` | locked |
| C11 | `test-kzc` | locked |
| C12 | Gates follow the platform | locked |
| C13 | Documents | locked |
| C14 | Timer on the ARM generic timer | locked |
| C15 | Kozane's Microkit SDK | locked |
