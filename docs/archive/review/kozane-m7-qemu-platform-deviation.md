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
