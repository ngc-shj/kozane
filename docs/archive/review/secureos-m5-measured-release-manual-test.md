# Manual Test: secureos-m5-measured-release

The automated `make check` exercises every path below under QEMU and swtpm.
This file is for an operator rebuilding the dev image and walking one
release through by hand. It also names what only a board can show (M7).

## Pre-conditions

- The dev image is rebuilt from `docker/Dockerfile`:
  `cd docker && docker build --network host --build-arg UID=1000 --build-arg GID=1000 -t secureos-dev .`
- The container is recreated with `--memory 40g`. It must contain:
  - `swtpm` and `tpm2_pcrread`;
  - `/opt/u-boot/u-boot-2025.01.tar.bz2`;
  - `/opt/verus/{syn,prettyplease}`.
- The tree is clean at the commit under test. `make check` has passed in
  this container.
- A directory outside the repo and the cache volumes is ready for release
  keys, e.g. `~/secureos-dev-keys` (dev keys, RM5-1).

## Steps

1. `make release-keys KEYS=~/secureos-dev-keys`. Expect four files; the
   `.key` files are mode 0600.
2. Provision a swtpm state and read its SRK public, as run.py's
   `provision_swtpm` does. Package one deployment:
   `make package SECRETS=<blob> PQ_SECRETS=<blob> SRK_PUBLIC=<file> OUT=<new dir>`.
   Expect `published.img`, `boot.desc`, `secrets.env`, `pq_secrets.env`
   and `pcr8`, and no secret-embedded `loader.img`.
3. `make release KEYS=~/secureos-dev-keys PKG=<package dir> OUT=<new dir>`.
   Expect `manifest`, `manifest.sig`, `published.img` and `boot.desc`.
4. `make release-verify PUB=~/secureos-dev-keys REL=<release dir> ENVELOPE=<package dir>/secrets.env KIND=key`.
   Expect `release: verified (envelope sealed to its PCR 8)`.
5. `make repro` twice, from two different clone paths if available. Expect
   the same `REPRO-ARTIFACTS 14` hashes. For the milestone record, compare
   the same hashes on gx10 and z1mn.
6. Boot the package under U-Boot + swtpm with a copy of the provisioned
   state (run.py's `boot`). Expect every PD to print `<pd>: ready` through
   `audit`, and a WireGuard + Rosenpass handshake.

## Expected result

- **The release** verifies only with both signatures. Its PCR 8 equals the
  value U-Boot extends.
- **The envelopes** unseal only on the TPM they were sealed to, for that
  image and descriptor.
- **The console** prints only `audit` lines and U-Boot's own output.

## Rollback

- **No device state is changed:** the image is immutable and secrets are
  per boot.
- **To undo a release,** delete the release directory, and the dev keys if
  wanted.
- **To return to M4 behaviour,** check out `e132cd6`, rebuild the image
  from its Dockerfile, and recreate the container.

## Adversarial scenarios (Tier 2: crypto, key handling)

The automated case named in each item must fail as described.

- **Patched image, same envelopes** (A6). Boot it: hs and pq audit
  `KeyUnavailable code=14` and no handshake happens (`sealed boot: wrong
  image`).
- **Descriptor with a shortened `image_len`.** Same result
  (`sealed boot: tampered descriptor`).
- **A wrapping or overlapping descriptor range.** U-Boot prints
  `secureos: boot refused` and powers off (`measured boot: wrapping range
  refused`).
- **Envelopes on another swtpm's state.** `KeyUnavailable code=13`
  (`foreign TPM`).
- **A plaintext `SOSSECR1` blob in place of an envelope.**
  `KeyUnavailable code=11`.
- **One flipped byte in the Unseal response** (A7 proxy).
  `KeyUnavailable code=15` (`tpm proxy`).
- **One edited manifest byte, or a published image changed after
  signing.** `release-verify` refuses (`RELEASE-FIXTURES`).
- **Known to succeed (RM5-5).** A relay that runs its own TPM session, or
  rewrites the client's StartAuthSession to unsalted, reads the KEK while
  PCR 8 holds the expected value. The swtpm host test
  `rm5_5_a_relay_that_unsalts_the_session_reads_the_kek_and_the_client_refuses`
  documents it. On a board this needs TPM-bus or reset-line access (SC32,
  M7).

## Hardware only (M7, VE5)

- Firmware measuring U-Boot into PCR 0–7.
- The board's TIS bus.
- An EK certificate chain.
- The board's UART, under the release kernel.
