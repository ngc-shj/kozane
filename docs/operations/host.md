# Host configuration

For the operators of a Kozane KVM host. It states the one supported host
configuration and how `kozane-vm`, the host launcher, is installed, pinned
and run. Contract IDs (C1–C15, D1–D13, H1–H3, A17–A20, RM9-n) are those of
[the M9 plan](../archive/review/kozane-m9-kvm-client-plan.md), as amended by
[its deviation log](../archive/review/kozane-m9-kvm-client-deviation.md).
Provisioning and policy updates follow
[the peer-policy runbook](peer-policy-runbook.md).

**The host is trusted (H1).** The hypervisor, QEMU, swtpm and its state,
`kozane-vm` and its pin, and the host's administrators can read guest memory
and unseal. Nothing below defends against them. What it does is keep the
supported path closed: a swapped firmware file does not boot (I4.2), a
forged or older release cannot move the pin (I4.3), and stolen VM files stay
sealed (H2).

## Requirements

| What | Required | Why |
|---|---|---|
| CPU and hypervisor | arm64 with KVM and a GICv3 (`/dev/kvm`) | the machine is `virt-9.0,gic-version=3` with `-accel kvm -cpu host` (D2); the EL1 kernel is GICv3-only (D9) |
| Host kernel | Linux 6.17 or later | the version P4 (i) passed on (gx10): the supervisor's PSCI `SYSTEM_RESET` from EL1 is an in-guest reset under KVM (C3 row 1) |
| QEMU | 9.0 or later, stock, with the `virt-9.0` machine type | versioned machine types keep the guest ABI fixed across later QEMU releases; no patched device (D2, C14) |
| swtpm | 0.7 or later, with `--key fd=` | the TPM and its encrypted state (C4) |
| systemd | any current version | the unit below |

## The host

- **A dedicated host** (A19). Another guest on the same cores can observe
  Kozane through shared caches and branch predictors. If the host cannot be
  dedicated: SMT off (`nosmt` on the kernel command line), the VM's cores
  pinned and shared with nothing else (`CPUAffinity=` in the unit, and
  `isolcpus=` or a cpuset for the rest), and KSM off
  (`echo 0 > /sys/kernel/mm/ksm/run`). The machine itself sets
  `mem-merge=off` (RM9-6).
- **Guest RAM never reaches host storage** (H2):
  - no VM snapshots, saves or migrations;
  - swap off, or on an encrypted device with a key that does not survive a
    reboot;
  - hibernation off (`systemctl mask hibernate.target hybrid-sleep.target`);
  - no core dumps of QEMU: the machine sets `dump-guest-core=off`, and the
    unit sets `LimitCORE=0`.
- **Guest RAM is locked.** `kozane-vm` runs QEMU with
  `-overcommit mem-lock=on` and raises QEMU's `RLIMIT_MEMLOCK` itself before
  dropping privilege; the unit's `LimitMEMLOCK=infinity` keeps the launcher's
  own limit from standing in the way (P14). Locking costs time at every
  start, proportional to guest RAM (2 GiB): on gx10 under memory pressure
  QEMU printed nothing for 86 s while it faulted in and locked the RAM (D-8).
  A slow first console line is expected; the host needs 2 GiB of free,
  lockable memory beyond its own.
- **The swtpm state key lives off the VM's storage** (H2):
  `/etc/kozane/swtpm.key`, root-owned, mode 0600. A copy of the state
  without the key cannot be read.

## Users and files

Create two system users with no login shell and no home directory:
`kozane-swtpm` (runs swtpm) and `kozane-qemu` (runs QEMU and the serial
reader). Neither may be uid or gid 0; `kozane-vm` refuses one that is.
`kozane-qemu` gets the group that owns `/dev/kvm` from the launcher, and
should not be in it otherwise.

Every input below is opened by root without following a symlink and must be
owned by root and writable by no one else; the two secrets must be exactly
mode 0600. `kozane-vm` refuses to start otherwise.

| Path | Owner, mode | What |
|---|---|---|
| `/etc/kozane/` | root, 0755 or tighter | |
| `/etc/kozane/vm.conf` | root, 0644 or tighter | the launcher's settings (below) |
| `/etc/kozane/firmware.pin` | root, 0600 | written only by `kozane-vm pin-firmware` |
| `/etc/kozane/swtpm.key` | root, 0600 | the swtpm state key: 64 hex digits (D-6) |
| `/etc/kozane/release-keys/` | root, 0755 or tighter | the release keys' public halves, `ed25519.pub` and `ml-dsa-65.pub`, as `make release-keys` writes them |
| `/var/lib/kozane/node/` | root, 0755 or tighter | `u-boot.bin`, `published.img`, `boot.desc` (from the release); `secrets.env`, `pq_secrets.env`, `tls_secrets.env`, `audit_secrets.env` (from the node's package); `slot-a.bin`, `slot-b.bin` (the policy slots, runbook) |
| `/var/lib/kozane/swtpm/` | `kozane-swtpm`, 0700 | the encrypted TPM state |
| `/var/log/kozane/` | root, 0700 | `console.log`, mode 0600 |

`vm.conf` is canonical `key=value` text: exactly these four keys, in this
order, one per line, LF line ends, no spaces:

```
inside_bridge=br-kozane-in
outside_bridge=br-kozane-out
qemu=/usr/bin/qemu-system-aarch64
swtpm=/usr/bin/swtpm
```

## The bridges

`kozane-vm` creates two taps, `kozane-out` (the guest's outside NIC) and
`kozane-in` (its inside NIC), joins them to the bridges `vm.conf` names and
brings them up. The taps exist only while the VM runs. The operator creates
the bridges, persistently (systemd-networkd or the distribution's network
configuration):

- the outside bridge holds the uplink toward the clients and the internet,
  and nothing on the host's own management network;
- the inside bridge holds the protected LAN.

The host itself needs no address on either bridge. A tap name already in
use, or a missing bridge, refuses the start.

## Installing `kozane-vm` (once)

`kozane-vm` is installed once, by the operator, and never by the release's
update path (C4). The bootstrap is ASSUMED (C5): it trusts the owner's
signed git tag.

1. Check out the owner-signed tag of the release (`git verify-tag`), at the
   commit the release's manifest names.
2. Build the verifier and verify the release with the release keys' public
   halves:
   `make release-tool` and `make release-verify PUB=<keys> REL=<release>`.
   This also checks that the shipped `kozane-vm` has the signed
   `kozane_vm_sha256` and reports `SEAMS=0`.
3. Install the release's `kozane-vm` as `/usr/local/sbin/kozane-vm`,
   root-owned, mode 0755. `kozane-vm --build-info` must print `SEAMS=0`
   (no test seams) and `sha256sum` must equal `kozane_vm_sha256`.
4. Copy the release keys' public halves to `/etc/kozane/release-keys/`.

To rebuild it instead of installing the shipped binary: `make host` builds
it with `cargo build --release -p kozane-vm --locked` in `host/`, without
`--features`; the result must match `kozane_vm_sha256`.

## Pinning the firmware

`kozane-vm pin-firmware <release dir>` is the only writer of
`/etc/kozane/firmware.pin`. It:

1. verifies the release's `manifest` and `manifest.sig` with the linked
   release verifier and `/etc/kozane/release-keys/` (both signatures,
   Ed25519 and ML-DSA-65);
2. refuses a release whose signed `release_seq` is below the pinned one;
3. checks the release's `u-boot.bin` against the signed `firmware_sha256`;
4. writes the hash and `release_seq` to a new 0600 file and renames it over
   the old pin.

Any refusal leaves the old pin in place. Copy the release's `u-boot.bin`,
`published.img` and `boot.desc` into `/var/lib/kozane/node/` after pinning.

## The swtpm key and provisioning

Create the key once, before provisioning:

```
umask 077
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/kozane/swtpm.key
echo >> /etc/kozane/swtpm.key
```

Create the TPM state with that key
(`swtpm_setup --tpm2 --tpmstate /var/lib/kozane/swtpm --keyfile /etc/kozane/swtpm.key --cipher aes-256-cbc`,
as `kozane-swtpm`), then provision the node as the runbook says. The state
and the pin belong together: a new state needs a new provisioning, and a new
pin needs envelopes sealed under that release.

## Running it

```
[Unit]
Description=Kozane gateway VM
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/sbin/kozane-vm
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=30
LimitMEMLOCK=infinity
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

`kozane-vm` runs as root. Before any child starts it checks every input,
copies `u-boot.bin` into a sealed memfd and refuses to start unless its
SHA-256 is the pinned one; it copies each boot medium into a sealed memfd
too, so QEMU reads exactly what was checked. It creates the TPM's
socketpair and the taps itself, then starts swtpm as `kozane-swtpm`, QEMU as
`kozane-qemu` (with the kvm group) and a serial reader as `kozane-qemu`. Each
child gets no capability in any set and `no_new_privs`, an empty
environment, and only its own fds at the numbers `tools/vm.py` rendered. The
argv is `tools/vm.py`'s, compiled in; the launcher adds nothing and has no
QMP.

**The restart policy** (C3 row 1): a supervisor reset is an in-guest PSCI
reset under KVM, so QEMU keeps running. When QEMU, swtpm or the reader
exits, `kozane-vm` stops the other two and exits, and systemd starts it
again (`Restart=always`). There is no launcher watchdog. On `systemctl
stop`, `kozane-vm` asks QEMU to exit and stops the rest.

**The console is root-only.** The reader copies the guest console to
`/var/log/kozane/console.log` (root, 0600); nothing of it goes to the
journal. Ship that file to the SIEM for `tools/audit-verify`, over a channel
only root on the host can read. The reader writes one byte to the launcher
per `audit` heartbeat line, and the journal shows
`kozane-vm: guest heartbeat` after the first one: that is the only guest
liveness root sees, and root never parses guest output. QEMU's own errors
go to the journal.

**The console log is capped at 1 GiB**, since the guest decides how much it
prints:
- At the cap, the reader writes `kozane-vm: console log full; dropping
  console output until it is rotated` and drops console bytes. It keeps
  counting heartbeats, so the VM keeps running.
- When the file is smaller again, the reader first writes
  `kozane-vm: <n> console bytes dropped while the log was full`, then
  resumes.
- `audit`'s seq and chain numbers in the log show which records the gap
  took. `tools/audit-verify` reports the gap; it does not pass over it.
- Rotate with `copytruncate` (logrotate), since the reader keeps its file
  open. A rename-based rotation leaves it writing to the old file.
- Keep `/var/log/kozane` on a filesystem, or under a quota, that a full
  log cannot exhaust for the rest of the host. A failed write stops the
  reader, and with it the VM.

Refusals print `kozane-vm: …` on stderr (the journal) and exit non-zero;
the message names the file and the check that failed.
