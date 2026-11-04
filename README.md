# Kozane

A single-purpose network appliance OS on seL4 (Microkit), written in no_std
Rust, run as a virtual appliance under QEMU/KVM. One base, two images:

- **VPN gateway**: a WireGuard responder with Rosenpass. A session exists
  only with a fresh post-quantum PSK; WireGuard alone is refused.
- **HTTPS reverse proxy**: TLS 1.3 with X25519MLKEM768 only and
  ChaCha20-Poly1305, forwarding HTTP/1.1 to fixed backends.

Each function runs in its own protection domain (PD) with only the
authority its role needs. Static keys live in passive PDs that have no
device and no network path. The image is reproducible, its boot is measured
into a TPM, and its secrets are sealed to that measurement.

Which peers may connect, and what each may reach behind the gateway, comes
from a signed peer-policy bundle rather than from the image. A bundle is
approved by two people and signed with Ed25519 + ML-DSA-65. It is
installed without a rebuild, and a TPM NV counter refuses any rollback to
an older one. The audit stream on the console is hash-chained, with
checkpoints signed inside the gateway, so a log collector can check that it
is complete and unaltered.

A client of its own, `kzc`, keeps a kernel WireGuard peer's PSK fresh
through Rosenpass, and falls back to a random PSK when no exchange
succeeds. Its core is a portable Rust library with a C ABI, the base for
clients on other platforms.

> **Research project.** It runs under QEMU/KVM (and TCG), with swtpm. It has
> had no independent audit, and the keys in this repository are
> development keys. Do not deploy it to protect anything real. What is and
> is not established is listed below.

## What is established, and how

| Level | Meaning |
|---|---|
| PROVEN | A prover checks the property for all inputs, under the trusted assumptions listed in the repository |
| BOUNDED | Kani model checking up to a stated bound, or a proof that relies on an argued step |
| CHECKED | A mechanical gate on every build (fails closed), or tests and fuzzing |
| ASSUMED | Trusted, not checked here |

| Property | Level | Evidence |
|---|---|---|
| Wire parsers and emitters for WireGuard, Rosenpass, Ethernet/IP/UDP, the inter-PD messages, and the PD rings: memory safety and parse/emit round trips | PROVEN | Verus (`make verus`); required functions in `policy/verus-required.toml`, trusted constructs in `policy/verus-trusted.toml` |
| TLS record and handshake parsers, HTTP/1.1 head parser (smuggling forms refused), TPM 2.0 wire format, ingress and inner gates | BOUNDED | Kani (`make kani`). The HTTP parser is proved step by step and composed by induction; the induction itself is argued |
| Peer-policy bundle parser and slot selection, NV counter advanced only after a verified newer slot, inner's group authorization and flow table, the audit checkpoint signer's sequence rule | BOUNDED | Kani (`make kani`: `policy-wire`, `tpm2-wire`, `inner-core`, `auditkey-core`, `audit-core`) |
| Driver PDs only copy frames, never interpret them, within proved bounds (L7) | BOUNDED | Kani (`crates/ring`: every copy stays in its region) |
| Capability layout: taint, secrets only in the key PDs, default deny, device ownership, budgets and priorities (L1–L5, L11, L13) | CHECKED | `tools/laws` against `policy/laws.toml` and the exact `.system` given to Microkit |
| Constant-time code paths in the key PDs | CHECKED | `make ct` and `make ct-shape` (Valgrind memcheck with secrets marked undefined, and a shape gate) |
| Post-quantum is mandatory: no WireGuard session without a Rosenpass PSK (L8), no TLS traffic secret without X25519MLKEM768 (L14) | CHECKED | Contracts in the code and end-to-end tests against wireguard-go, Rosenpass and OpenSSL |
| Reproducible image: two builds from different paths are bit-identical; the shipped code matches the verified code at the MIR level | CHECKED | `make repro`, `make mir` |
| Measured boot into PCR 8, secrets sealed to it, signed releases (Ed25519 + ML-DSA-65) | CHECKED (QEMU + swtpm) | `make test` boots the packaged image through U-Boot. The firmware (U-Boot) is not measured: the launcher pins its hash, and PCRs 0–7 stay at zero |
| The supported launch path: pinned firmware, fd-passed devices, no QMP or monitor, guest RAM locked, swtpm state encrypted | CHECKED | `make host` (the launcher against argv-recording stubs), `make test-kvm` (a release boot through `kozane-vm` under KVM) |
| Timer writes only in the timer PD; no PD has writable executable memory | CHECKED | `tools/timer-scan` over the shipped ELFs, `tools/laws` |
| The client: PQ-mandatory on its side (a random PSK at start and at the L8 bound), the privilege split, key file checks | CHECKED | `make client`, `make test-kzc` (kernel WireGuard against the gateway), interop with upstream Rosenpass |
| Peer-policy bundles: two-person approval, an append-only approval ledger, slots measured into PCR 9 (not sealed), anti-rollback through a TPM NV counter | CHECKED (QEMU + swtpm) | `tools/policy` fixtures, `make test` (the policy cases), the self-test's injected faults |
| Audit export: every line numbered and hash-chained, checkpoints signed by a separate `auditkey` PD | CHECKED | `tools/audit-verify` and its fixtures, `make test` |
| seL4 enforces isolation for this configuration | ASSUMED | The kernel runs at EL1 with MCS on QEMU `virt`. seL4's verified AArch64 configurations run it in EL2, MCS proofs are in progress, and QEMU `virt` is not a verified platform |
| The host: hypervisor, QEMU, swtpm and its state, the launcher, the host admin | ASSUMED | A host admin can read guest memory and unseal. See [docs/operations/host.md](docs/operations/host.md) |
| The launcher's first install | ASSUMED | The operator builds `tools/release` from the signed tag and checks `kozane_vm_sha256` |
| libcrux primitives, rust-sel4, smoltcp, the Rust toolchain | ASSUMED | Pinned by version and hash, not verified here |

`make check` runs every gate above. `tests/manifest.txt` lists how many
cases each gate must run, so a gate that silently runs nothing fails.

## Residual risks

These are known and accepted, not oversights:

- **No DMA isolation on aarch64.** Microkit supports IO address spaces only
  on x86. A compromised NIC driver PD can reach everything. The only
  defence is that the drivers copy and never parse (L7).
- **Kernel proofs.** The kernel configuration (EL1, MCS, QEMU `virt`) is not
  covered by seL4's AArch64 proofs. Timing channels between PDs are not
  addressed.
- **A trusted host.** The appliance runs under QEMU/KVM. The host
  (hypervisor, QEMU, swtpm, the launcher, its admin) is trusted: it can
  read guest memory and unseal. The seal protects against other media
  booted through the pinned firmware, and against a copy of the media run
  on another TPM state. Stolen VM files stay protected only while swtpm's
  key is off the VM's storage and guest RAM never reaches host storage. A
  co-resident guest is not defended against: use a dedicated host.
- **The firmware is not measured.** U-Boot is a host file. The launcher
  refuses a U-Boot whose hash differs from the pin. Outside the launcher,
  any first-stage code can extend PCR 8 with the genuine digests.
- **The timer is confined by a code property, not a capability.** seL4
  exports the generic timer to every PD. A build gate checks that only the
  timer PD's code writes it, and that no PD can create executable memory.
- **Client keys** are not encrypted at rest on Linux yet. A `SIGKILL`ed
  client leaves its last PSK until the next start or the gateway's L8
  window. Clients for Windows, macOS, iOS and Android are future work.
- **Keys and rollback.** Release and bundle signing keys are development
  keys kept on the build host. A bundle older than the TPM counter is
  refused, and an older release refuses a bundle whose `min_release` is
  above it, so it stops serving. But an older signed release still boots
  until a bundle raises that floor.
- **Human procedures.** Two-person approval, provisioning and ledger
  restore depend on the operators following the runbook. What each step
  catches, and what it does not, is listed in the M8 deviation log (D-24).
- **Clients without post-quantum TLS** cannot connect to the HTTPS proxy.
  This is intended (L14). Some older client stacks offer only classical
  groups.
- **Development images** use the debug kernel, through which any PD can
  print. Packaged images use the release kernel, where only the audit PD
  owns the console.

The full threat model, the per-PD consequences of compromise, and each
milestone's deviations are in [docs/](docs/).

## Building and running

Everything runs in a pinned development container. The base image is
pinned by digest, packages by snapshot date, and every download by SHA-256.
The Microkit SDK is built in the image from pinned sources, for a GICv3
EL1 board, and is bit-reproducible. Development happens on an arm64 Linux
host. KVM is used where the host has it.

```sh
make -C docker build    # build the dev image
make -C docker run      # start the container (repo mounted at /work)
make -C docker exec     # shell inside it

make image              # build the PD ELFs and the loader image
make package ...        # seal secrets to a provisioned TPM (tools/provision)
make run PKG=<out> TPM_STATE=<swtpm state> TPM_KEY=<its key> SLOT_A=<its slot A>   # boot the package as shipped
make test               # integration tests under TCG: VPN, HTTPS proxy, measured boot
make test-kvm           # the same platform under KVM, a release booted through kozane-vm
make test-kzc           # the client against the gateway and upstream Rosenpass
make check              # every gate: proofs, laws, constant-time, fuzz, repro, tests
```

`make check` takes hours. Kani proofs need up to about 30 GB of memory; the
container is capped at 40 GB (`memory=` in `docker/Makefile`), and Kani
proofs should not run concurrently.

## Repository layout

| Path | Contents |
|---|---|
| `crates/pds/` | One binary crate per PD |
| `crates/*-wire`, `crates/wire`, `crates/ring` | Parsers and emitters, verified with Verus or Kani |
| `crates/*-core` | The logic of each PD, testable on the host |
| `crates/mce460896` | Classic McEliece 460896 (Rosenpass's static KEM) |
| `system/kozane.system` | The Microkit system description |
| `policy/` | The security laws and gate inputs (`laws.toml`, Verus lists, constant-time rules) |
| `tools/` | Laws checker, packaging, release signing and verification, peer-policy signing and approval (`policy`), TPM provisioning, audit-stream verification, gates |
| `tests/` | Integration tests (QEMU, wireguard-go, Rosenpass, OpenSSL) |
| `docker/` | The pinned development environment |
| `docs/` | Roadmap, scope research, plans, reviews and deviation logs |

## Deploying the HTTPS proxy: the backend's trust contract

The proxy drops every client-address field it knows (`Forwarded`,
`X-Real-IP`, `X-Forwarded-*`, `X-Envoy-*` and the CDN variants) and appends
its own `X-Forwarded-For: <client address>` and `X-Forwarded-Proto: https`.
Those lists are defence in depth, not the boundary: a field no list names
still reaches the backend. The boundary is the backend's configuration, and
it must hold all of the following:

- The backend accepts connections only from the gateway, enforced at the
  network level (a firewall or a private link), not by the backend's own
  checks of a header.
- It trusts `X-Forwarded-For` and `X-Forwarded-Proto` only on those
  connections.
- It expects exactly one `X-Forwarded-For`, which is the proxy's: incoming
  ones never reach it. More than one, or a list, is not from this proxy.
- It ignores every other client-address field.

## Documentation

- [docs/PLAN.md](docs/PLAN.md): milestones and status
- [docs/operations/peer-policy-runbook.md](docs/operations/peer-policy-runbook.md):
  key custody, provisioning, issuing and rolling out a policy change,
  recovery
- [docs/operations/audit-map.md](docs/operations/audit-map.md): who, from
  where, when and under which policy, mapped to the mechanism and the test
- [docs/research/2026-10-scope.md](docs/research/2026-10-scope.md): why this scope
- [The architecture plan](docs/archive/review/secureos-pq-vpn-architecture-plan.md):
  security laws, threat model, residual risks
- [docs/archive/review/](docs/archive/review/): every milestone's plan, review and deviation log

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

BSD 2-Clause; see [LICENSE](LICENSE). Third-party code and the licenses of
components built into the images: [THIRD_PARTY.md](THIRD_PARTY.md).
