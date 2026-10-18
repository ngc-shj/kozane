# secureos roadmap

A single-purpose network appliance OS on seL4 (Microkit), in pure no_std Rust:
first a post-quantum remote-access VPN gateway (WireGuard + Rosenpass), then a
PQ-hybrid HTTPS reverse proxy on the same base.

- Why this scope: [research/2026-10-scope.md](research/2026-10-scope.md)
- Security laws, threat model, residual risks and current contracts:
  [archive/review/secureos-pq-vpn-architecture-plan.md](archive/review/secureos-pq-vpn-architecture-plan.md)

## Goals beyond QEDOS

| Axis | QEDOS | secureos |
|---|---|---|
| Entry point addressed | HTTPS front | VPN/RDP edge (≥ 60% of JP ransomware entry), then HTTPS |
| Crypto TCB | OpenSSL (C) inside `tls_pd` | Pure Rust; libcrux verified primitives |
| Verification | 13 Kani bounded proofs | Kani (+ Verus/Vest in M4) for every parser and state machine; mechanical capability-layout laws |
| Key handling | Key in TLS PD | Static secrets only in a device-less, passive `key` oracle PD |
| PQ | KEM hybrid; X.509 classical | VPN fully PQ (Rosenpass PSK mandatory) |
| Runtime proof | — | Reproducible image, measured boot, attestation |
| Operations | Signed config | Immutable image; secrets in a separately packaged MR |

## Milestones

| | Deliverable | Status |
|---|---|---|
| M0 | Docker dev env, Microkit 2.3.1 + rust-sel4, hello PD boots in QEMU | done |
| M1 | virtio-net driver, `ingress` (ARP + UDP echo), `audit`, laws checker, proofs for `ring`/`wire`/driver copy | done |
| M2 | WireGuard responder (`hs`, `key`, `data`), `rng`, second NIC, dev secrets packaging, fault policy | |
| M3 | Rosenpass (`pq`), PQ-mandatory gate | |
| M4 | Verus/Vest re-proofs | |
| M5 | Reproducible build, measured boot, TPM sealing, attestation, signed releases, UART audit | |
| M6 | HTTPS proxy | |
| M7 | Real hardware (verified board) | |
