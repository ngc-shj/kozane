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
| M4 | Verus/Vest re-proofs | done: Verus proofs for wg-wire, msgs, rosenpass-wire, wire and ring (278 functions; four under `--no-cheating`); Classic McEliece 460896 ported in-tree (mce460896) with the C9 constant-time and residue gate, C10 ELF identity and SC23 closed. Residuals: docs/archive/review/secureos-m4-verus-mceliece-deviation.md |
| M5 | Reproducible build, measured boot, TPM sealing, attestation, signed releases, UART audit | done (QEMU + swtpm): bit-reproducible PD images and loader with a MIR comparison of the verified and shipped builds; U-Boot measures the boot descriptor and image into PCR 8; secrets sealed to PCR 8 and a pinned SRK through a salted TPM 2.0 session in a `tpm` PD; implicit attestation and a release verifier; Ed25519 + ML-DSA-65 signed releases (dev keys, RM5-1); release kernel with UART audit only. Hardware-bound parts (firmware-measured U-Boot, board TPM, explicit Quote, key custody) are M7/SC31-33. Residuals: docs/archive/review/secureos-m5-measured-release-deviation.md |
| M6 | HTTPS proxy | |
| M7 | Board-equivalent platform under QEMU: TF-A measured boot into swtpm PCR 0–7 with PCR 0–7 in the seal policy (SC32), RNG driver on a CPU without RNDR (SC18), end-to-end release boot | No board combines an MCS-verified kernel (Microkit is MCS-only; AArch64 MCS proofs not before Q3/27), a TPM with firmware measured boot, and RNDR. Board-only items (entropy quality, NIC line rate, TPM bus attacks, verified-platform claim) are residuals, not deferrals |
