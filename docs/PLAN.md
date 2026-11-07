# kozane roadmap

A single-purpose network appliance OS on seL4 (Microkit), in pure no_std Rust:
first a post-quantum remote-access VPN gateway (WireGuard + Rosenpass), then a
PQ-hybrid HTTPS reverse proxy on the same base.

- Why this scope: [research/2026-10-scope.md](research/2026-10-scope.md)
- Security laws, threat model, residual risks and current contracts:
  [archive/review/secureos-pq-vpn-architecture-plan.md](archive/review/secureos-pq-vpn-architecture-plan.md)

## Goals beyond QEDOS

| Axis | QEDOS | kozane |
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
| M6 | HTTPS proxy | done (QEMU): a `tls` PD (untrusted_input, 0.05) terminates TLS 1.3 with X25519MLKEM768 only, ChaCha20-Poly1305, and an ECDSA P-256 certificate whose key is sealed in a passive `tlskey` PD through a third TPM envelope; HTTP/1.1 heads are parsed strictly (smuggling forms refused) and rewritten (client-address fields dropped, X-Forwarded-For appended) and proxied one request per connection to a backend only through `inner`; secrets and plaintext are wiped at each lifecycle point; one ClientHello per pass (earliest admission) with HS_CAP = 3 concurrent handshakes, measured under TCG (RM6-8); VPN budgets and L13 unchanged. Kani: http-wire by step proofs composed by induction (the induction, long delimiter-free scans and large Writer::put argued, RM6-11). Final `make check` green at 4479d66; the full check-selftest run is deferred to the combined run after the post-M6 fixes and the repository restructure. Residuals: docs/archive/review/secureos-m6-https-proxy-deviation.md |
| M7 | Board-equivalent platform under QEMU: TF-A measured boot into swtpm PCR 0–7 with PCR 0–7 in the seal policy (SC32), RNG driver on a CPU without RNDR (SC18), whole-system halt / watchdog reset on PD fault (SC17), end-to-end release boot | done (QEMU, no board): TF-A 2.15 BL1/BL2 extend BL2, BL31 and U-Boot into swtpm PCR 0 through an MMIO TIS backend, and the secrets are sealed to PCRs 0–8 with a host twin of every value; provisioning binds the SRK to a CA-verified EK by credential activation; a passive `rng` PD drives virtio-rng and every PD draws from an rng-seeded HMAC-DRBG on a cortex-a72 (RNDR faults); a `supervisor` PD parents every PD, records each fault for `audit` and resets through PSCI, while init-time refusals go dormant through a one-shot, leaf-only boot stop (laws, check-pins P26, ct-shape's stage check, Kani); every boot runs paused under `-no-reboot` with QMP and a declared SHUTDOWN reason; a signed, verified release boots end to end with PCRs 0–8 matching its manifest. Board-only items are residuals RM7-1…RM7-10. Residuals: docs/archive/review/kozane-m7-qemu-platform-deviation.md |
| M8 | Enterprise-usable identity: signed peer-policy bundles with two-person approval, NV anti-rollback, release floor (SC33), group authorization, verifiable audit export | done (QEMU + swtpm): peers, allowed IPs, groups and rules come from a hybrid-signed (Ed25519 + ML-DSA-65) bundle in A/B slots, measured into PCR 9 (not sealed); a passive `policy` PD verifies it and advances a platform NV counter only after a newer slot verified, and every PD that uses peers waits for its verdict; `tools/policy` keeps an append-only, two-person-approved ledger, shows approvers every peer and rule, and binds the diff they reviewed; `tools/provision` clears the TPM, defines the NV state under a two-operator delete policy and binds a signed record; `inner` enforces per-group rules with a per-peer flow table; `audit` hash-chains every line and an `auditkey` PD signs checkpoints that `tools/audit-verify` checks. Final `make check` and the split self-test green at 7ac8f9b. Residuals: docs/archive/review/kozane-m8-peer-policy-deviation.md (D-24) |
| M9 | Virtual appliance under KVM, and a client of its own | done (v0.2.0; KVM on gx10, TCG on every worker): the image runs on stock QEMU `virt-9.0` with GICv3 under KVM (production) and TCG (every worker); Kozane builds its own bit-reproducible Microkit SDK (EL1, GICv3, MCS); TF-A leaves, U-Boot measures PCR 8/9 and the launcher `kozane-vm` pins the firmware, passes every device as an fd and runs QEMU and swtpm unprivileged; the timer PD drives the generic timer, confined by a code-property gate; a heartbeat line every minute. Client: a Rosenpass initiator in `rosenpass-core` (replays upstream's vectors byte for byte), the sans-IO `kozane-client` with a C ABI, and `kzc`/`kzc-psk` on kernel WireGuard as two units and two uids. Gates: `make client`, `make host`, `make test-kvm`, `make test-kzc`; the split self-test merged at 319 cases. Code review: eight rounds, the QEMU and swtpm argv bound value by value to what `tools/vm.py` renders. Residuals: a client-level stack-residue measurement (M10), VE22/24/26/28 runtime, the unmarked-`kz0` window. Plan, log and review: docs/archive/review/kozane-m9-kvm-client-{plan,deviation,code-review}.md |
