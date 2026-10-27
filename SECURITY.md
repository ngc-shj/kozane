# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) (the
"Report a vulnerability" button on the Security tab). Do not open a public
issue, pull request or discussion for an unfixed vulnerability.

A useful report says which image (VPN gateway or HTTPS proxy), which
commit, what an attacker needs (network position, a compromised PD, a stolen
client key), and how to reproduce it, ideally as a test or a frame sequence
against `make run`.

This is a research project maintained by one person. Reports are answered
on a best-effort basis. Fixes are made on `main`, and a GitHub security
advisory is published once a fix is available.

## Scope

In scope: anything that breaks a property the project claims, as stated in
the [README](README.md) and the security laws in
[the architecture plan](docs/archive/review/secureos-pq-vpn-architecture-plan.md).
For example:

- a frame or message that crashes, hangs or takes control of a PD
- a way for a compromised PD to reach authority its role does not grant
- static or session secrets leaving the PD that holds them
- a session established without the post-quantum component (WireGuard
  without a Rosenpass PSK, TLS without X25519MLKEM768)
- a gap in the reproducible build, measured boot, sealing or release
  signing chain
- an error in a proof's statement or in a trusted assumption

Known limits that are not vulnerabilities in themselves are listed in the
README under "Residual risks". This includes the missing DMA isolation on
aarch64, the unverified MCS kernel configuration, and the development keys
in this repository. A new way to exploit one of them is still welcome.

## Supported versions

There are no releases yet. Only the current `main` branch is supported. The
images are not intended for production use.
