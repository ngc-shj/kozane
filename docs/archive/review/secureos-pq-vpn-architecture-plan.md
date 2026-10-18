# Plan: secureos-pq-vpn-architecture

Working style (user directive): short plan → review → implement → test cycles.
This plan fixes the **architecture-wide security laws and threat model**, and locks
**contracts only for iteration 1 (M0 + M1)**. Each later milestone gets its own
short triangulate cycle that adds contracts here. Finding IDs in brackets refer to
[secureos-pq-vpn-architecture-review.md](secureos-pq-vpn-architecture-review.md).

Research and rationale: [../../research/2026-10-scope.md](../../research/2026-10-scope.md).

## Project context

- Type: `mixed` — bare-metal OS image (seL4 + Microkit PDs in no_std Rust) + host tools + libraries.
- Test infrastructure: iteration 1 creates `unit + proof + fuzz + integration (QEMU)` behind a local `make check`; CI when a remote exists (SC9).
- Platform decisions (user, 2026-10-18): **aarch64 primary**; **Microkit's MCS kernel accepted**.
- Verification environment constraints:
  - **VE1** QEMU `virt` is not a verified platform; and every Microkit 2.3.1 kernel config is **MCS** (`CONFIG_KERNEL_MCS 1`, checked in `gen_config.h`), whose AArch64 proofs are scheduled for Q3/27. Kernel proofs are therefore a roadmap property, not a current one [F1].
  - **VE2** QEMU has no root of trust — measured boot under QEMU is a demonstration only.
  - **VE3** Microkit supports IO address spaces (`iomap`) on x86 only; on aarch64 there is **no DMA isolation on any board**. Permanent residual risk while aarch64 is the target [S1].
  - **VE4** Integration tests inject raw Ethernet frames over `-netdev dgram` (UDP socket, no tap, no `NET_ADMIN`) and use user-net `hostfwd` only for one end-to-end smoke test [T1, F5].
  - **VE5** No physical verified board yet — hardware paths are `blocked-deferred` to M7.

## Objective

A post-quantum remote-access VPN gateway OS (WireGuard + Rosenpass) on seL4, pure Rust,
where compromise of a PD that parses attacker bytes yields as little as its role allows,
followed by a PQ-hybrid HTTPS proxy on the same base.

## Threat model

Assets: gateway static secrets (WireGuard X25519, Rosenpass static KEM keys); session keys;
tunnelled plaintext; integrity of the inside network; image integrity.

| ID | Adversary | Capability |
|---|---|---|
| A1 | Network attacker (outside) | Arbitrary frames to the outside NIC, floods, replay; harvest-now-decrypt-later |
| A2 | Inside attacker | Arbitrary frames on the inside NIC |
| A3 | Compromised PD | Full control of one PD after exploiting a bug in it |
| A4 | Revoked/stolen client | Holds a revoked peer key |
| A5 | Supply chain | Tampered toolchain, SDK, crate, base image, or image in transit |

Consequence of compromise per PD (what the design does and does not give) [S1, S3]:

| PD | Attacker gains |
|---|---|
| `eth_out`, `eth_in` | **Everything** (DMA, VE3). Mitigated only by copy-only drivers with proved bounds (L7) |
| `ingress`, `inner` | ≈ A1 / A2, plus DoS of its own path |
| `hs` | Decrypt and impersonate sessions established while compromised; static-DH oracle (KCI-style impersonation of clients) while compromised. Past sessions stay safe only via L12. Never the static key |
| `pq` | PSKs established while compromised; static-KEM decapsulation oracle while compromised |
| `data` | All live tunnelled plaintext and transport keys — reachable by A1 (ciphertext) and A2 (inside packets) |
| `key` | Everything |

Reboot (stateless image) ends persistence but not exploitability: the same input re-exploits until a fixed image ships.

Residual risks (accepted, revisited each milestone): R1 MCS kernel proofs pending (VE1); R2 no DMA isolation on aarch64 (VE3); R3 microarchitectural timing channels between PDs (seL4 time protection unverified); R4 `debug` kernel lets any PD print via `seL4_DebugPutChar`, so L10 holds only on `release` images [S12].

## Architecture-wide security laws

C7 checks L1–L5, L11 and L13 mechanically against the exact `.system` file passed to the Microkit tool.

| ID | Law | Enforcement |
|---|---|---|
| L1 | **Taint**: a PD is tainted if it maps a NIC device or is connected (shared memory region or channel) to a tainted PD. The sole exception is the `key` role, and only while: every channel to `key` has `pp="true"` on the peer end and `pp="false"` on the `key` end, `notify="false"` on the peer end, and `key` maps no MR except the secrets MR (so it shares **no** memory with any PD). Message sizes per oracle label are a code property checked in the M2 `key` contract. Tainted PDs map no secret MR [F2, S2, S16] | C7 taint propagation |
| L2 | Static secrets exist only in one MR mapped only into `key`. `key` has no device and exposes a closed oracle enum (static-DH, static-KEM decapsulation) that rejects invalid inputs and all-zero DH output, uses constant-time libcrux code, and enforces a count-based per-caller query quota | C7 + closed IPC enum + `key` contract (M2) |
| L3 | Tunnelled plaintext is reachable only by `data` and the inside path | C7 |
| L4 | Default deny: every PD, channel, map, IRQ and attribute in the `.system` must be described by `policy/laws.toml` | C7, fail-closed |
| L5 | Only driver PDs map device MMIO; device ownership is keyed by **physical page**, one driver per page; a DMA MR (any `region_paddr` target) is mapped only into its owning driver and is never a C3 data region [F6, S18, S21] | C7 |
| L6 | No runtime configuration path. The published image holds code + public policy (peer public keys, allowed IPs, addresses — topology confidentiality is not a goal). Secrets live in one fixed-`size` `prefill_path` MR. The published image fills it from an all-zero placeholder. Packaging re-runs C7 and `microkit` on a `.system` identical except for that `prefill_path` value, and asserts the output differs from the published image only inside the MR's byte range; verification hashes the image with that range masked, and the blob (or its sealed form) separately. The blob path and the packaged image's output path (and any intermediate copy) must lie outside the repo, `build/` and the cache volumes (checked) [S20]. M5 replaces the blob with TPM sealing; the TPM driver ↔ `key` exchange is PPC-only with parameter-encrypted responses and is the one permitted exception to the callee-only rule of L1 [S7, S15, S17] | packaging script + C7 |
| L7 | Driver PDs never interpret frame contents: copy between device descriptors and rings only, with bounds proved by Kani (harness from M1). On aarch64 this is the only DMA mitigation (VE3) [S1, T11] | Kani + review |
| L8 | PQ mandatory: `hs` installs a WireGuard session only with `Some(psk)` from `pq` younger than the Rosenpass rotation bound by the trusted `timer`; no zero-PSK default. This also defends cross-reboot handshake replay (TAI64N state is lost on reboot) [S10] | `hs` contract (M3) |
| L9 | No randomness → no handshake (entropy failure is fail-closed) | `rng` contract (M2) |
| L10 | Audit events are a closed enum of codes + integers; no byte-carrying variant (holds on `release` images, R4) | rustc |
| L11 | Single core (`CONFIG_MAX_NUM_NODES == 1`), MCS kernel as shipped, `release` config for any non-dev image | `make image` reads `gen_config.h` |
| L12 | Ephemeral keys, chaining keys, superseded transport keys and PSKs, and cookie/biscuit secrets are zeroized at protocol expiry; secret types are not `Copy`/`Clone`/`Debug` [S3] | type design + review (M2) |
| L13 | **Availability**: every tainted PD (incl. `audit`) has an explicit `budget < period` with a per-PD ratio cap, and the ratio sum over tainted PDs is under a policy cap (`laws.toml`); untrusted-input PDs run at strictly lower priority than `key` and `timer`; shared oracle PDs (`key`) are `passive="true"` so each caller pays for its own calls; `ingress` applies the cookie/under-load gate before anything reaches `hs`/`pq` [S6, S13, S14, F12] | C7 (priorities, explicit budgets, ratios, passive) |

Target VPN PD set (introduced over M1–M3):

| PD | Holds | Attacker bytes from |
|---|---|---|
| `eth_out`, `eth_in` | one virtio-net device each | wire (copy only, L7) |
| `ingress` | cookie secret | A1 |
| `hs` | handshake state, PSKs | A1 via `ingress` (WG initiation incl. encrypted static) |
| `pq` | Rosenpass state | A1 via `ingress` |
| `key` | static secrets only | attacker-chosen X25519 points and KEM ciphertexts relayed by `hs`/`pq` (oracle inputs) |
| `data` | transport keys | A1 (ciphertext), A2 (via `inner`) |
| `inner` | — | A2 |
| `rng`, `timer` | DRBG state / — | none |
| `audit` | — | A3: event rings written by tainted producers (bounded by C8 drain/notify limits and its L13 budget) |

## Iteration 1 scope (M0 + M1)

M0 (done 2026-10-18): Docker env, hello PD boots in QEMU, `make test` passes.
M1: one virtio-net driver, `ingress` answering ARP and echoing UDP on one port, `audit`,
laws checker, proofs for `ring`, `wire` and the driver copy path.

### Contracts

**C1 — Pinned development environment** [S8, T7, F9]
- Artifacts: `docker/Dockerfile`, `docker/Makefile`, `rust-toolchain.toml`, `Cargo.lock`, `tools/check-pins`.
- Invariants:
  - Base image pinned by `@sha256:` digest; apt from `snapshot.debian.org` at a fixed timestamp.
  - Every downloaded artifact is followed by `sha256sum -c` (Microkit SDK additionally by `VALIDSIG FE91…FDCA`); Kani and cargo-bolero are installed at image build at pinned versions, including Kani's own toolchain bundle.
  - Rust toolchain `nightly-2026-08-21` (rustup verifies component hashes against the dated manifest over TLS — accepted, not separately pinned).
  - Every git dependency carries a 40-hex `rev`; all cargo invocations use `--locked`.
  - `ring` and `wire` use no `#![feature]`, so they build on both the PD toolchain and Kani's toolchain.
- Control class: fail-closed verification gate. Adjudication: `sha256sum -c`, `gpg --status-fd`, cargo `--locked`, and `tools/check-pins` (positive rules: every `curl`/`wget` line in the Dockerfile is followed by a hash check; every git dep has `rev = "<40 hex>"`).
- Acceptance: `make -C docker build` succeeds after removing the image **and** the cache volumes; mutating any pin makes it fail; `tools/check-pins` has a fixture per rule that must fail.

**C2 — Build, run and gate harness** [S9, T6, T8, T9]
- Interface: `make image`, `make run`, `make test`, `make check` (= unit + kani + bolero 30 s + laws + test), `make fuzz-long`, `make check-selftest`.
- Invariants:
  - `SHELL := bash`, `.SHELLFLAGS := -euo pipefail -c`; no `.IGNORE`, no `-i`/`-k` in `MAKEFLAGS`, no `-`/`@-` recipe prefix, no `|| true`, `|| :`, `; true`, `set +e` (checked by `tools/check-pins`).
  - `make image` runs C7 on the exact `.system` it then passes to `microkit`, and checks L11 from `gen_config.h`.
  - `make check` compares executed counts with a committed manifest — unit tests, Kani harnesses, integration cases, laws fixtures, `check-pins` fixtures, bolero targets (each with > 0 iterations); zero or fewer than recorded fails.
  - Kani runs with `--fail-uncoverable` (with `-Z unstable-options` if the pinned Kani requires it; checked against the pinned binary at image build), else a wrapper that fails on any cover status other than SATISFIED [T14, N2].
  - `make check-selftest` injects one deliberate failure per layer (unit, kani incl. an unsatisfiable cover, bolero, laws, integration, plus "delete one test" for the manifest); applying an injection is a hard error if it does not apply; only the layer under test runs; the failure output must name the injected item (test/harness name, law-ID set, target) [T15].
- Control class: fail-closed verification gate. Adjudication: unpiped exit status of each step.
- Acceptance: `make check` green; `make check-selftest` green (i.e. every injected failure detected).

**C3 — `ring`: shared-memory buffer exchange** [F3, S5, T3]
- Interface (no_std): per direction a **free** ring and a **used** ring of `Desc { offset: u32, len: u32 }` over a data region; `push`/`pop` on SPSC rings with `N` a compile-time-asserted power of two. Own implementation, sDDF free/used shape as reference. Not reusing rust-sel4 `sel4-shared-ring-buffer` (R1 decision): it needs `#![feature(core_intrinsics)]` (breaks C1) and its index reads are internal, so the read-once `SharedAccess` model cannot be injected [F11].
- Invariants:
  - Peer-written indices are read exactly once per operation through a `SharedAccess` trait; distance `head - tail` (wrapping) must be ≤ `N`, else the ring is treated as corrupt and the PD stops consuming it (fail-closed, audit event).
  - `offset + len` computed with `checked_add` against the region length; a descriptor not currently owned by the peer (per-buffer owner state) is rejected.
  - **Copy-in**: payloads are copied into a PD-private buffer before any parsing; no `&[u8]` over peer-writable memory is ever handed to `wire`.
  - Publication order uses Release/Acquire atomics (single core, L11).
  - The consumer maps the producer's data region read-only (checked by C7).
  - `unsafe` only in `ring::shmem`.
- Control class: enforceable boundary for the local PD's memory safety against a malicious peer. Adjudication: Kani with a `SharedAccess` model that returns a fresh `kani::any()` on every read and counts reads.
- Acceptance: Kani proves no panic, no out-of-region access, one read per index per operation, for N ∈ {1, 4, 256}; removing the mask or the bounds check makes a harness fail (shown once, recorded); host tests cover full/empty/wrap/corrupt.

**C4 — `wire`: Ethernet/ARP/IPv4/UDP parse and emit** [F4, S11, T5, T6, T12, T13]
- Interface: `parse_frame(&[u8]) -> Result<Frame<'_>, DropReason>`; `Frame { eth: EthAddrs { src, dst }, body: Arp(ArpPacket) | Udp4 { src, dst, sport, dport, payload } }`; `emit(&Frame, &mut [u8]) -> Result<usize, TooSmall>`; `check(bytes: &[u8])` property shared by the Kani harness and the bolero target.
- Invariants: total (never panics); ARP requires htype 1, ptype 0x0800, hlen 6, plen 4, op ∈ {1, 2}; IPv4 requires IHL 5, no fragmentation, valid checksum, `total_len ≤ available` (trailing Ethernet padding ignored); UDP length consistent; source MAC/IP not broadcast, multicast or zero; `parse(emit(f)) == f`. No std/test `cfg` in non-test code; std only via dev-dependencies.
- Control class: enforceable boundary (input validation for `ingress`). Adjudication: the parser, proved by Kani; Vest/Verus re-proof in M4 (SC4).
- Lints: `#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]`.
- Acceptance: `DropReason` and `DropReason::ALL` are generated from one macro list, and the per-reason test frame and the Kani covers are exhaustive `match`es, so a new variant cannot miss a test or a cover [T17, T19]; Kani over symbolic length 0..=64 with `kani::cover!` for `Ok(Arp)`, `Ok(Udp4)` and every `DropReason` reachable within 64 bytes (`TooLong` by a separate harness) — unsatisfiable covers fail per C2 [T14, T17]; bounded round-trip harness with a non-empty-payload cover; bolero with a committed seed corpus of valid frames; each `DropReason` unit test is a one-field mutation of a valid frame next to the passing original.

**C5 — `eth_out` virtio-net driver PD** [L7, T11]
- Interface: maps one virtio-mmio page + DMA region; exposes rx/tx free+used rings to `ingress`.
- Invariants: copy-only (L7); owns exactly its device page (L5).
- Control class: enforceable boundary via capability layout (C7) for device ownership; Kani for the copy path.
- Acceptance: Kani harness over the descriptor-to-ring copy function (arbitrary device-reported lengths); frames injected by the test harness reach `ingress` and return.

**C6 — `ingress` v1** [F4, S11, T9]
- Interface: consumes rx used ring, produces tx used ring; compiled-in `{mac, ipv4 = 10.0.2.15, echo_port}`; prints `ingress: ready` after ring init.
- Behaviour: replies to ARP requests for its IPv4; echoes UDP to `echo_port` when `dst` equals its MAC and IPv4 (reply = swap MAC/IP/port, no ARP cache); drops everything else with a `DropReason`. Echo is behind cargo feature `echo`, removed in `ingress` v2 (M2).
- Invariants: tainted (L1), holds no secret; every frame is copied in and parsed by `wire::parse_frame`.
- Control class: enforceable boundary (inherits C3 copy-in and C4).
- Acceptance: integration test injects ARP, a nonce UDP datagram, and one frame per `DropReason`; asserts exact replies (nonce bytes, source port) and the exact audit lines; a hostfwd `nc -u` smoke passes in a separate boot with the user-net backend [T18].

**C7 — Laws checker (`tools/laws`)** [F2, F6, S2, S4, S6, T4]
- Interface: `laws check --system <file> --policy policy/laws.toml --search-path build` → exit 0, or non-zero with the sorted set of violated law IDs.
- Parsing: `roxmltree` pinned to the version the Microkit tool embeds (0.19.0); `DOCTYPE`, entities and duplicate attributes are rejected.
- Semantics: per-element/attribute allowlist with Microkit defaults applied before evaluation (`perms` default `rw`, default priority); unknown element or attribute = violation.
  - Denied outright: `cspace` caps, child `protection_domain`, `virtual_machine`, `smc`, `x` permission on any shared map.
  - `setvar` only with `region_paddr`, only in a driver PD, only naming that driver's policy-declared DMA MR; map attributes `setvar_vaddr`/`setvar_size` allowed [F10].
  - A DMA MR (any `region_paddr` target) is mapped into exactly one PD — its owning driver — and is never a C3 data region [S18].
  - Attributes evaluated explicitly incl. `passive`, `budget`, `period`, `pp`, `notify`, `prefill_bootinfo`, `path_for_symbols`, `domain` [S16].
  - Numbers parsed exactly as the Microkit tool parses them (`0x` prefix, `_` separators) [F13].
  - `phys_addr` only on policy-declared device MRs owned by drivers (page-granular, no overlap with board RAM).
  - `prefill_path` only on the secrets MR, mapped only into `key`.
  - Evaluates L1 (taint propagation incl. the `key` exemption conditions), L2, L3, L5, L13 (priority order, explicit `budget < period`, per-PD and sum ratio caps from `laws.toml`, `key` passive), consumer-side read-only data maps (C3) [S19, N1].
  - Resolves each `program_image` through the same search path as the build and prints its sha256.
- Control class: fail-closed verification gate. Adjudication: the same parser family and the same file the Microkit tool consumes, checked immediately before use.
- Acceptance: each fixture asserts the exact violated-law-ID set and no parse error; every deny fixture has an adjacent allow fixture (e.g. driver maps own device page → pass; another device's page → `{L5}`); fixture for scenario 2 (secret MR mapped into `ingress` → `{L1, L2}`); DOCTYPE fixture fails; default budget on a tainted PD → `{L13}`; driver gets its own DMA paddr via `setvar` → pass, `ingress` gets it → `{L5}`; DMA MR also mapped into `ingress` → `{L5}` next to the driver-only allow case; non-passive `key`, per-PD ratio over cap, and ratio sum over cap → `{L13}` each with an allow pair; the M0 `system/secureos.system` is an allow fixture against its own minimal policy file.

**C8 — `audit` PD and event schema** [F7, T2, T10]
- Interface: `enum AuditEvent` serialised as `(code: u16, a: u32, b: u32)`; producers push over a ring; `audit` prints to serial (debug images; a UART driver PD replaces kernel printing in release images, SC11).
- Invariants: no byte-carrying variant (L10); per reason, emit on the 1st occurrence and every 64th thereafter with `a = running total`; `b` carries `audit_overflow` (count of events lost to a full ring), reset after a successful push; never blocks the data path. `audit` treats producers as untrusted (A3): per-producer drain limit per notification, one shared counter for all unknown codes, and notifications handled at most once per drain cycle [S14].
- Control class: enforceable boundary (rustc: the IPC type has no byte field).
- Acceptance: unit tests — 1st occurrence emits; 2nd–64th do not; 65th emits with total 65; full ring increments overflow and the next push carries it; unknown code prints as a number. Integration: after a flood of K bad frames, per reason ≥ 1 and ≤ K/64 + 2 audit lines, the last `a` ≡ 1 (mod 64), last `a + b` ≤ K, and a nonce echo succeeds afterwards (liveness); exact counts are asserted only in unit tests because arrival in QEMU is not deterministic [T16].

### Consumer-flow walkthroughs (iteration 1)

- `ingress` (consumer of `eth_out` rx used ring) reads `{offset, len}`, checks ownership and bounds, copies into a private buffer, parses with `wire::parse_frame`, then returns the descriptor on the rx free ring.
- `eth_out` (consumer of `ingress` tx used ring) reads `{offset, len}`, checks ownership and bounds against the tx region, copies into a virtio descriptor, then returns it on the tx free ring.
- `audit` (consumer of audit rings) reads `(code, a, b)` and maps `code` to a fixed string; an unknown code prints numerically.

## Testing strategy

| Layer | Tool | Classification |
|---|---|---|
| Unit | `cargo test --locked` on host | verifiable-local |
| Proof | Kani (C3, C4, C5) — pinned in the image | verifiable-local |
| Fuzz | bolero, seed corpus; 30 s in `make check`, long run in `make fuzz-long` | verifiable-local |
| Layout | laws checker + exact-ID fixtures (C7); `tools/check-pins` fixtures (C1, C2) | verifiable-local |
| Integration | pexpect boots QEMU; waits for readiness lines (no sleeps); raw frames over `-netdev dgram`; nonce echo; bounded retries; QEMU process group killed in `finally`; free port per run | verifiable-local |
| Gate self-test | `make check-selftest` | verifiable-local |
| Hardware, root of trust, DMA isolation | — | blocked-deferred (VE1, VE2, VE3, VE5) — needs a verified board + TPM; owners M5/M7; DMA isolation needs a platform change (SC10) |

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC1 | `eth_in`, `inner`, second NIC; virtio-mmio page placement for two NICs (L5) | M2 |
| SC2 | WireGuard responder (`hs`, `key`, `data`), `rng` + DRBG, dev secrets packaging (acceptance must include: diff non-empty and covering the blob's full extent, a blob that cannot be all-zero, and a fixture changing a non-`prefill_path` attribute that packaging must reject [T20]), `timer` | M2 |
| SC3 | Rosenpass (`pq`), L8 gate; pure-Rust Classic McEliece assurance spike | M3 |
| SC4 | Verus/Vest re-proof of `ring`, `wire`, WG/Rosenpass formats | M4 |
| SC5 | Reproducible build, measured boot, TPM sealing, attestation, ML-DSA-65+Ed25519 release signing | M5 |
| SC6 | HTTPS proxy | M6 |
| SC7 | Real hardware | M7 |
| SC8 | Fault policy (any PD fault → halt + watchdog reset) | M2 |
| SC9 | CI pipeline | when a git remote exists |
| SC10 | x86_64 + VT-d second target (closes R2 on that platform) | unscheduled |
| SC11 | UART driver PD for `audit` in release images | M5 |
| SC12 | Split `data` per direction or per peer | revisit at M2 |

## User operation scenarios

1. Developer: `make -C docker run && make -C docker exec`, then `make check` — all gates in one command.
2. Developer maps the secrets MR into `ingress` — `make image` fails naming `{L1, L2}`.
3. Network attacker floods malformed frames — `ingress` drops with counters, audit output stays within the C8 bounds, and the echo still answers afterwards.

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Pinned development environment | locked |
| C2 | Build, run and gate harness | locked |
| C3 | `ring` buffer exchange | locked |
| C4 | `wire` parser/emitter | locked |
| C5 | `eth_out` driver PD | locked |
| C6 | `ingress` v1 | locked |
| C7 | Laws checker | locked |
| C8 | `audit` PD and event schema | locked |

## Implementation Checklist (iteration 1)

Greenfield: no existing shared utilities to reuse; rust-sel4 `sel4-shared-ring-buffer` deliberately not reused (C3, F11). No CI config exists yet (SC9), so `make check` is the full gate set.

| Contract | Files |
|---|---|
| C1 | `docker/Dockerfile`, `docker/Makefile`, `docker/keys/microkit-release.asc`, `rust-toolchain.toml`, `Cargo.lock`, `tools/check-pins`, `tests/tools/test_check_pins.py` |
| C2 | `Makefile`, `tools/kani-gate.sh`, `tools/check-manifest`, `tools/check-selftest`, `tests/manifest.txt`, `tests/integration/run.py` |
| C3 | `crates/ring/src/{lib,shmem,link,tests,proofs}.rs` |
| C4 | `crates/wire/src/{lib,tests,proofs}.rs`, `crates/wire/src/__fuzz__/*/corpus/seed-*` |
| C5 | `crates/pds/eth-out/`, `ring::link` proofs |
| C6 | `crates/ingress-core/`, `crates/pds/ingress/` |
| C7 | `tools/laws/`, `policy/laws.toml` |
| C8 | `crates/audit-event/`, `crates/pds/audit/` |
| shared | `crates/layout/`, `system/secureos.system`, `support/targets/aarch64-sel4-microkit.json`, `.cargo/config.toml` |

Patterns applied at every site: copy-in before parse; `checked_*`/`saturating_*` arithmetic under `clippy::arithmetic_side_effects`; `unsafe` only in `ring::shmem` and the PD `init` functions mapping Microkit regions; no `unwrap`/`expect`/`panic` outside PD init and tests.
