# Plan: secureos-m2-wireguard

Iteration 2 (M2): a WireGuard responder gateway. Architecture-wide laws L1–L13,
threat model A1–A5, residual risks R1–R4 and VE1–VE5 are those of
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md); this plan adds what
M2 needs and records where M2 amends them. Finding IDs in brackets refer to
[secureos-m2-wireguard-review.md](secureos-m2-wireguard-review.md).

## Project context

- Type: `mixed`. Test infra: unit + Kani + bolero + QEMU integration behind `make check` with check-selftest; no CI (SC9).
- Verification environment constraints (additions):
  - **VE6** Development CPU is QEMU `neoverse-n2` (Armv9, FEAT_RNG/RNDR). `-cpu max` fails seL4's VTCR check; `cortex-a53`/`a76` lack RNDR; verified boards (RPi4 = Cortex-A72) lack RNDR → RNG device driver at M7 (SC18).
  - **VE7** Interop client is the official userspace `wireguard-go` + `wireguard-tools` (Debian snapshot). The build container gets **no NET_ADMIN** [S5]: integration runs QEMU, wireguard-go and the Python peers inside an unprivileged user + network namespace (`unshare -rn`), permitted by `docker/seccomp-userns.json` — Docker's pinned default profile plus `unshare` restricted by an argument filter to exactly `CLONE_NEWUSER|CLONE_NEWNET` [S10]; `/dev/net/tun` is passed as a device only. Residual (architecture R5): code running in the dev container, including `build.rs`, can obtain NET_ADMIN/NET_RAW over a fresh empty network namespace, which widens the kernel attack surface reachable from a malicious crate (nf_tables, tc, xfrm, AF_PACKET).
  - **VE8** PDs read time from `CNTPCT_EL0`/`CNTFRQ_EL0` (`CONFIG_EXPORT_PCNT_USER 1`); periodic work is driven by an sp804 timer PD (the patched QEMU already provides sp804 on virt).

## Objective

A `wireguard-go` client holding the gateway's public key and its per-peer PSK completes a handshake and exchanges IPv4 traffic with a host on the inside network. A client with a wrong PSK can make the gateway answer its initiation (IKpsk2 mixes the PSK after the responder decrypts the initiation) but never gets a transport packet accepted or forwarded; unknown keys and spoofed inner sources get nothing through [T1, S1].

## Design decisions

- **Responder only.** Clients initiate, rekey and send `PersistentKeepalive` (mksecrets emits client configs with it). Accepted limitation: an inside host cannot reach a client whose session expired until that client sends again [F5].
- **Key confirmation [F1, S1, F8].** `data` keeps per-peer `next` / `current` / `previous` sessions. A new install replaces `next` (an older unconfirmed `next` is discarded and zeroized), as wireguard-go does; the first authenticated transport packet on `next` (keepalives included) promotes it to `current` (old `current` → `previous`, which stays valid for receiving; the old `previous` is zeroized). Only `current` is used for sending. An unconfirmed `next` never displaces a working `current`.
- **Ordering [F1].** `hs` pushes `SessionInstall` to `data` *before* releasing the response to `ingress`; `data` drains its install ring before its ingress ring on every notification.
- **Endpoints [F2, S7].** `ingress` is the single owner of peer endpoints. `hs` replies to the initiation's source without changing the table; `data` sends `EndpointUpdate { peer, src }` only for an authenticated packet whose counter exceeds the highest seen on that session.
- **Indices [F3, F8].** Unique by construction: `hs` issues `index = F_k(n)` for a per-boot counter `n`, where `F_k` is a 32-bit permutation (8-round Feistel, round function BLAKE2s keyed by `k_idx = BLAKE2s("wg-index" ‖ boot_seed)`, a label-separated derivation [S15]), so indices never repeat within a boot. Unpredictability is **not** relied on (16-bit halves give only birthday-bound security); nothing may treat an index as a secret. `data` still rejects a colliding install (audited) as a safety net. wg-core takes the local index as a parameter.
- **PSK never leaves `key` [S3].** `key` exposes `PskMix(peer, C) -> (C', τ, κ)` computing the IKpsk2 `KDF3(C, Q)` step; `Q` stays in the secrets MR. **Amends L2's closed oracle set** to {StaticDh, PskMix, BootSeed}, where BootSeed returns only a per-boot derived value (below), never blob contents.
- **Time and expiry [S2, S13, F9].** A `timer` PD (sp804) notifies `data` and `hs` once per second. `data` zeroizes every session (including an unconfirmed `next`) as soon as it passes `REJECT_AFTER_TIME`. Timestamps come from `CNTPCT_EL0`, frequency from `CNTFRQ_EL0` [F6]. `timer` is **untainted by construction** [S11]: it maps only its own device page, receives no notifications (peer ends `notify="false"`), and `pp="false"` on both ends of every channel [S14], so it only notifies; L1 gains this notify-only exemption (architecture plan amended), so M3's "trusted timer" basis holds.
- **Randomness (L9) [S8, S9].** At init `key` derives `boot_seed = BLAKE2s(blob_seed ‖ RNDR samples ‖ CNTPCT)` and returns only that via `BootSeed` (the blob seed never leaves `key`); `hs` derives each ephemeral key as `BLAKE2s(boot_seed ‖ counter ‖ CNTPCT ‖ RNDR output)`. RNDR is read with inline `mrs s3_3_c2_c4_0` and retried while NZCV.Z = 1, up to a bound, then the handshake (or boot) is refused (fail-closed).
- **DoS [S4, S12].** **L13 is waived for M2** (architecture residual R6, tied to SC13): without cookies an attacker who knows a peer's public key can make the gateway spend DH. Interim controls: per-source-IP token bucket for initiations in `ingress`; `hs` rejects an unknown peer after the first DH (before `ss`); `key`'s per-caller token bucket is sized at or above what `hs`'s budget can drive and exhaustion is audited. **Enforced dev-only:** `make package` refuses every kernel config other than `debug`, read from the built kernel's `gen_config.h` (not a make variable) [F10]; the check is removed with SC13 at M2.5. L2's quota wording becomes rate-based (CNTPCT token bucket).
- **Secrets residue [S6].** IPC message registers carrying DH outputs or KDF results are zeroed after each PPC on both sides; `data` zeroes an install slot after copy-in.
- **Static configuration (L6).** `config/gateway.toml` is compiled in: gateway public key, addresses, peers (public key, allowed IPs — non-overlapping), static neighbors (outside gateway MAC; inside hosts as IP + MAC pairs). `inner` forwards only frames whose source IP and MAC match a static neighbor [S7]. No ARP cache.
- **Secrets blob [F7, S8].** One no_std crate `secret-blob` defines the format: magic, version, gateway private key, boot seed, per peer `{hash(peer public key), PSK}`, BLAKE2s checksum. `key` validates it and checks every peer hash and the derived gateway public key against the config, printing a distinct line per failure and halting. `mksecrets` writes it with mode 0600 to a path that, after resolving symlinks, lies outside the repo, `build/` and the cache volumes.
- **Devices (L5) [F4].** `eth_out` on `virtio-mmio-bus.31` (`0xa003e00`, page `0xa003000`, IRQ 79); `eth_in` on `virtio-mmio-bus.23` (`0xa002e00`, page `0xa002000`, IRQ 71), placed with QEMU's `bus=` option (verified); timer = sp804 at `0x90d0000`, IRQ 43.
- **Decisions recorded against the architecture plan [S8]:** no `rng` PD or software DRBG (RNDR + per-boot seed in `hs` instead, SC18 for boards without RNDR); `timer` arrives in M2 as planned; SC12 (`data` split) stays deferred.

## PD set (M2)

| PD | Role | Holds | Inputs |
|---|---|---|---|
| `eth_out`, `eth_in` | driver | one NIC each | wire |
| `timer` | driver | sp804 | IRQ only; notifies `data`, `hs` |
| `ingress` | untrusted_input | gateway public key, endpoint table, per-source buckets | outer frames |
| `hs` | untrusted_input | handshake state, ephemeral keys, index mirror | initiations from `ingress` |
| `key` | key (passive) | secrets MR | PPC from `hs` |
| `data` | data | transport sessions | ciphertext from `ingress`, IPv4 from `inner`, installs from `hs` |
| `inner` | untrusted_input | static neighbors | inside frames |
| `audit` | service | — | event rings |

Priorities: drivers and timer 150, key 140 (passive), hs 110, ingress/data/inner 100, audit 50; explicit `budget < period` on every tainted PD.

## Contracts

**C9 — `wg-wire` + `wg-core`** (no_std): crypto-free crate `wg-wire` (message parsers/emitters, total; replay window, const-generic size) — the only crate Kani and bolero target [T12]; `wg-core::noise` (IKpsk2 responder over traits `StaticKey { dh, psk_mix }`, `Entropy`); `wg-core::session` (`open`/`seal`, limits, zeroize). Invariants as in the whitepaper: construction/identifier strings, labels, mac1 key = HASH(LABEL_MAC1 ‖ S_pub); TAI64N strictly increasing per peer; ≤ 1 accepted initiation per peer per 1/50 s; all-zero DH rejects; REJECT_AFTER_TIME / REJECT_AFTER_MESSAGES; secret types not `Copy`/`Clone`/`Debug` (compile-time assertion), zeroized on drop; constant-time comparison for any tag compared in hand-written code. Primitives: libcrux X25519, ChaCha20-Poly1305, BLAKE2s (no_std build verified for the PD target).
- Acceptance [T2, T6, T10]: RFC 7748, RFC 8439, RFC 7693 vectors; HMAC-BLAKE2s vs Python; the Linux `selftest/counter.c` replay sequence; a **captured wireguard-go initiation fixture** (known responder/initiator statics and PSK) that `consume_initiation` must decrypt exactly; a host full-handshake test against a Python initiator; Kani: parsers total, replay window at small N with a two-call harness (`accept(c); accept(c)` → second false) plus accept/reject covers; bolero targets for the WG parsers.

**C10 — `key`**: passive; PPC labels `StaticDh(point)`, `PskMix(peer, C)`, `BootSeed()` with fixed message sizes; validates the blob (C15 format) with distinct failure lines and halts; rejects all-zero DH; per-caller CNTPCT token bucket (injectable clock for tests), exhaustion audited; zeroes message registers after each reply. Acceptance [T4]: host tests per validation branch and the bucket; integration boot with a blob whose fields are all valid but whose public key mismatches the config prints the mismatch line and the monitor reports `key` faulted.

**C11 — `hs`**: copy-in initiations; C9 responder with `key` + hedged RNDR; unknown peer rejected after the first DH; install to `data` before the response to `ingress`; indices from the per-boot permutation (generic over half-width; exhaustive bijectivity test at 8-bit halves [T13]); zeroize; audits `HandshakeOk`, `HandshakeRejected{reason}`.

**C12 — `data`**: next/current/previous slots and promotion; install ring drained first; inbound open → keepalive counts for confirmation and roaming → inner source ∈ peer allowed IPs (else drop + `SpoofedSource`) → `inner`; `EndpointUpdate` only on a new highest counter; outbound by allowed-IP lookup over `current` only; timer-driven expiry and zeroization; colliding installs rejected.

**C13 — `eth_in` + `inner`**: `netdrv` library + two thin driver binaries; `inner` answers ARP for its address, forwards only IPv4 to the gateway MAC whose source IP+MAC match a static neighbor, and addresses outbound frames by static neighbor (unknown → drop + audit). `wire` gains `Body::Ipv4 { src, dst, proto, payload }` under the same guarantees (Kani re-proof).

**C14 — `ingress` v2**: UDP 51820 only (echo removed): type 1 / 148 B / valid mac1 / within the per-source bucket → `hs`; type 4 / ≥ 32 B → `data`; else drop with a reason. Builds outer frames for `hs`/`data` using the endpoint table and the static outside-gateway MAC.

**C15 — `config` + `secret-blob`**: `config/gateway.toml` validated by a library function (overlapping allowed IPs, malformed keys, duplicates, count mismatches) with direct negative tests [T9], plus one end-to-end build-failure fixture; `secret-blob` shared by `key`, `mksecrets`, `config`.

**C16 — `mksecrets` + packaging**: as in Design decisions; `make image` uses a zero placeholder; `make package SECRETS= OUT=` re-runs C7 and `microkit` with only `prefill_path` changed. Acceptance [T8]: two builds from identical inputs are byte-identical (precondition); the diff checker is a unit-tested function with counted fixtures (empty diff, diff outside the MR, all-zero blob, other attribute changed — all rejected; the real package accepted); a blob path inside the repo is refused.

**C17 — laws/policy/layout**: new roles/channels/IRQs (71, 43), `key` passive with exemption conditions, timer device page; layout tests for all new channels/IRQs. C7 fixtures for the timer exemption [T13]: the real timer passes; timer with a shared MR → `{L1}`; peer end `notify="true"` → `{L1}`; timer end `pp="true"` → `{L1}`.

**C18 — integration [T3, T4, T5, T7]**: `make test` creates a temp dir, runs `mksecrets` and `make package` into it (removed on every exit path), then inside `unshare -rn` boots QEMU (outside NIC on user-net `hostfwd=udp:127.0.0.1:<p>-:51820`, inside NIC on `-netdev dgram` to a Python inside host, `bus=` placement, `-cpu neoverse-n2`). `run.py` fails (never skips) if `unshare`, `/dev/net/tun`, wireguard-go or the Python `cryptography` package is unavailable, and tears down `wg0`/wireguard-go/QEMU on every path. Cases, each negative case asserting a positive audit line **and** a following liveness barrier (a valid packet that must arrive afterwards):
  1. wireguard-go with key + PSK: `wg show wg0 latest-handshakes` non-zero, then ping the inside host (exit status and receipt at the inside host).
  2. Python initiator with the **same peer key as case 1** and a wrong PSK, run after case 1 with a newer TAI64N [T11]: a response arrives and the Python side fails to open its empty AEAD (proving the gateway used the right PSK); its transport packet is audited as rejected; barrier: the wireguard-go ping still works and `latest-handshakes` is unchanged (the unconfirmed `next` did not displace `current`). Plus `data` unit tests for every slot rule.
  3. Python initiator with an unknown static key: `HandshakeRejected{UnknownPeer}` audited, barrier.
  4. Python initiator (valid key + PSK) sends a transport packet with a spoofed inner source: `SpoofedSource` audited, barrier.
  5. Boot with the mismatched blob (C10 acceptance).
  New manifest keys per crate (`WG-CORE-UNIT`, `WG-WIRE-KANI`, …) — the `unit` target runs each listed crate separately and records its own count [T12] — INTEGRATION-CASES raised, and a check-selftest case per new gate with a new integration anchor (echo is gone), including `make package` against a non-debug `gen_config.h` failing with a named message [T13]. `run.py` also asserts `unshare -rm` is refused (deny side of the seccomp filter) [T14], and `make check` runs an offline check that `docker/seccomp-userns.json` differs from the pinned default profile embedded in the repo only by the single `unshare` entry (`SCMP_CMP_EQ` 0x50000000) [T14].

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC13 | Cookie reply / mac2 under load (L13 complete; M2 images dev-only until then) | M2.5 |
| SC14 | Passive keepalives | M2.5 |
| SC15 | IPv6 | unscheduled |
| SC16 | Rosenpass + PSK age (L8 complete) | M3 |
| SC17 | Whole-system halt / watchdog reset on PD fault | M7 |
| SC18 | RNG device driver for boards without RNDR | M7 |

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C9 | wg-core | locked |
| C10 | key PD | locked |
| C11 | hs PD | locked |
| C12 | data PD | locked |
| C13 | eth_in + inner | locked |
| C14 | ingress v2 | locked |
| C15 | config + secret-blob | locked |
| C16 | mksecrets + packaging | locked |
| C17 | laws/policy/layout | locked |
| C18 | integration | locked |
