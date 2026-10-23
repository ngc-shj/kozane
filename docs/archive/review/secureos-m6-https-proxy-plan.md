# Plan: secureos-m6-https-proxy

M6 of [docs/PLAN.md](../../PLAN.md): a PQ-hybrid HTTPS reverse proxy on the
VPN gateway's base. Architecture laws L1–L13 and residuals R1–R6 are in
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md);
M5's measured, sealed release path is in
[secureos-m5-measured-release-plan.md](secureos-m5-measured-release-plan.md).
This plan amends L2, L3 and L13 and adds L14 where stated. Review findings
are cited by ID (F*, S*, T*: `secureos-m6-https-proxy-review.md`).

Process (owner, 2026-10-22): contract-first, risk-tiered review, vertical
slices with fast gates, one solo `make check` at the end; run to M7 without
questions, decisions recorded here.

## Project context

- Type: `mixed` — seL4/Microkit image (no_std Rust PDs) + host tools + libraries.
- Test infrastructure: unit + Kani + Verus + bolero + ct/residue gates +
  QEMU integration (U-Boot, swtpm) + gate self-test, all behind local
  `make check`; no CI (SC9).
- Verification environment constraints (IDs continue VE1–VE8):
  - **VE2/VE5/VE6/VE7** (existing) no root of trust under QEMU, no board,
    U-Boot stands in for the CRTM, swtpm.
  - **VE9** No public CA: the server certificate chains to a dev CA made at
    provisioning. Browser trust (WebPKI) needs an operator-issued certificate.
  - **VE10** QEMU TCG timing is not the board's: throughput and handshake
    latency are measured and recorded, not claimed for hardware.
  - **VE11** RNDR under QEMU is the host's RNG; entropy quality on a board is M7.

### QEMU-verifiable vs hardware-required

| Area | verifiable-local (QEMU, netns, OpenSSL 3.5.7 / curl 8.14 in the dev image) | blocked-deferred |
|---|---|---|
| TCP | handshake, data, close, retransmission, refusals on the outside tap (C3, C10) | line-rate behaviour on a real NIC (M7) |
| TLS 1.3 + X25519MLKEM768 | OpenSSL `s_client -groups X25519MLKEM768` and curl; refusal of classical-only clients; host test client for refusal paths; keylog-based residue scans (C6–C8) | browser interop against a WebPKI certificate (VE9, ops) |
| Server signature | ECDSA P-256 CertificateVerify signed by `key`, verified by OpenSSL against the dev CA (C5) | RNDR quality on a board (VE11, M7) |
| HTTP proxy | request to a raw-capture backend on the inside tap, response streamed back, smuggling refusals (C9, C10) | — |
| Release path | the M5 sealed, measured boot with the v3 key blob (C11) | as M5 (SC32) |

Anti-Deferral for the deferred column: VE9 is an operator action (a CA
issues to the deployment's public key; the image only needs the DER), VE10
and VE11 need a board (VE5). Worst case until then: throughput and RNDR
quality on hardware are unmeasured; RFC 6979 hedging (C5) keeps a weak RNDR
from leaking the signing key.

## Objective

An HTTPS endpoint on the outside NIC that accepts only TLS 1.3 with
X25519MLKEM768, authenticates with an ECDSA P-256 certificate whose private
key exists only in the passive `key` oracle, and forwards one HTTP/1.1
request per connection to a fixed backend on the inside network — with the
VPN's guarantees unchanged (bounded interference, C1/C5) and every new
parser bounded and checked.

## Decisions

- **D1 Own minimal TLS 1.3 server, primitives from libcrux.** rustls 0.23
  needs `alloc` (no PD outside the NIC drivers has a heap), needs a custom
  provider for X25519MLKEM768 anyway, and implements far more than this
  profile: one suite, one group, one signature algorithm, no resumption, no
  0-RTT, no client auth, no HRR. The protocol logic is ours; every primitive
  is libcrux (ML-KEM-768, X25519, ChaCha20-Poly1305, SHA-256, HKDF, HMAC,
  P-256 ECDSA via `libcrux-p256` — already locked for `tpm2`). Cost: RM6-1.
- **D2 smoltcp `=0.14.0` for TCP state, behind our TCP parser.**
  `default-features = false`, features `medium-ip`, `proto-ipv4`,
  `socket-tcp`; no `alloc`. Probe (2026-10-24): `cargo check` against
  `support/targets/aarch64-sel4-microkit.json` with `-Z build-std=core`
  passes; new transitive crates: bitflags, byteorder, cfg-if, hash32,
  heapless, managed, stable_deref_trait. It runs inside `tls` on IP packets
  that `ingress`/`inner` have parsed with `wire` (Kani). Cost: RM6-2.
- **D3 One image, one more PD.** `tls` joins the existing system. Changed
  VPN-side code: `wire`, `ingress-core`/`ingress`, `inner-core`/`inner`,
  `key-core`/`key`, `secret-blob`, `layout`, `timer`, `audit`, `config`,
  `hs-core` (invariants only), `tpm2` (envelope assert). The L13 cap rises
  0.90 → 0.95 for `tls` at 0.05 (C1). Stop rule: if the slice-1 or slice-3
  probe (C10) misses its margin, the slice stops and re-plans the budget
  split (re-planning, not widening: the M3 rule).
- **D4 One request per connection.** The request carries `Connection:
  close` to the backend; the response is streamed back unparsed and ends
  when the backend closes cleanly (C10 close rules). No keep-alive, no
  pipelining, no HTTP/2 (ALPN selects `http/1.1`).
- **D5 TLS key failure is TLS-only (F10).** A TLS scalar that is invalid or
  does not match the compiled certificate leaves `key` Ready for `hs`;
  `TlsSign` answers `ERR_UNAVAILABLE | code`, `tls` audits it and halts.
  The VPN keeps running.

## Threat model additions

| ID | Adversary | Capability |
|---|---|---|
| A1 | (existing) network attacker | now also: TCP SYN/ACK floods, slow handshakes, malformed TLS records and handshake messages, HTTP request smuggling attempts |
| A8 | Malicious HTTPS client | Completes a valid TLS handshake and sends arbitrary HTTP bytes |
| A9 | Backend | Returns arbitrary bytes; trusted for content, not for the proxy's memory safety |
| A3 | (existing) compromised PD | now also: a compromised `tls` (RM6-1/2) — bounded by C1, C2, C4 and C5 |

## Law amendments

Adjudicators are restated against the code (S13): L2 callers of a key PD
are the channels the policy allows (L4 default deny over `policy/laws.toml`
channels) plus `key_core::caller()`; L3 is per-region producer/consumers in
the policy.

| Law | Amendment |
|---|---|
| L2 | `key`'s closed oracle enum gains `TlsSign` (C5) and per-caller boot seeds; quotas become per caller. `tls` holds no pp channel to `pqkey` (the existing "no PD calls two key PDs" check). |
| L3 | "Tunnelled plaintext" becomes "plaintext of a protected session": the regions carrying HTTPS plaintext (`tln`, `ntl`) have `tls` and `inner` as their only producer/consumers; `tls` maps no ring shared with `hs`, `pq` or `data`. |
| L13 | Tainted ratio cap 0.90 → 0.95 (the M3 hard ceiling); `tls` 0.05 with role `untrusted_input` (F3, S12), so the existing `below` rows put it under `key` and `timer`. |
| **L14** (new) | PQ mandatory for HTTPS: no TLS traffic secret exists unless the handshake used X25519MLKEM768. Enforcement (C7): `KeySchedule::new` takes only `HybridSecret`, constructed only by `HybridSecret::exchange` (type system, `compile_fail` tests, a check-pins constructor rule); a check-pins code-point ban in `tls-core` is a best-effort tripwire (S6). |

## Contracts

Control classes follow R49. "Gate" = fail-closed verification gate unless
stated. Member sets are derived by the stated command at lock time and
re-derived in Phase 2. Each contract lists its files; the consumer
walkthroughs are in the Acceptance appendix.

### C1 — System, laws and budget (Critical tier)

- New PD `tls`: role `untrusted_input`, priority 100, budget 500/10000,
  stack 0x20000, not passive. Rings (each a used/free/data triple from
  `layout`, consumer maps data read-only): `itl` ingress→tls, `tli`
  tls→ingress, `tln` tls→inner, `ntl` inner→tls. Channels: ingress↔tls,
  tls↔inner (notify), timer→tls (notify-only), tls→key (PPC,
  `pp={tls=true,key=false}`, `notify={tls=false}`), tls→audit (`audit_tls`
  ring).
- `policy/laws.toml`: every new PD, MR, channel and attribute (L4); L13 cap
  0.95 and the `tls` budget row.
- Control class: enforceable boundary (seL4 capabilities as laid out by the
  checked `.system`). Adjudication: tools/laws over the exact file given to
  microkit. No new law code.
- Member set (callers of `key`): `grep -n 'pp="true"' system/secureos.system`
  filtered to channels whose other end is `key` → today {hs}; after {hs, tls}.
- Acceptance: `make laws` green; check-selftest cases under `laws`: a
  `tls`↔`pqkey` PPC (L2), a `tls` budget pushing the sum above 0.95 (L13),
  `tls` at priority 140 (L13 below `key`), `tls` mapping `hd` (L3/L4); each
  red with its law's message, and the shipped file green (allow side).
- Files: system/secureos.system, policy/laws.toml, crates/layout (new `tls`
  module; key, ingress, inner, audit, timer channel ids), crates/pds/timer
  (`PEERS`), crates/pds/audit (source list, `audit_tls`), Makefile (PD and
  lint-pds lists), tools/check-selftest.

### C2 — `ingress`: TCP admission and `tli` egress (Critical tier: first parser of A1 TCP bytes)

- Admission (F1): `wire::parse_frame` and its Verus spec stay unchanged
  (ARP or IPv4/UDP). In `ingress_core::respond`, on `Err(NotUdp)` the frame
  is re-parsed with `parse_frame_ip`; protocol 6 → `wire::parse_tcp(&Ip4Packet)
  -> Result<TcpHeader<'_>, DropReason>`: data offset 5..=15 within the
  payload, checksum over the pseudo-header from the packet's addresses, no
  SYN+FIN, no SYN+RST, no zero ports; options are length-walked only. Any
  other protocol → `NotUdp` as today. New `DropReason` variants are appended
  to `ALL` and run.py's mirror.
- Branch rules: destination our IP and port `HTTPS_PORT`, source not our IP
  and source MAC not ours (S16) → `Outcome::Tls`; other TCP → `NoService`.
  SYNs (SYN without ACK) pass a per-source SYN bucket and a global SYN
  bucket (`SYN_GLOBAL_BURST`, `SYN_GLOBAL_INTERVAL_NS`); all other segments
  pass a separate global TCP data bucket (F11). `Buckets` gains its
  constants as const generics so the SYN instance has its own (S18; the
  existing instance's Kani harnesses re-run).
- `ingress` copies the IP packet into `itl`.
- Egress (F2, S2, S3): `ingress_core::tls_egress(packet, tx_free) ->
  Result<Frame, DropReason>`: IPv4, protocol 6, source = outside IP, source
  port = `HTTPS_PORT`, destination unicast and not ours, length ≤ 1500,
  checksums valid; framed to `router_mac` (no ARP cache). TX tier: allowed
  only while `tx_free > TX_RESERVE + TLS_TX_SHARE` (compile-time asserted
  ≥ the `Unsolicited` tier), so `hs`/`data` keep their reserve.
- Control class: fail-closed verification gate (Kani-proved parser and
  egress check). Adjudication: `wire::parse_tcp`, `tls_egress`.
- Acceptance: Kani harnesses (bounds in the testing strategy) for
  `parse_tcp` (no panic, offset within payload, checksum checked on every
  accepted header), the new `respond` branch, and `tls_egress` (every
  accepted packet satisfies each field); bolero `wire` target with TCP
  seeds; unit allow/deny pairs at each bound; `tls_egress` refused at the
  reserve boundary while `data` output passes; existing Verus proofs of
  `wire` re-run green.
- Files: crates/wire (lib, tests, Kani, bolero seeds), crates/ingress-core,
  crates/pds/ingress, tests/integration/run.py (`DROP_REASONS`, `frame_for`:
  the `NotUdp` fixture moves to protocol 47, T14).

### C3 — `tls` PD: TCP via smoltcp (Major tier)

- Two `Interface`s (`Medium::Ip`) with two `SocketSet`s (F5): outside
  (outside IP, `itl`/`tli`, `MAX_CONNS` = 8 listeners on 443) and inside
  (inside IP, `ntl`/`tln`, 8 backend sockets). Each set is polled only by
  its interface. `Config::random_seed` (ISN) from the hedged RNG (C7).
- Socket options: `set_ack_delay(None)`, Nagle off, a SYN-RECEIVED/connect
  timeout via `set_timeout` (F6, F11). Polling: on every ring notification
  and timer tick; the timer is 1 Hz, so retransmission and probes run at
  ≥ 1 s granularity (accepted, recorded; F6).
- Backend ports: `TLS_PORTS` (config, 1024 ports) allocated round-robin; the
  sustained rate bound this gives against the backend's 60 s TIME-WAIT is
  recorded (F20).
- Control class: best-effort tripwire for TCP-level DoS (bounded pools,
  timeouts; SYN floods: RM6-7); smoltcp is trusted code inside a tainted PD
  (RM6-2).
- Acceptance: in slice 1, a TCP connect to 443 completes and data is echoed
  (echo mode removed in slice 3); FIN and RST handled.
- Files: crates/pds/tls (new), Cargo.toml (workspace), Cargo.lock.

### C4 — `inner`: backend routing (Major tier)

- `inner-core` parses inside TCP with the same `wire::parse_tcp` (F16b).
- Inbound → `ntl` only when: source = backend IP and source port = backend
  port, destination = inside IP, destination port ∈ `TLS_PORTS`, TCP. Local
  delivery: no TTL decrement (F16c). Everything else as today → `nd`.
- Outbound `tln` accepted only when: TCP, source = inside IP, source port ∈
  `TLS_PORTS`, destination = backend IP and destination port = backend port
  exactly (S2, F16d); forwarded out `eth_in` via the static neighbour table.
- Config validation (F16a): the backend must lie in `inside_prefix` and be a
  configured neighbour; build fails otherwise.
- Control class: enforceable boundary for what `tls` can reach and who can
  reach `tls` inside (inner drops). Adjudication: `inner-core` (Kani).
- Acceptance: Kani harnesses for both directions (accepted ⇒ every field
  holds) with allow cases (the backend's SYN-ACK reaches `ntl`; a legitimate
  `tln` SYN leaves); unit tests for each refusal (T9 — a compromised `tls`
  is simulated at unit level, not in QEMU).
- Files: crates/inner-core, crates/pds/inner, crates/config (validate.rs,
  tests), config/gateway.toml.

### C5 — `key`: TLS signing oracle (Critical tier)

- Blob v3 (`secret-blob`): v2 layout plus `tls_private[32]` (P-256 scalar,
  big-endian) after `boot_seed`; version 3; v2 refused (`BadVersion`).
  Member set: `grep -rnE 'KEY_MAX_PEERS|_key_body|KEY_BLOB_FIXED|FIXED|MAX_PEERS|80 \+' crates/secret-blob crates/tpm2 tools/package tools/mksecrets crates/config tests/integration/run.py`
  (F15, S18): secret-blob `FIXED` 112 → 144 / `MAX_PEERS` 124 → 123,
  envelope `KEY_MAX_PEERS` 110 → 109, tools/package `_key_body` 80 → 112 and
  `VERSION` 2 → 3, the secret-blob Python mirror test, run.py offsets.
- Validation (D5): the scalar is valid and its public point equals
  `config::TLS_PUBLIC`; else the TLS capability is `Unavailable{code}`
  (`TlsKeyInvalid` 17, `TlsKeyMismatch` 18) while `hs`'s labels keep
  working. Codes added to the code table and run.py's mirror.
- `LABEL_TLS_SIGN` = 4: request 4 words = the 32-byte transcript hash; `key`
  builds the TLS 1.3 server CertificateVerify content (64 × 0x20 ‖ "TLS 1.3,
  server CertificateVerify" ‖ 0x00 ‖ hash, RFC 8446 §4.4.3) and signs it
  with `libcrux_p256::ecdsa_sign_p256_sha2`. Reply 8 words = r ‖ s, each
  32 bytes big-endian (F8: `tls-wire` DER-encodes). `MAX_WORDS` of
  key-core 4 → 8 (`grep -rn 'MAX_WORDS' crates/key-core crates/pds/key
  crates/pds/hs crates/hs-core`; pqkey-core's own `MAX_WORDS` unchanged).
  The oracle signs nothing but a server CertificateVerify; a compromised
  `tls` can obtain such signatures for arbitrary transcripts while it is
  compromised (RM6-1).
- Nonce (S7): RFC 6979 §3.2 HMAC-DRBG (HMAC-SHA256, libcrux-hmac) with the
  §3.6 additional input k' = 32 bytes of RNDR; a candidate the sign function
  rejects (k ∉ [1, q−1]) continues step h.3. K, V, k, k' and the content
  buffer are `Secret` types, wiped after each signature; `key`'s stack is
  scrubbed after the call (the `scrub_session_stack` pattern). RNDR failure
  → `ERR_CRYPTO` (L9).
- Callers: `enum Caller { Hs, Tls }`; `allows()` exhaustive: `Tls` → {
  `TlsSign`, `BootSeed` }, `Hs` unchanged. Per-caller buckets. Boot seed per
  caller = `BLAKE2s(seed ‖ caller tag)`, `hs` included (S14); repeated calls
  return the same value and count against the caller's bucket (F12).
- Bucket and interference invariants (F12, S1, S14), compile-time:
  `TLS_SIGN_BURST − TLS_BOOT_CALLS ≥ SYN_GLOBAL_BURST`,
  `TLS_SIGN_INTERVAL_NS ≤ SYN_GLOBAL_INTERVAL_NS` (sized at the forwarded
  handshake rate: the abuse bound), and `TLS_SIGN_BURST ×
  ceil(SIGN_COST_NS / tls_budget_ns) × period_ns ≤ HS_KEY_WAIT_MAX_NS`, where
  `SIGN_COST_NS` is measured under TCG in slice 2 (recorded with its method)
  and `HS_KEY_WAIT_MAX_NS` is a stated fraction of WireGuard's
  REKEY_TIMEOUT. If no constants satisfy all three, D3's stop rule applies.
- Control class: enforceable boundary (closed label table, callee-only PPC).
  Adjudication: `Oracle::handle`'s exhaustive match.
- Acceptance: key-core unit tests (each label × caller incl. `Tls` →
  `StaticDh` refused, lengths, buckets, D5 codes); RFC 6979: A.2.5 (empty
  k') reproduced, a host differential test against the RustCrypto `rfc6979`
  crate (dev-dependency only) over random keys, hashes and k' values, a
  forced rejection-branch test, two k' values giving different r, RNDR
  failure → `ERR_CRYPTO`; integration: OpenSSL verifies CertificateVerify;
  a ClientHello flood while a WireGuard handshake completes within its
  timeout (S1), red-proved by raising `TLS_SIGN_BURST`; residue (T8).
- Files: crates/secret-blob, crates/key-core, crates/pds/key,
  crates/hs-core (invariants), crates/pds/hs (per-caller seed), crates/tpm2
  (envelope assert), tools/package, tools/mksecrets, tests/integration/run.py
  (`KEY_CALLERS`, codes, offsets).

### C6 — `tls-wire`: TLS 1.3 record and handshake parsing (Critical tier)

- Records: type ∈ {handshake, alert, application_data, change_cipher_spec};
  legacy version 0x0303 (0x0301 allowed on the first record); length ≤ 2^14
  (plaintext) or 2^14 + 256 (ciphertext, RFC 8446 §5.2). CCS: exactly one
  byte 0x01, unprotected, only between ClientHello and the client Finished,
  at most once (our rule beyond §5, S11a); otherwise `unexpected_message`.
- Protected records (§5.4): padding stripped, all-zero plaintext refused,
  inner type ∈ {handshake, alert, application_data}.
- Handshake framing (F23, S11b): messages may span records and several may
  share a record; ClientHello and the client Finished must end at a record
  boundary (key change), else `unexpected_message`; handshake reassembly ≤
  8 KiB.
- `client_hello`: legacy_session_id ≤ 32 (echoed); cipher suites must
  include 0x1303; compression = [0]; extensions walked by length, duplicates
  refused: supported_versions must include 0x0304; supported_groups;
  key_share with exactly one 0x11EC entry of 1216 bytes, duplicate groups
  refused (§4.2.8); a client offering 0x11EC in supported_groups without a
  key share for it is refused with its own reason (RM6-6); signature
  algorithms must include 0x0403; ALPN optional (`http/1.1` selected, only
  others → `no_application_protocol`); server_name parsed, unused;
  `pre_shared_key` must be last and requires `psk_key_exchange_modes`
  (§4.2.9) — then ignored (no tickets are ever issued); `early_data` →
  refused with `illegal_parameter` (S11g; no tickets means no conforming
  client sends it). Unknown extensions skipped.
- Serializers into caller buffers, sizes checked: ServerHello,
  EncryptedExtensions, Certificate (one DER), CertificateVerify with the
  DER `ECDSA-Sig-Value` from r ‖ s (8..=72 bytes, minimal INTEGERs; F8),
  Finished, alerts.
- Control class: fail-closed verification gate; adjudication: this parser.
- Acceptance: Kani (no panic; every accepted extension within its parent;
  duplicate refusal; DER length bounds); bolero with seeds of OpenSSL and
  curl ClientHellos captured on the tap (capture command recorded, T19);
  unit allow/deny pairs at every bound (T17): session_id 32/33, ClientHello
  8192/8193, plaintext 2^14/2^14+1, ciphertext 2^14+256/+257, key_share
  1216 ± 1; the DER encoder against an OpenSSL-verified signature.
- Files: crates/tls-wire (new).

### C7 — `tls-core`: handshake, key schedule, records (Critical tier)

- States: `AwaitClientHello → AwaitClientFinished → Connected → Closed`.
  Any unexpected message → fatal alert, connection closed, slot wiped.
- `HybridSecret::exchange(client_share, rng) -> Result<(HybridSecret,
  [u8; 1120]), Refusal>`: ML-KEM-768 encapsulation key checked (FIPS 203
  modulus check, libcrux), encapsulate, X25519 with a fresh ephemeral from
  the RNG (S11h; all-zero result refused); shared secret = ML-KEM ss ‖
  X25519 ss, server share = ML-KEM ct ‖ X25519 public (draft-ietf-tls-
  ecdhe-mlkem order). `HybridSecret`: not `Copy`/`Clone`/`Debug`, wiped on
  drop, no other constructor.
- Key schedule (RFC 8446 §7.1, libcrux-hkdf/SHA-256): `KeySchedule::new(
  HybridSecret, transcript)` wraps a private `schedule_from_ikm(&[u8; N])`
  reachable from outside the module only under `#[cfg(test)]` (F9, S6, T2).
  ChaCha20-Poly1305 record protection with the §5.3 nonce; a connection is
  closed before its sequence number would wrap.
- Finished verified with a constant-time compare (`ct_eq`; S9).
- KeyUpdate (S11d): refused before `Connected`; value 0 or 1, else
  `illegal_parameter`; updates the read key; a pending update request is one
  flag (no queue); the write key updates once per flag.
- Randomness: server random, X25519 ephemeral, ML-KEM encapsulation
  randomness and the smoltcp ISN seed from a hedged RNG seeded by `key`'s
  per-caller boot seed, RNDR and CNTPCT (the `pq` pattern); RNDR failure →
  no handshake (L9).
- Control class: enforceable boundary for L14 (type system); fail-closed
  for protocol errors.
- Acceptance (T1, T2, T3):
  - RFC 8448 §3 via `schedule_from_ikm`: early, handshake and master
    secrets, client/server handshake and application traffic secrets,
    Finished keys and verify_data (both use SHA-256; the trace's AES-128-GCM
    keys/IVs are not compared).
  - Record keys/IVs and record protection: a fixture from a captured OpenSSL
    session plus its keylog, decrypted by Python `cryptography`
    (HKDF-Expand-Label, ChaCha20Poly1305) and committed; the unit test
    reproduces it; KeyUpdate's `traffic upd` derivation likewise.
  - A host test client (Rust, libcrux on the host: ML-KEM keygen/decaps,
    X25519) drives the server through: a valid handshake; tampered Finished
    → `decrypt_error`; flipped tag → `bad_record_mac`; out-of-order message
    → `unexpected_message`; second CCS and CCS after Finished; KeyUpdate
    value 2; each asserting the slot is wiped.
  - `compile_fail` doctests: `HybridSecret` not `Clone`/`Copy`, not
    constructible outside its module.
  - Integration: OpenSSL/curl complete; `-groups X25519` →
    `handshake_failure`, audit `TlsRefused{NoPqGroup}`; TLS 1.2-only →
    `protocol_version`; supported-but-no-share → its own reason.
- Files: crates/tls-core (new), crates/pds/tls.

### C8 — Secrets and plaintext lifecycle in `tls` (Critical tier, L12)

- Wipe points: handshake secrets when the application secrets exist; the
  superseded traffic secret and keys at KeyUpdate; on close, alert, timeout
  and refusal: traffic secrets, record keys, `HybridSecret`, the record and
  head buffers and both sockets' storage (S10). The slot is wiped before the
  client sees the connection end, and `tls` audits `TlsClosed{reason}`
  after the wipe (T7: the scan's barrier).
- Acceptance: integration residue cases with OpenSSL `s_client
  -keylogfile`, scanning for the secrets and for the record key/IV derived
  from them in Python (T6, T7):
  1. While a connection is open after the handshake: handshake traffic
     secrets absent, CLIENT_TRAFFIC_SECRET_0 present (the control).
  2. After an `s_client` KeyUpdate (`k`): secret_0 absent, secret_1
     (HKDF-Expand-Label "traffic upd") present.
  3. After `TlsClosed`: the connection's secrets, keys and a request/
     response marker string absent; the control is a second, held-open
     connection's traffic secret (kept within its idle timeout, read from
     the Rust source).
  Alert and timeout wipes are host unit tests on the connection core (C10).
  Selftest cases (one per wipe point) remove each wipe and turn its case red.
- Files: crates/tls-core, crates/pds/tls, tests/integration/run.py.

### C9 — `http-wire`: request head parsing and rewrite (Critical tier: A8 bytes)

- `request_head(bytes) -> Result<Head<'_>, HttpRefusal>`: request line
  `token SP origin-form SP HTTP/1.1 CRLF` with the origin-form character set
  of RFC 9112/3986; ≤ 32 headers; head ≤ 8 KiB; field names are tokens
  without `_` (S5); values without CR, LF, NUL or other CTLs except HTAB
  (S15); no obs-fold; no whitespace before the colon; names matched ASCII
  case-insensitively. Refused: any `Transfer-Encoding`, more than one or a
  non-decimal `Content-Length`, absolute-form, asterisk-form, `CONNECT`,
  `Upgrade`, a `Connection` header naming `Content-Length`,
  `Transfer-Encoding`, `Host` or any field the proxy sets (S5); missing or
  duplicate `Host`, or a Host value that is not authority syntax (S15,
  F17); `Expect` (417).
- `rewrite(head, client_ip, out) -> Result<usize, HttpRefusal>`: request
  line verbatim; hop-by-hop fields dropped (`Connection` and the fields it
  names, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Upgrade`); `Forwarded`,
  `X-Real-IP` and every `X-Forwarded-*` dropped, then ours appended
  (`X-Forwarded-For`, `X-Forwarded-Proto: https`) and `Connection: close`;
  output bounded (overflow → 431).
- Statuses: 400 (syntax), 413 (`Content-Length` > `MAX_BODY`, decided at
  head time), 417 (`Expect`), 431 (head or rewrite too large), 501
  (method/feature refused); fixed bodies; then close (C10 rules).
- Control class: fail-closed verification gate. Adjudication: this parser;
  the backend sees only `rewrite`'s output plus exactly `Content-Length`
  body bytes.
- Acceptance: Kani (no panic, every slice within the head, CL parse without
  overflow); bolero with smuggling seeds (CL.TE, TE.CL, TE.TE, duplicate
  CL, signed/spaced CL, obs-fold, bare LF, `Connection: content-length`,
  underscore names); unit allow/deny pairs (32/33 headers, 8192/8193 head);
  an allow case where ordinary custom headers pass unchanged.
- Files: crates/http-wire (new).

### C10 — Proxy flow, limits, close and timeouts (Major tier)

- The connection/slot/timer machinery lives in `tls-core::conn` with an
  injected clock (T16), the PD only wiring rings and smoltcp to it.
- Flow: TLS handshake → head (≤ 8 KiB) → rewrite → backend connect → head +
  body (≤ `MAX_BODY` 1 MiB, streamed) → response streamed to the client.
- Close rules (F4, F7): close_notify only after a clean backend FIN; then
  `tls` waits ≤ 2 s for the client's close_notify/FIN and aborts the socket
  (no TIME-WAIT slot). Backend RST, any timeout, a `tls` error or a refusal
  after the response started → TCP RST to the client without close_notify
  (truncation is visible). A client FIN or close_notify before the response
  ends → backend aborted.
- Limits: `MAX_CONNS` 8, at most 2 per source address, total connection
  lifetime 120 s (S17). Timeouts: handshake 10 s, head 10 s, backend connect
  5 s, idle 30 s; each wipes the slot (C8). Activity does not reset the
  handshake or head timer.
- Memory (F18): per connection two sockets (outside rx 16 KiB / tx 8 KiB,
  backend rx 8 KiB / tx 16 KiB), a 16 KiB + 256 rx record buffer, a 4 KiB +
  256 tx record buffer (server records ≤ 4 KiB), head 8 KiB, rewrite 9 KiB
  ≈ 86 KiB; × 8 ≈ 690 KiB static, asserted at compile time against
  `TLS_STATE_MAX` (1 MiB).
- Audit (L10; `crates/audit-event`, appended): `TlsAccepted`,
  `TlsRefused{reason: u8}`, `TlsClosed{reason: u8}`, `HttpRefused{status:
  u16}`, `BackendUnavailable`, `TlsTimeout{stage: u8}`, `TlsStackHighWater`;
  the audit PD's name table and run.py's parser updated.
- Probes (D3, T13, F19): slice 1 measures ML-KEM-768 encapsulation +
  X25519 + HKDF CPU time at 0.05; slice 3 measures 20 full handshakes and 8
  concurrent ones. Margin: the slowest handshake ≤ 1/3 of the 10 s handshake
  timeout and of run.py's wait for it; else the stop rule.
- Control class: best-effort tripwire for resource exhaustion (known
  bypass: eight slow-but-valid clients from four sources — RM6-4).
- Acceptance: conn-core unit tests per stage (timeouts with the injected
  clock, each wiping the slot; per-source cap; lifetime); the integration
  cases below.
- Files: crates/tls-core, crates/pds/tls, crates/audit-event,
  crates/pds/audit, tests/integration/run.py.

### C11 — Packaging, config and certificate (Major tier)

- Order (F13): `mksecrets` generates the P-256 scalar, writes blob v3 and
  `tls.pub`, then runs `tools/mkcert` (Python `cryptography`, host only) to
  make the dev CA and the leaf, then writes config naming the leaf and
  `tls_public`, then validates it; `make package` takes the blob as in M5.
- Dev CA (S8): critical NameConstraints (permitted dNSName = the configured
  SAN), `pathLen=0`, 30-day validity; its private key is destroyed after
  issuing the leaf. Leaf: SAN from config, EKU serverAuth, KU
  digitalSignature, CA:false.
- Config (`config/gateway.toml`): `https_port`, `tls_ports`, backend
  address and port, `tls_cert` (DER path), `tls_public` (hex). `config`'s
  build.rs emits them for the PDs that read them (`ingress`, `inner`,
  `tls`, `key`) and `TLS_CERT: &[u8]`; it checks that the certificate
  contains the fixed 26-byte P-256 SPKI prefix followed by `tls_public`
  (no DER parser; R1). `MAX_BODY`, the head limit and `MAX_CONNS` are
  compile-time constants in `tls` (security ceilings, not configuration).
- tools/package, the envelope size assert and release verify: unchanged
  formats except the v3 blob; the descriptor stays at two envelopes.
- Acceptance: `make package` with a v3 blob produces a sealed image that
  boots and serves HTTPS; `secret-blob` unit test: v2 → `BadVersion`;
  integration: a blob with a different TLS scalar packaged on the same image
  (mksecrets option, the existing "b" pattern; T22) → `TlsSign` unavailable,
  `tls` audits and halts, the VPN still completes a handshake (D5); OpenSSL:
  a leaf for another name signed by the CA fails verification, the
  configured SAN passes.
- Files: tools/mksecrets, tools/mkcert (new), crates/config, config/
  gateway.toml, tools/package, Makefile.

## Testing strategy

- Per slice: unit tests, the slice's Kani harnesses (each alone first, under
  the proof lock and a 40 GB cap), selftest cases, `make test` when run.py or
  a crate it reads changes, the slice's integration cases.
- Gate enrolment (T16): `tls-wire`, `tls-core`, `http-wire` join
  `host_crates`, lint, `kani_crates` (tls-wire, http-wire) and
  `bolero_targets` (tls-wire, http-wire); `tls` joins the PD, lint-pds and
  ct-shape "no Verus symbols" lists; check-pins P9/P10/P11 crate lists gain
  `tls-core`, `pds/tls` and `key-core` (S9); new manifest keys:
  UNIT-TLS-WIRE, UNIT-TLS-CORE, UNIT-HTTP-WIRE, KANI-TLS-WIRE,
  KANI-HTTP-WIRE and updated KANI-WIRE/INGRESS-CORE/INNER-CORE,
  BOLERO-TARGETS 4 → 6, CHECK-PINS-RULES/FIXTURES, MIR-CRATES,
  INTEGRATION-CASES.
- Kani bounds (T15): `parse_tcp` over a ≤ 64-byte symbolic payload;
  `tls_egress` and inner branches over ≤ 64-byte packets; `tls-wire` record
  header and the extension walker over ≤ 96-byte messages; the DER encoder
  over symbolic r, s; `http-wire` head over ≤ 96 bytes and ≤ 4 headers;
  unwind stated per harness. All new crates (as stubs), all dependencies and
  the `tls` PD land in slice 1 so the Kani cache keys (Cargo.toml/Cargo.lock)
  change once.
- Integration (boot group `https`, netns): outside tap with curl/OpenSSL
  clients (several source IPs where a case needs them); inside tap with a
  raw-socket backend that logs each connection's peer and raw bytes and
  answers fixed or echo responses (T10). `ip_forward=0` asserted. Preflight
  fails unless `openssl list -tls-groups` has X25519MLKEM768 and curl links
  OpenSSL 3.5 (T21). Cases:
  1. GET returns the backend body byte for byte; curl verifies the chain and
     hostname; the negotiated group is X25519MLKEM768; a wrong CA or name
     fails curl (verification is on).
  2. The backend log shows exactly `rewrite`'s bytes (hop-by-hop gone,
     X-Forwarded-For = client address, `Connection: close`) from the inside
     IP; POST bodies of 0, 1 and `MAX_BODY` bytes arrive exactly;
     `MAX_BODY` + 1 → 413 at head time.
  3. `-groups X25519` → handshake_failure, `TlsRefused{NoPqGroup}` (L14).
  4. TLS 1.2-only → protocol_version.
  5. Smuggling and header cases (TE+CL, duplicate CL, obs-fold,
     `Connection: content-length`, underscore name, spoofed `Forwarded`) →
     the stated status; after each, a valid request is sent and the backend
     log grows by exactly that one connection (barrier, T10).
  6. Head > 8 KiB → 431.
  7. Residue cases (C8) and the scalar count (below).
  8. TLS-only key failure (C11): HTTPS refused, VPN handshake completes.
  9. HTTPS SYN flood (spoofed sources): ingress SYN-drop audit total ≥ N
     first, then a WireGuard handshake and transport still work (the VPN
     half; HTTPS during the flood is RM6-7) (S4, T11).
  10. Eight connections from four sources held established; a ninth from a
      fifth source is refused with RST; a third from one source is refused
      (per-source cap); more than `MAX_CONNS` sequential connections within
      10 s are all served (F4).
  11. Slowloris: one byte at intervals shorter than the timeout until past
      it → `TlsTimeout{Handshake}` and EOF/RST, bounded from above only.
  12. ClientHello flood while a WireGuard handshake completes (C5, S1).
  13. The full VPN suite unchanged.
- Scalar residue (T8, F21): a helper asserts an exact count; after a
  handshake observed on the client, the TLS scalar occurs exactly once
  big-endian (`key`'s plaintext buffer) and never little-endian in guest RAM;
  a selftest case that copies it into `tls` turns it red.
- Mutations (T18): each a check-selftest case with gate and failure-only
  needle, listed in the Implementation Checklist at Phase 2 start: L14
  constructor and Clone, check-pins code-point spellings, Finished check and
  its `ct_eq`, CCS rules, key_share length, duplicate extension, the three
  C8 wipes, the k' input, `allows()` Tls→StaticDh, D5 codes,
  CertificateVerify content built in `key`, `parse_tcp` checksum/offset/
  SYN+FIN, `tls_egress` fields, inner both directions, SYN buckets, TE and
  duplicate-CL refusals, `Connection` naming CL, the `X-Forwarded-*` strip,
  the per-source cap.
- Integration cost (T22): stated after slice 3 (INTEGRATION-CASES delta,
  number of 2 GiB scans, wall time).

## Slices (order)

1. C1 + C2 + C3 (echo): every new crate as a stub and every dependency
   (smoltcp, libcrux-hkdf, ML-KEM-768 feature, rfc6979 dev-dep); `tls` PD
   with smoltcp echo on 443; the NotUdp fixture move; first probe.
2. C5 + C11: blob v3, `TlsSign`, RFC 6979, per-caller buckets and seeds,
   `SIGN_COST_NS` measurement, certificate tooling.
3. C6 + C7 + C8: TLS handshake and records; OpenSSL interop; echo over TLS;
   second probe.
4. C4 + C9 + C10: backend routing, HTTP rewrite, proxy flow.
5. Hardening cases, selftest, manifest, docs; final gates.

## Considerations & constraints

- `wire` and `ingress-core` are Verus/Kani-verified: `parse_frame`'s spec is
  untouched; new functions are Kani-only (SC35). The per-PD cargo invocation
  keeps ML-KEM-768 out of `pq`'s build.
- No Kani/Verus concurrency; container at 40 GB; subagents run no Kani,
  `make check` or QEMU.
- After M6 the tainted budget sum is at the 0.95 ceiling: no headroom for
  later tainted PDs without re-planning.

### Residual risks added

- **RM6-1** own TLS 1.3 / HTTP protocol code without a formal proof of the
  state machine; mitigated by Kani on parsers, bolero, RFC 8448 and keylog
  fixtures, the host test client and OpenSSL interop. Worst case (A3 on
  `tls`): plaintext and traffic keys of current connections, and server
  CertificateVerify signatures for arbitrary transcripts while compromised
  (impersonation for that period); never `key`'s secrets; past connections'
  plaintext is wiped (C8).
- **RM6-2** smoltcp is unverified code in a tainted PD; same worst case. A
  panic in `tls` or smoltcp ends HTTPS until reboot (no restart, SC17).
- **RM6-3** dev CA only (VE9).
- **RM6-4** eight slow-but-valid clients from four sources can hold every
  slot until the 120 s lifetime.
- **RM6-5** libcrux P-256 and ML-KEM are outside the ct gate (as libcrux
  elsewhere, R-M1 class).
- **RM6-6** no HRR: a client that supports X25519MLKEM768 but sends no key
  share for it is refused rather than asked again.
- **RM6-7** HTTPS under a spoofed SYN flood: smoltcp has no SYN cookies, so
  spoofed SYNs can occupy the listeners until their SYN-RECEIVED timeout;
  ingress buckets keep the flood from reaching the VPN and `key`.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC6 | HTTPS proxy | closed by M6 |
| SC34 | HelloRetryRequest (RM6-6) | unscheduled |
| SC35 | Verus proofs for `parse_tcp`, `tls-wire`, `http-wire` (Kani in M6) | unscheduled (SC29 Vest) |
| SC36 | HTTP keep-alive, HTTP/2, multiple backends, TLS session tickets | unscheduled |
| SC37 | WebPKI certificate issuance and renewal | ops (VE9) |
| SC38 | SYN cookies / client puzzles for HTTPS (RM6-7) | unscheduled |

## User operation scenarios

1. Operator: puts the backend in config, runs `mksecrets` (blob v3, fresh
   P-256 key, dev CA and leaf, config) and `make package` → envelopes sealed
   as in M5; boots; `curl --cacert devca.pem https://gw/` returns the
   backend's page.
2. A browser without X25519MLKEM768 connects → handshake failure, audit
   `TlsRefused{NoPqGroup}`.
3. An attacker sends `Transfer-Encoding: chunked` with `Content-Length` →
   400, nothing reaches the backend.
4. A spoofed SYN flood at 443 → VPN peers keep working; HTTPS may refuse new
   clients until the flood stops (RM6-7).
5. The image is swapped (A6) → `key` stays sealed, no TLS key, no
   handshake (as M5).

## Acceptance appendix: consumer walkthroughs (F15)

| Shape | Producer | Consumer reads → use |
|---|---|---|
| Blob v3 | mksecrets `write` | `secret_blob::Blob::parse` reads version, gateway_private, boot_seed, tls_private, peer hashes, checksum → `key` validation; tools/package `_key_body` reads the same sizes → envelope payload length; run.py reads gateway_private [16:48] (unchanged) and tls_private [80:112] → residue needles |
| `TlsSign` request | `tls` | `key` reads 4 words → 32-byte transcript hash → builds the CertificateVerify content |
| `TlsSign` reply | `key` | `tls-wire` reads 8 words → r [0..32], s [32..64] big-endian → DER `ECDSA-Sig-Value` |
| `itl`/`ntl` buffers | ingress / inner | `tls` reads one raw IPv4 packet ≤ 1500 bytes (length in the used-ring entry) → smoltcp `Device::receive`; producer notifies `tls` |
| `tli`/`tln` buffers | `tls` | ingress `tls_egress` / inner reads one raw IPv4 packet → checks of C2/C4 → frame; `tls` notifies the consumer |
| Audit events | `tls` | audit PD reads code + integers → name table line on the UART; run.py parses `audit: src=tls <Name> field=N` |
| Config outputs | config build.rs | ingress: `HTTPS_PORT`; inner: backend IP/port, `TLS_PORTS`; tls: both plus `TLS_CERT`; key: `TLS_PUBLIC` |

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | System, laws, budget | pending |
| C2 | ingress TCP admission and tli egress | pending |
| C3 | tls PD TCP via smoltcp | pending |
| C4 | inner backend routing | pending |
| C5 | key TLS signing oracle | pending |
| C6 | tls-wire parsing | pending |
| C7 | tls-core handshake, key schedule, records | pending |
| C8 | secrets and plaintext lifecycle in tls | pending |
| C9 | http-wire head parsing and rewrite | pending |
| C10 | proxy flow, limits, close, timeouts | pending |
| C11 | packaging, config, certificate | pending |
