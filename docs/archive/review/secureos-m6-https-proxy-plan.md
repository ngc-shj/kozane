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
  `hs-core` (invariants), `hs` (the key-wait audit), `tpm2` (envelope
  assert). The L13 cap rises
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
| L3 | "Tunnelled plaintext" becomes "plaintext of a protected session": the regions carrying HTTPS plaintext (`tln`, `ntl`, and the existing `inner_rx`/`inner_tx`) keep their declared producer/consumers (`tls`, `inner`, `eth_in`); `tls` maps no ring shared with `hs`, `pq` or `data`. |
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
- Branch rules: Ethernet destination our MAC, destination our IP and port
  `HTTPS_PORT`, source not our IP and source MAC not ours (S16, F-N9) → `Outcome::Tls`; other TCP → `NoService`.
  SYNs (SYN without ACK) pass a per-source SYN bucket and a global SYN
  bucket (`SYN_GLOBAL_BURST`, `SYN_GLOBAL_INTERVAL_NS`); all other segments
  pass a separate global TCP data bucket (F11), whose constants and the
  throughput they allow are recorded in slice 1 (F-N11). Bucket refusals
  raise a coalesced audit kind `TcpLimited{syn_source|syn_global|data}`
  (T-N5). `Buckets` gains its
  constants as const generics so the SYN instance has its own (S18; the
  existing instance's Kani harnesses re-run).
- `ingress` copies the IP packet into `itl`.
- Egress (F2, S2, S3): `ingress_core::tls_egress(packet, tx_free) ->
  Result<Frame, DropReason>`: IPv4, protocol 6, source = outside IP, source
  port = `HTTPS_PORT`, destination unicast and not ours, length ≤ 1500,
  checksums valid, no SYN without ACK (`tls` never opens outbound
  connections; S-N5); framed to `router_mac` (no ARP cache). TX tier: allowed
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
  its interface. `Config::random_seed` from the hedged RNG (C7). smoltcp 0.14 derives
  ISNs from PCG32 seeded once (`src/rand.rs`, read 2026-10-24), so ISNs
  are predictable from observed ones (RM6-7, SC38).
- Socket options: `set_ack_delay(None)`, Nagle off. `set_timeout` is
  socket-wide, so a listener is armed with 5 s and the socket's timeout is
  raised to the 30 s idle timeout on reaching Established (F6, F11, F-N5). Polling: on every ring notification
  and timer tick; the timer is 1 Hz, so retransmission and probes run at
  ≥ 1 s granularity (accepted, recorded; F6).
- Backend ports: `TLS_PORTS` (config, 1024 ports; validated: start ≠ 0,
  count ≥ `MAX_CONNS`, start + count ≤ 65536, both sides of each bound
  tested; F-N-d) allocated round-robin; the
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
  (F15, S18): secret-blob `FIXED` 80 → 112 (F-N1) / `MAX_PEERS` 124 → 123,
  envelope `KEY_MAX_PEERS` 110 → 109, tools/package `_key_body` 80 → 112 and
  `VERSION` 2 → 3, the secret-blob Python mirror test (extended to assert
  that Rust's body length equals `_key_body` for several peer counts),
  run.py offsets.
- Validation (D5): the scalar is valid and its public point equals
  `config::TLS_PUBLIC`; else the TLS capability is `Unavailable{code}`
  (`TlsKeyInvalid` 17, `TlsKeyMismatch` 18) while `hs`'s labels keep
  working. The TLS check runs on the mutable plaintext before the
  long-lived `Blob` borrow; on failure bytes [80:112] are wiped and the
  TLS status is stored beside the blob (the checksum is not re-checked
  after the wipe) (S-N3, F-N8). `key`'s stack is scrubbed after the boot-time
  TLS check, on success and failure (F-N-b). The codes are a separate `TlsKeyError`
  sharing the code space, never returned by `Oracle::boot`; a unit test
  shows no `code()` collides. Codes added to run.py's mirror.
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
  rejects (k ∉ [1, q−1]) continues step h.3, at most 8 candidates, then
  `ERR_CRYPTO` (S-N4, F-N6; a retry has probability ≈ 2^-32 per candidate, as q lies ≈ 2^224 below 2^256, so all 8 refused ≈ 2^-256; corrected in code review round 1, S3). K, V, k, k' and the content
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
  handshake rate: the abuse bound), and the per-call wait `(ceil(
  SIGN_COST_NS / TLS_BUDGET_NS) + 1) × PERIOD_NS ≤ HS_KEY_WAIT_MAX_NS`: `tls`
  is single-threaded and the endpoint queue is priority-ordered (`hs` 110 >
  `tls` 100), so `hs` waits behind at most one sign in progress, plus the
  part of `tls`'s current period already spent (S-N1, F-N7).
  `TLS_BUDGET_NS`/`PERIOD_NS` live in `layout`, checked against the
  `.system` by layout's tests. `SIGN_COST_NS` = the maximum of 20 runs under
  TCG × 2, recorded with the libcrux-p256 lock entry; a check-pins rule
  fails when Cargo.lock's libcrux-p256 entry differs from the recorded one
  (re-measure trigger; a fixture with a changed entry and a selftest case
  under `pins`, T-R3-10). `HS_KEY_WAIT_MAX_NS` is a stated fraction of
  WireGuard's REKEY_TIMEOUT. If no constants satisfy all three, D3's stop
  rule applies. `hs` audits its key-call wait high-water as a value event
  (`KeyWaitHighWater us=N`, like `RpCostHighWater`) — the runtime
  observable (T-N7).
- Control class: enforceable boundary (closed label table, callee-only PPC).
  Adjudication: `Oracle::handle`'s exhaustive match.
- Acceptance: key-core unit tests (each label × caller incl. `Tls` →
  `StaticDh` refused, lengths, buckets, D5 codes); RFC 6979: A.2.5 (empty
  k') reproduced, a host differential test against the RustCrypto `rfc6979`
  crate (dev-dependency only) over random keys, hashes and k' values plus
  hash values ≥ n reduced independently in the test (S-N4), a forced
  rejection-branch test, the 8-candidate cap through a seam that keeps
  rejecting, two k' values giving different r, RNDR
  failure → `ERR_CRYPTO`; integration: OpenSSL verifies CertificateVerify;
  case 12 (S1, T-N7); residue (T8).
- Files: crates/secret-blob, crates/key-core, crates/pds/key,
  crates/hs-core (invariants), crates/pds/hs (`KeyWaitHighWater`), crates/tpm2
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
  (§4.2.9) — then ignored (no tickets are ever issued); `early_data` is
  ignored as RFC 8446 §4.2.10 allows: records that fail deprotection
  under the handshake key are skipped up to 16 KiB in total, then
  `bad_record_mac` (S11g, S-N8) — only when the ClientHello offered
  early_data, without advancing the handshake read sequence number, and
  only until the first record that deprotects; any later failure is fatal
  (S-R3-3). Unknown extensions skipped.
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
  drop, no other constructor. The X25519 ephemeral scalar, the ML-KEM
  encapsulation randomness and both component shared secrets are wiping
  `Secret` types; `tls` scrubs its stack with `tls_core::scrub_session_stack`
  (in the library, with an exported `SCRUB_DEPTH_EXCHANGE` sized from the
  exchange's measured depth; T-R5-2) after `exchange` and after the
  `TlsSign` call (S-R3-2).
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
    value 2; each asserting the slot is wiped. early_data (T-R3-6,
    S-R3-3): offered with 16 KiB of undecryptable records before the client
    Finished → completes; 16 KiB + 1 → `bad_record_mac`; not offered and one
    undecryptable record → `bad_record_mac`; one after `Connected` →
    `bad_record_mac`. With a deterministic-RNG seam, after `exchange` the
    ephemeral and the randomness are absent from the wiped buffers (S-R3-2).
  - ct-harness residue mode (T-R4-1): `HybridSecret::exchange` with a known
    RNG followed by `tls_core::scrub_session_stack`, run on the harness's
    painted stack (high-water asserted within `SCRUB_DEPTH_EXCHANGE`) and
    searched for every stored form of the ephemeral scalar, the
    encapsulation randomness and both component shared secrets (as for
    `tpm2::envelope::open_sealed`); the root is a non-generic inner
    function taking the randomness as bytes, the RNG-generic shim excluded
    from identity by name (the McEliece `encaps` precedent), and the scrub
    is `#[inline(never)]`, called from the frame that called `exchange`
    (F-R6-1); RESIDUE-CASES raised; a selftest case
    under `ct` removes the scrub. Binding to what ships (T-R5-1): every
    libcrux crate `tls-core` pulls into tools/ct-harness is `=`-pinned to the
    root lock's version (the `sha3`/`keccak` precedent), and ct-shape gains
    `(pd-tls, tls_core::exchange_with_randomness)` (the non-generic inner
    function) and the scrub as identity roots (identity
    check only; libcrux stays outside the shape baseline, RM6-5). ct-shape
    gains an identity-only root class for this (T-R6-1), with
    tests/tools/test_ct_shape.py fixtures (a differing tls closure fails
    with the identity message; a libcrux function absent from the shape
    baseline does not fail for that root while existing roots still do),
    CT-SHAPE-FIXTURES raised, CT-SHAPE-SYMBOLS updated, and a selftest case
    under `ct-shape` perturbing the tls closure.
  - `compile_fail` doctests: `HybridSecret` not `Clone`/`Copy`, not
    constructible outside its module.
  - Integration: OpenSSL/curl complete; `-groups X25519` →
    `handshake_failure`, audit `TLS_REFUSED_BASE + NoPqGroup`; TLS 1.2-only →
    `protocol_version`; supported-but-no-share → its own reason.
- Files: crates/tls-core (new), crates/pds/tls.

### C8 — Secrets and plaintext lifecycle in `tls` (Critical tier, L12)

- Order (T-R3-3, F-R4-1, S-R4-1, S-R5-1): close_notify or a fatal alert is
  sealed into the socket's send buffer, then keys and the record, head and rewrite buffers are
  wiped, then it is transmitted. smoltcp owns socket storage while the
  socket exists and sends an abort's RST only from the live socket at the
  next poll, so the socket is aborted and polled; once that poll has
  dispatched the RST (observed by `tls`'s own `Device` transmit path, which
  records a RST for the aborted 4-tuple written into `tli`; F-R6-2), the socket is removed from its set, its storage
  wiped through the static and the listener re-created, before any further
  poll of the outside interface (F-R5-2). If `tli` had no free buffer, the
  RST is retried on the next passes, at most 8, then the socket is removed
  and wiped anyway (F-R5-1). This sequencing (dispatched or not, the retry
  counter, wipe on exhaustion) lives in `tls-core::conn`, the PD only
  reporting the observed RST; unit tests: dispatched on pass k ≤ 8 → wiped
  on that pass, never dispatched → wiped after pass 8 (T-R6-2). The backend
  socket follows the same `conn` sequence, its RST observed on `tln` and
  its polls those of the inside interface; the barrier ordering concerns
  only the outside interface (F-R7-1). The
  backend socket's storage wipe itself has no integration observable (no
  value on the backend path is unique to `tls`): the decision is red-proved
  by the unit test; the storage wipe itself is a declared gap without a
  red-proof, its single call site reviewed (T-R7-1).
- Wipe points: the client handshake secret once the client Finished is
  verified, the server handshake secret once the application secrets exist
  (T-N4); the superseded traffic secret and keys at KeyUpdate; on close,
  alert, timeout and refusal: traffic secrets, record keys, `HybridSecret`,
  the rx and tx record buffers, the head and rewrite buffers and both
  sockets' storage (S10, S-N2). The host-observed barrier for a closed
  connection: the sniffer sees the server's abort RST for its 4-tuple, then
  a fresh SYN to 443, from an address the boot uses for nothing else and
  retried a bounded number of times (failing with "barrier SYN
  unanswered"; T-R5-3), gets its SYN-ACK or RST; `tls` handles that SYN in a
  later pass than the one that emitted the abort RST, so the wipe is done
  (T-R3-3, F-R4-1).
- Scope (S-N2): the claim covers `tls`-owned memory. The backend link
  (`tln`/`ntl`, `inner`, `eth_in` buffers) carries the request and response
  in cleartext by design, as `dn`/`nd` do for the VPN.
- Acceptance: integration residue cases in a dedicated boot `https-residue`
  (T-N2) with OpenSSL `s_client -keylogfile`, scanning for the secrets and
  for the record key/IV derived from them in Python (T6, T7). Barriers are
  host-observed (T-N4): the raw backend's log of a request head proves the
  server verified the client Finished and decrypted data sent after a
  KeyUpdate; the backend then holds the response open.
  Cases 1→2 are one connection (T-R3-2): a POST head with `Content-Length:
  L` and part of the body.
  1. After the backend logs the head: the client and server handshake
     traffic secrets absent, CLIENT_TRAFFIC_SECRET_0 present.
  2. Then `k`, then more body; after the backend logs those body bytes
     (decrypted under the new key): client secret_0 absent, client secret_1
     (HKDF-Expand-Label "traffic upd") present; a `K` variant for the server
     write secret.
  3. After that barrier: the connection's secrets, keys and its marker
     absent.
     The marker is the value of a `Keep-Alive` field, which `rewrite` drops,
     so only `tls` ever holds it (asserted absent from the backend log too;
     T-N3). The control is a second connection held in response streaming
     (the backend sends part of a response and keeps the socket open; idle
     timeout and lifetime read from the Rust source) with a marker of its
     own.
  Alert and timeout wipes are unit tests on `tls-core::conn`, asserting
  through a `cfg(test)` accessor `Slot::is_zeroized()` (T-N15). Selftest
  cases (one per wipe point) remove each wipe and turn its case red.
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
- Close rules (F4, F7): close_notify only after a clean backend FIN or
  after a response `tls` generated itself in full before any backend byte
  (a refusal; F-N3); once the send buffer has drained (close_notify ACKed),
  `tls` waits ≤ 2 s for any inbound record or FIN (not decrypted: the read
  key is already wiped; F-R4-2, S-R4-1) and aborts the socket
  (no TIME-WAIT slot); the whole close is bounded by the idle timeout
  (F-N4). Backend RST, any timeout, a `tls` error or a refusal
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
- Audit (L10; `crates/audit-event`, appended; F-N2): attacker-driven kinds
  are coalesced with one code per value, as `FRAME_DROPPED_BASE + reason`:
  `TLS_REFUSED_BASE + reason`, `TLS_CLOSED_BASE + reason`,
  `HTTP_REFUSED_BASE + status index` (400, 413, 417, 431, 501),
  `TLS_TIMEOUT_BASE + stage`, `TCP_LIMITED_BASE + {syn_source,
  syn_global, data}` (C2), `BackendUnavailable`; `a` is the running total.
  `tls` also uses the existing `KeyUnavailable{code}` and `Halted{reason}`
  with a closed `tls` halt table (`KEY_UNAVAILABLE`, `RNDR`, `INIT_FAILED`)
  for D5. Value events (not coalesced, emitted on a new high): the existing
  per-producer `StackHighWater` and `KeyWaitHighWater` (C5) (F-N-a). No barrier depends
  on an audit line; cases assert totals where they need counts. The audit
  PD's name table and run.py's parser are updated.
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
- Dev CA (S8, S-N7, S-R3-1): critical NameConstraints covering both name
  forms — name mode: permitted dNSName = the configured name, excluded
  iPAddress 0.0.0.0/0 and ::/0; IP mode: permitted iPAddress = the
  configured address/32, excluded ::/0, permitted dNSName `invalid` (RFC
  6761) only — `pathLen=0`, 30-day validity; in IP mode the leaf has an
  empty subject and a critical SAN (RFC 5280 §4.2.1.6; no hostname-like CN
  for OpenSSL to check against the dNSName constraint; S-R4-2, S-R5-2); the CA key exists only in
  mkcert's memory and is never serialized. A `--test-negative` option
  issues, before the key is dropped, a leaf for another name for the
  acceptance test (F-N12). Leaf: SAN from config, EKU serverAuth, KU
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
- Acceptance (T-N10): `tests/tools/test_mkcert.py` with a fixture per
  property (critical NameConstraints for both name forms, a negative leaf
  in the other name form for each mode, an IP-mode positive leaf verified
  by OpenSSL, `pathLen=0`,
  validity, no key file written, leaf EKU/KU/CA:false), manifest key
  `MKCERT-FIXTURES`, a selftest case under `pins`.
- Files: tools/mksecrets, tools/mkcert (new), tests/tools/test_mkcert.py
  (new), crates/config, config/gateway.toml, tools/package, Makefile.

## Testing strategy

- Per slice: unit tests, the slice's Kani harnesses (each alone first, under
  the proof lock and a 40 GB cap), selftest cases, `make test` when run.py or
  a crate it reads changes, the slice's integration cases.
- Gate enrolment (T16): `tls-wire`, `tls-core`, `http-wire` join
  `host_crates`, lint, `kani_crates` (tls-wire, http-wire) and
  `bolero_targets` (tls-wire, http-wire); `tls` joins the PD, lint-pds and
  ct-shape "no Verus symbols" lists; check-pins P9/P10/P11 crate lists gain
  `tls-core`, `pds/tls` and `key-core` (S9); P11 gains a `tls-core` name
  set (`finished`, `verify_data`) anchored on the file that verifies
  Finished, as `TAG_ANCHOR` does for tpm2, with a fixture per name (T-N1);
  manifest keys: new UNIT-TLS-WIRE, UNIT-TLS-CORE, UNIT-HTTP-WIRE,
  KANI-TLS-WIRE, KANI-HTTP-WIRE, MKCERT-FIXTURES; changed KANI-WIRE/
  INGRESS-CORE/INNER-CORE, UNIT-WIRE/INGRESS-CORE/INNER-CORE/KEY-CORE/
  SECRET-BLOB/AUDIT-EVENT/CONFIG/MKSECRETS, LINT-CRATES, LINT-PDS,
  BOLERO-TARGETS 4 → 6, CHECK-PINS-RULES/FIXTURES, MIR-CRATES,
  INTEGRATION-CASES, UNIT-TESTS (T-N12).
- Kani bounds (T15): `parse_tcp` over a ≤ 64-byte symbolic payload;
  `tls_egress` and inner branches over ≤ 64-byte packets; `tls-wire` record
  header and the extension walker over ≤ 96-byte messages; the DER encoder
  over symbolic r, s; `http-wire` head over ≤ 96 bytes and ≤ 4 headers;
  unwind stated per harness. Each harness has a `kani::cover!` on an
  accepting path (the crates/wire/src/proofs.rs pattern); a ClientHello
  cannot be accepted within 96 bytes (1216-byte key share), so the
  ClientHello accept side is covered by bolero and unit tests only, and its
  harness covers the extension walker accepting other extensions (T-N9). All new crates (as stubs), all dependencies and
  the `tls` PD land in slice 1 so the Kani cache keys (Cargo.toml/Cargo.lock)
  change once.
- Integration (boot group `https`, netns): outside tap with curl/OpenSSL
  clients (several source IPs where a case needs them); inside tap with a
  raw-socket backend that logs each connection's peer and raw bytes and
  answers fixed or echo responses (T10). `ip_forward=0` asserted. Preflight
  fails unless `openssl list -tls-groups` has X25519MLKEM768 and curl links
  OpenSSL 3.5 (T21). A deliberate timing gate (R53, not a wait): run.py
  takes curl's `time_appconnect − time_connect` for case 1 and fails with
  "probe margin exceeded" above 1/3 of the Rust handshake timeout (T-R3-8), so an eroded margin on
  another host is diagnosed, not flaky (T-N14). curl runs with `-H
  'Expect:'` where a body is large (S-N8). Cases:
  1. GET returns the backend body byte for byte; curl verifies the chain and
     hostname; the negotiated group is X25519MLKEM768; a wrong CA or name
     fails curl (verification is on).
  2. The backend log shows exactly `rewrite`'s bytes (hop-by-hop gone,
     X-Forwarded-For = client address, `Connection: close`) from the inside
     IP; POST bodies of 0, 1 and `MAX_BODY` bytes arrive exactly;
     `MAX_BODY` + 1 → 413 at head time.
  3. `-groups X25519` → handshake_failure, `TLS_REFUSED_BASE + NoPqGroup` (L14).
  4. TLS 1.2-only → protocol_version.
  5. Smuggling and header cases (TE+CL, duplicate CL, obs-fold,
     `Connection: content-length`, underscore name, spoofed `Forwarded`) →
     the stated status; after each, a valid request is sent and the backend
     log grows by exactly that one connection (barrier, T10).
  6. Head > 8 KiB → 431.
  7. Residue cases (C8, boot `https-residue`) and the scalar count (below).
  8. TLS-only key failure (C11): HTTPS refused, VPN handshake completes; the
     rejected scalar occurs 0 times in guest RAM while `gateway_private`
     occurs (the control: `key` stays Ready for `hs`) (S-N3, T-R3-7).
  9. HTTPS SYN flood (spoofed sources), run last in its boot: the flood is
     sized so the `TCP_LIMITED_BASE + syn_global` total crosses a printed
     point (≥ 64 refusals) and that line is awaited first (T-R3-1), then a WireGuard
     handshake and transport still work. This is a positive availability
     check without its own red-proof: the controls it relies on (SYN
     buckets, `TLS_TX_SHARE`) are red-proved by `ingress-core` unit cases
     (S4, T11, T-N5).
  10. Per-source cap with free slots: two connections from source A held,
      a third from A refused (RST), one from B accepted (allow pair). Slot
      recycling (F4, T-N6, T-R3-4): seven connections held in response
      streaming (the backend holds; idle timeout and lifetime from the Rust
      source); the eighth slot runs nine full requests whose close the server
      initiates (backend FIN → close_notify → abort), each accepted, the
      backend sending one response byte to each held connection between
      cycles so none reaches its idle timeout (T-R4-2); then
      the seven are still alive (the backend finishes and the clients
      receive their responses). Red-proof: without the abort (TIME-WAIT
      kept) a cycle fails. With eight held from four sources, a ninth from a
      fifth source gets RST.
  11. Slowloris, first in the `https-residue` boot so no earlier case raises
      its code: one byte at intervals shorter than the timeout until past it
      → client EOF/RST, bounded from above only; the `TLS_TIMEOUT_BASE +
      Handshake` line with `total=1` (T12, T-N2, T-R3-1).
  12. In its own boot `https-contention` (no probe canary; T-R3-5): first
      the no-contention `KeyWaitHighWater` baseline; then a ClientHello flood
      (a replayed OpenSSL ClientHello captured on the tap; generator and
      sources — four × two connections — in run.py) while repeated WireGuard
      initiations (wg.py) run until the high-water exceeds the baseline by at
      least one `tls` period, bounded by a retry count (the overlap
      precondition); then the high-water stays ≤ `HS_KEY_WAIT_MAX_NS` and a
      handshake completes. Needle: "KeyWaitHighWater above
      HS_KEY_WAIT_MAX_NS". Red-proof: a scratch tree lowers `tls`'s budget
      and `TLS_BUDGET_NS` with the compile-time assert removed, to a value
      where `(ceil(SIGN_COST_NS / budget) + 1) × PERIOD_NS` is several times
      `HS_KEY_WAIT_MAX_NS`, so the overlap precondition alone exceeds the
      bound (S1, S-N1, T-N7, T-R4-3). The boot reuses the cookie boots'
      Rosenpass/PSK installation so `hs` reaches `key` (L8; T-R4-4).
  13. Backend RST mid-response (`SO_LINGER` 0) → `s_client -msg` shows no
      close_notify alert and the read fails with ECONNRESET, and the sniffer
      sees the server's RST (T-R3-9); a client FIN before the response ends → the backend sees
      its connection aborted (T-N8, with conn-core unit tests for the 2 s
      wait).
  14. The full VPN suite unchanged.
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
  the per-source cap; and (T-N11) a handshake/head timer reset by activity,
  the conn-core alert/timeout wipes, the truncation rule, `tls` RNDR failure
  → no handshake (L9), the `TLS_TX_SHARE` tier, minimal DER INTEGERs, 413
  at head time, the no-key-share refusal reason, the RFC 6979 candidate
  cap, the `tls_egress` SYN refusal, the rejected-scalar wipe (D5), the
  early_data skip after `Connected` and without its cap (T-R3-6), no wipe
  after the RST retries are exhausted (T-R6-2), the `tls`
  stack scrub after `exchange` (S-R3-2), the libcrux-p256 lock pin
  (T-R3-10).
- Keylog fixture (T-N13): captured against `openssl s_server -groups
  X25519MLKEM768 -ciphersuites TLS_CHACHA20_POLY1305_SHA256` (independent of
  our server, available before slice 3), with the capture script committed
  beside the fixture.
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
  (impersonation for that period); never `key`'s secrets. Past connections'
  plaintext is wiped from `tls`-owned memory (C8); the backend link and its
  buffers (`tln`/`ntl`, `inner`, `eth_in`) hold cleartext by design.
- **RM6-2** smoltcp is unverified code in a tainted PD; same worst case. A
  panic in `tls` or smoltcp ends HTTPS until reboot (no restart, SC17).
- **RM6-3** dev CA only (VE9).
- **RM6-4** eight slow-but-valid clients from four sources can hold every
  slot until the 120 s lifetime.
- **RM6-5** libcrux P-256 and ML-KEM are outside the ct gate (as libcrux
  elsewhere, R-M1 class).
- **RM6-6** no HRR: a client that supports X25519MLKEM768 but sends no key
  share for it is refused rather than asked again.
- **RM6-7** HTTPS under spoofed floods: smoltcp has no SYN cookies, so
  spoofed SYNs occupy listeners until their 5 s timeout; spoofed ACK/data
  segments exhaust the global TCP data bucket and stall established HTTPS
  connections; smoltcp's ISNs come from PCG32 and are predictable from
  observed ones, enabling blind spoofed handshakes (filling slots past the
  per-source cap) and blind RST injection (S-N6, F-N11). TLS keeps content
  and X-Forwarded-For authentic. Ingress buckets keep the floods from
  reaching the VPN and `key`.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC6 | HTTPS proxy | closed by M6 |
| SC34 | HelloRetryRequest (RM6-6) | unscheduled |
| SC35 | Verus proofs for `parse_tcp`, `tls-wire`, `http-wire` (Kani in M6) | unscheduled (SC29 Vest) |
| SC36 | HTTP keep-alive, HTTP/2, multiple backends, TLS session tickets | unscheduled |
| SC37 | WebPKI certificate issuance and renewal | ops (VE9) |
| SC38 | SYN cookies, RFC 6528 ISNs (a smoltcp patch or fork), client puzzles for HTTPS (RM6-7) | unscheduled |

## User operation scenarios

1. Operator: puts the backend in config, runs `mksecrets` (blob v3, fresh
   P-256 key, dev CA and leaf, config) and `make package` → envelopes sealed
   as in M5 (the 30-day dev leaf means re-issue, re-package and re-seal
   within 30 days; S-N7); boots; `curl --cacert devca.pem https://gw/` returns the
   backend's page.
2. A browser without X25519MLKEM768 connects → handshake failure, audit
   `TLS_REFUSED_BASE + NoPqGroup`.
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
| Audit events | `tls`, `ingress`, `hs` | audit PD reads the kind code (a base + value for coalesced kinds) and `a` (running total, or the value for high-water events) → name table line on the UART; run.py parses `audit: src=<pd> <Name> total=N` / `us=N` / `bytes=N` (F-N2) |
| Config outputs | config build.rs | `HTTPS_PORT: u16` (ingress, tls); `TLS_PORTS: (u16, u16)` start and count (inner, tls); `BACKEND: ([u8; 4], u16)` (inner, tls); `TLS_CERT: &[u8]` (tls); `TLS_PUBLIC: [u8; 65]` uncompressed point (key) (F-N13) |

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | System, laws, budget | locked |
| C2 | ingress TCP admission and tli egress | locked |
| C3 | tls PD TCP via smoltcp | locked |
| C4 | inner backend routing | locked |
| C5 | key TLS signing oracle | locked |
| C6 | tls-wire parsing | locked |
| C7 | tls-core handshake, key schedule, records | locked |
| C8 | secrets and plaintext lifecycle in tls | locked |
| C9 | http-wire head parsing and rewrite | locked |
| C10 | proxy flow, limits, close, timeouts | locked |
| C11 | packaging, config, certificate | locked |

## Implementation Checklist

Authored at Phase 2 start (Step 2-1); per slice. No CI config exists, so
the local `make check` is the only gate set (no parity gap). Reusable code
(must be reused, not reimplemented): `pdkit` (`Audit`, `send`, `take`,
`release`, `recv` — ring I/O and audit for every PD), `ring`/`layout`
(ring triples and channel ids), `wire` (Ethernet/IPv4 parse, checksums,
`parse_frame_ip`, `emit`), `ingress-core` `Buckets`/`rp_tx_allowed`
pattern, `audit-event` coalescing (`FRAME_DROPPED_BASE` pattern),
`cpu::StackProbe`, `tpm2::boot::scrub_session_stack` (pattern for the
`tls-core` scrub), `secret-blob` parse/write, `config` build.rs/validate.

### Slice 1 (C1, C2, C3 echo)

- Cargo: workspace members `crates/tls-wire`, `crates/tls-core`,
  `crates/http-wire` (no_std stubs with one test each), `crates/pds/tls`;
  dependencies added now so Cargo.lock changes once: smoltcp `=0.14.0`
  (pds/tls; `default-features = false`, `medium-ip`, `proto-ipv4`,
  `socket-tcp`), libcrux-hkdf `=0.0.9` and libcrux-ml-kem `=0.0.11` with
  `mlkem768` (tls-core), libcrux-curve25519, libcrux-chacha20poly1305,
  libcrux-sha2, libcrux-hmac (tls-core, existing versions), libcrux-p256
  (key-core, existing version), `rfc6979` dev-dependency (key-core).
- system/secureos.system: PD `tls` (priority 100, budget 500/10000, stack
  0x20000), rings `itl`/`tli`/`tln`/`ntl`, `audit_tls`, channels
  ingress↔tls, tls↔inner, timer→tls, tls→key (PPC), tls→audit.
- policy/laws.toml: PD row (role `untrusted_input`), MRs, channels, budget
  row, cap 0.95.
- crates/layout: `tls` module, channel ids for ingress, inner, timer,
  audit, key, and tests checking them against the system file.
- crates/pds/timer `PEERS`; crates/pds/audit source list.
- crates/wire: `parse_tcp(&Ip4Packet)`, `TcpHeader`, new `DropReason`
  variants in `ALL`; Kani harnesses with `kani::cover!`; unit allow/deny
  pairs; bolero seeds for TCP.
- crates/ingress-core: `respond` fallback to `parse_frame_ip` on `NotUdp`,
  TCP branch rules, SYN/data buckets via const-generic `Buckets`,
  `tls_egress`, `TLS_TX_SHARE` with its compile-time assert; Kani harnesses;
  unit tests.
- crates/audit-event: `TCP_LIMITED_BASE` kinds (and the `tls` kinds'
  bases reserved); run.py and the audit PD name table.
- crates/pds/ingress: `itl`/`tli` wiring.
- crates/pds/inner: maps `tln`/`ntl` (forwarding arrives in slice 4).
- crates/pds/tls: smoltcp outside interface, 8 listeners on 443, echo mode;
  `StackHighWater`.
- Makefile: `pds`, `host_crates`, lint lists, `kani_crates`
  (tls-wire, http-wire later), `bolero_targets` later.
- tests/integration/run.py: `DROP_REASONS`/`frame_for` (NotUdp fixture to
  protocol 47), boot group `https` with the slice-1 echo case.
- tools/check-selftest: the four C1 `laws` cases; `CASES_FOR_GATE`.
- tests/manifest.txt: every changed count.

### Slice 2 (C5, C11)

- crates/secret-blob: v3 layout (`tls_private` after `boot_seed`), `FIXED`
  80 → 112, `MAX_PEERS` 124 → 123, v2 → `BadVersion`; the Python mirror test
  asserts Rust body length = tools/package `_key_body` for several peer
  counts.
- crates/tpm2 envelope `KEY_MAX_PEERS` 110 → 109; tools/package
  `_key_body` 80 → 112, `VERSION` 3.
- crates/key-core: `Caller { Hs, Tls }`, exhaustive `allows()`, per-caller
  buckets and boot seeds (`BLAKE2s(seed ‖ caller tag)`, `hs` included),
  `LABEL_TLS_SIGN` = 4, `MAX_WORDS` 8, CertificateVerify content built in
  `key`, RFC 6979 HMAC-DRBG with k' from RNDR, ≤ 8 candidates,
  `libcrux_p256::ecdsa_sign_p256_sha2`, Secret types, `TlsKeyError`
  (17/18) separate from `BootError`, the three compile-time invariants
  (`SIGN_COST_NS` provisional until measured in slice 3), all C5 unit tests
  (A.2.5, differential vs `rfc6979` incl. hash ≥ n, rejection branch, cap
  via seam, two k', RNDR failure, label × caller, code collisions).
- crates/pds/key: TLS check before the long-lived borrow, wipe [80:112] on
  failure, stack scrub after the check and after each signature, `CH_TLS`
  caller mapping, `MAX_WORDS` zeroing.
- crates/hs-core: invariants per caller; crates/pds/hs:
  `KeyWaitHighWater` value event (audit-event kind + audit PD name).
- crates/layout: `TLS_BUDGET_NS`, `PERIOD_NS`, checked against the system
  file.
- tools/check-pins: libcrux-p256 lock-entry pin rule with a fixture.
- crates/config: `tls_ports`, backend, `tls_cert`, `tls_public`; build.rs
  emits `TLS_PORTS`, `BACKEND`, `TLS_CERT`, `TLS_PUBLIC` and checks the
  26-byte SPKI prefix + `tls_public` inside the cert; validation of the
  backend (inside prefix, neighbour) and `TLS_PORTS` bounds, with tests.
- tools/mksecrets: P-256 scalar, blob v3, `tls.pub`, runs tools/mkcert,
  config output; a `--tls-scalar-from-other` style option for the
  TLS-only mismatch package (case 8).
- tools/mkcert (new, Python `cryptography`): dev CA per C11 (both name
  forms, pathLen 0, 30 days, key never serialized, `--test-negative`),
  leaf (EKU serverAuth, KU digitalSignature, CA:false; IP mode empty
  subject + critical SAN); tests/tools/test_mkcert.py with MKCERT-FIXTURES.
- run.py: `KEY_CALLERS`, codes 17/18, blob offsets, the packaged boots use
  v3 blobs; tests/manifest.txt; check-selftest cases for the new controls.

### Slice 3a (C6, C7 host side)

- crates/tls-wire: records (types, legacy version incl. first-record
  0x0301, length limits, CCS rules), protected-record inner type and
  padding (§5.4), handshake framing (span/coalesce, ClientHello and client
  Finished at record boundaries, ≤ 8 KiB), `client_hello` with every C6
  extension rule (incl. duplicate key_share groups, supported-but-no-share
  reason, pre_shared_key last + modes, early_data preconditions), the
  serializers (ServerHello, EncryptedExtensions, Certificate,
  CertificateVerify with DER `ECDSA-Sig-Value`, Finished, alerts); Kani
  harnesses within the stated bounds with `kani::cover!`; bolero target
  with seed ClientHellos from OpenSSL and curl (capture script committed);
  allow/deny unit pairs at every bound.
- crates/tls-core: `HybridSecret::exchange` (ML-KEM-768 ek check,
  encapsulation, X25519 with a fresh ephemeral, zero check) through a
  non-generic `exchange_with_randomness` taking randomness as bytes;
  wiping Secret types for the ephemeral, the randomness and both component
  secrets; `scrub_session_stack` (`#[inline(never)]`) and
  `SCRUB_DEPTH_EXCHANGE`; key schedule with private `schedule_from_ikm`
  (`#[cfg(test)]` reach); record protection (ChaCha20-Poly1305, §5.3
  nonce, sequence limit); state machine (CCS, KeyUpdate rules, early_data
  skip with its preconditions, Finished `ct_eq`); `conn` module with an
  injected clock (timeouts, per-source cap, lifetime, close sequencing and
  the RST retry/wipe decision, `Slot::is_zeroized()`); hedged RNG from a
  per-caller seed, RNDR and CNTPCT (the `pq` pattern) behind a trait.
- Tests: RFC 8448 §3 secrets/Finished; the OpenSSL `s_server` keylog
  fixture (Python capture script, committed) for keys/IVs/records and
  `traffic upd`; the host test client (libcrux on the host) driving every
  C7 refusal path and early_data case; `compile_fail` doctests for
  `HybridSecret`; conn unit tests.
- check-pins: L14 constructor rule and the code-point spelling tripwire
  with fixtures; P9/P10/P11 crate lists and the `tls-core` P11 name set
  anchored on the Finished file.
- Makefile: `kani_crates` += tls-wire (and http-wire in slice 4),
  `bolero_targets` += tls-wire; manifest keys.

### Slice 3b (C7, C8 in the PD; probes)

- crates/pds/tls: TLS over the smoltcp listeners (echo mode removed; the
  HTTP head is a seam until slice 4 — a connected client gets a fixed
  response), `Signer` over key's TlsSign PPC (`MAX_WORDS` zeroing), the
  hedged RNG over key's per-caller boot seed + RNDR + CNTPCT, `tls`'s
  `KEY_UNAVAILABLE` halt with `KeyUnavailable{code}` (D5), the C8 close
  order (seal, wipe, transmit; abort, poll, RST observed by the own
  `Device`, remove, wipe storage, re-create; retry ≤ 8 via
  `tls-core::conn`), `tls_core::scrub_session_stack` after `exchange` and
  after TlsSign, audit kinds at their reserved bases.
- run.py: `tls` in `KEY_CALLERS`; `TlsKeyError` codes; the `https` boot
  with OpenSSL/curl handshakes (cases 1, 3, 4 of the strategy against the
  fixed response), the `https-residue` boot (C8 cases 1–3, case 11), case 8
  (TLS-only key failure), the scalar count, the probe canary.
- tools/ct-harness: tls-core with `=`-pinned libcrux crates; residue case
  for `exchange_with_randomness` + scrub (SCRUB_DEPTH_EXCHANGE adjudicated);
  tools/ct-shape identity-only root class with fixtures and a selftest.
- Probes (C10/D3): CPU time of the handshake at 0.05 over 20 runs and 8
  concurrent; `SIGN_COST_NS` measured (max of 20 × 2), P17 and the
  constant moved together; the stop rule if the per-call wait bound fails.

## Re-plan R1 (2026-10-24, after the slice-3b probe; D3 stop rule; revised after its review)

**Trigger.** The probe measured TlsSignHighWater 0.64–1.72 s. The sign runs
in the passive `key` on `tls`'s 0.05 budget, ≈ 35–85 ms of CPU under TCG,
so `hs` can wait that long behind it. C5's per-call bound cannot hold
within the 0.25 per-PD cap, and widening `HS_KEY_WAIT_MAX_NS` is the
workaround D3 forbids. Findings of R1's review are cited R1-F*/S*/T*.

**Decision.** The TLS signing key leaves `key` for its own key PD,
`tlskey`. Like `key` and `pqkey` it is **passive**, so every signature
runs on `tls`'s scheduling context. The consequences:
- HTTPS can never use more CPU than `tls`'s 0.05, and L13 and its 0.95
  basis are unchanged (R1-S F1, F F1, T T7/T8).
- `hs` and `tls` share no key PD, so `hs` never waits on a signature.
- Signing latency and concurrent-handshake capacity are `tls`'s own
  availability concern (RM6-8).

This keeps M5's one-sealed-secret-per-key-PD rule, and `key` holds no TLS
secret. Rejected:
- `tlskey` non-passive: it puts 0.2 of CPU driven by tainted input
  outside the cap, at priority 135 over the VPN.
- Handing the scalar over a PPC from `key`: a new key↔key secret path.
- The scalar in `pqkey`: the interference moves onto `pq`.
- `key` non-passive: it breaks L13.

### Superseded text (R1-F F7)

Where they conflict, this section replaces the following, which now read
as amended here:
- the Objective's "only in the passive `key` oracle" (now `tlskey`);
- D3's changed-code list (plus the M5 chain below);
- D5 (now: `tlskey` Unavailable → `tls` halts at init);
- the L2 and L13 rows of the law amendments;
- C1's tls→key PPC, member set and acceptance (now tls→tlskey);
- C5 (→ C12);
- C11's blob v3 (→ two blobs);
- testing cases 7, 8 and 12;
- slice 2's key items;
- RM6-7's "and `key`" (now `tlskey`);
- the considerations' headroom sentence.

### C12 — `tlskey` PD (Critical tier)

- **PD.** Role `key`, passive, priority 135 (above `tls` 100, below `tpm`
  145), budget 2000/10000 (a passive PD's budget pays only for its `init`,
  the unseal flow; stated like `key`'s and `pqkey`'s, R1-S N1), stack
  0x20000 (`key`'s P-256 + scrub depth). Maps only
  `tls_secrets`: a 4096-byte prefill MR, `kind="secrets" owner="tlskey"`.
  Channels:
  - a callee PPC of `tls` (`pp={tls=true,tlskey=false}`, `notify={tls=false}`);
  - a caller PPC of `tpm`, as `key`/`pqkey` have.
- **Oracle `tlskey-core`.**
  - `TlsSign`: C5's content building, RFC 6979 hedged nonce, ≤ 8
    candidates, Secret types and stack scrub, moved from key-core
    unchanged in substance.
  - `BootSeed`.
  - The `allows()` table refuses every other label.
  - Codes live in their own range, disjoint from `key`'s (R1-S F6), with a
    collision test.
- **TLS blob** (`secret-blob::tls`, R1-S F2, F F2/F10, T T9). Layout:
  - magic "SOSTLSK1" (8);
  - version u32 = 1;
  - reserved u32 = 0;
  - `tls_private[32]` at 16;
  - `boot_seed[32]` at 48;
  - BLAKE2s checksum[32] over [0, 80) at 80;
  - zero padding to 4096.

  mksecrets draws `boot_seed` independently of `key`'s. The per-boot seed
  is `BLAKE2s(boot_seed ‖ RNDR ‖ CNTPCT)`. Deriving anything from the
  scalar is forbidden. `hs`'s seed reverts to M5's derivation, since `key`
  is single-caller again.
- **Boot.**
  - Unseal `Kind::Tls`, parse the blob, check that the scalar is valid and
    that its point equals `config::TLS_PUBLIC`.
  - Any failure → `Unavailable{code}` with the plaintext wiped (the M5
    rule), stack scrubbed after the check.
  - `tls`'s init calls `BootSeed`. On `ERR_UNAVAILABLE|code` it audits
    `KeyUnavailable{code}` and halts **before listening** (R1-T T12).
- **Failure layers** (R1-S F6). A malformed or missing TLS range in the
  descriptor refuses the whole boot (release defect). A bad TLS envelope,
  blob or scalar fails TLS only.
- **Bucket.**
  - `TLS_SIGN_BURST − TLS_BOOT_CALLS ≥ SYN_GLOBAL_BURST`.
  - `TLS_SIGN_INTERVAL_NS ≤ SYN_GLOBAL_INTERVAL_NS`.
  - `SYN_GLOBAL_*` move to a new dependency-free leaf crate `limits`,
    shared by ingress-core and tlskey-core, so neither needs the other
    (R1-F F11). Not `layout`: ingress-core's 23 Kani harnesses would re-run
    on every layout edit (R2-F N6). `limits` is `#![no_std]`, in
    `host_crates`, with a unit test pinning both values against
    ingress-core's source-bucket asserts (R3-F R3-2).
- **Retired with C5's interference bound.** `SIGN_COST_NS`,
  `HS_KEY_WAIT_MAX_NS`'s compile-time use, P17 and `TLS_BUDGET_NS` in
  `layout`. Their purpose was the per-call wait bound, which is now
  structural.
- **Observability kept.** `TlsSignHighWater` (tls) and `KeyWaitHighWater`
  (hs).

### `key` reverts

- `Caller { Hs }`; `MAX_WORDS` 4.
- Blob v2 (FIXED 80, MAX_PEERS 124, envelope KEY_MAX_PEERS 110, tools/package
  `_key_body` 80, VERSION 2).
- TLS validation, codes 17/18, TlsSign and the per-caller buckets and seeds
  are removed from key-core and pds/key.
- Evidence of removal: pd-key.elf no longer links the p256 sign path
  (ct-shape symbols).

### Third envelope through M5's chain

- **Descriptor v2** (R1-S F4, F F9, T T5/T6). 80 bytes, little-endian:
  - magic "SOSBOOT1";
  - version u32 = 2;
  - count u32 = 3;
  - `image_len` u64;
  - three (offset u64, len u64) pairs at 24, 40 and 56;
  - reserved u64 = 0 at 72.

  Changes this brings:
  - U-Boot hashes `0x50` bytes.
  - Load slots are 0x6fc00000, 0x6fd00000 and 0x6fe00000, each
    `ENVELOPE_ROOM` 1 MiB, before the descriptor at 0x6ff00000.
  - boot.cmd and tools/measure.py both check:
    - version 2 and count 3;
    - every 32-bit field;
    - each range inside the image and within its slot;
    - **all three pairs** disjoint.
  - The zero placeholder for each range is a host-side check only
    (measure.check_placeholder in package and release; R2-F N5).
  - Version 1 is refused.
- **`tpm2::envelope::Kind::Tls`.** `Key` and `Tls` regions are both 4096
  bytes; the kind in the AAD and the distinct blob magic separate them.
- **tpm PD and gate** (R1-S F3, F F3/F4, T T3/T4).
  - `tpm2-wire` `CLIENTS` = 3.
  - The one-flow rule moves into the `Gate`: a Fresh client gets Busy
    while **any** other client is Unsealing (R2-F N1). Busy is decided
    **after** every validity and ownership refusal (Capped, Finished,
    Malformed, NotAllowed, NotOwned, Hierarchy), so NotOwned stays
    reachable for a Fresh attacker. It comes **before** `once()` and the
    state change, and has no side effects. The PD maps it to `RSP_BUSY`
    (retried by `tpm2::boot`), never `RSP_REFUSED`.
  - `layout::tpm::CH_TLSKEY` with a `client()` arm.
  - `tpm2::boot::BUSY_TIMEOUT_NS` re-derived for waiting behind two flows,
    from the three key PDs' init budgets (R1-S N1).
  - The cap comes once all three clients are Done or Failed.
  - Module docs updated.
  - RM5-5's pre-cap window grows by one flow's duration; no new unseal
    path (only key-role PDs reach `tpm`).
- **Packaging, release.**
  - tools/package: `--tls-secrets`; `KINDS` in descriptor range order;
    `SEAL_KINDS["tls_secrets"] = ("tls", 3)`; outputs gain
    `tls_secrets.env`.
  - Makefile: `TLS_SECRETS`, a placeholder rule, and image/package
    dependencies.
  - mksecrets writes `tls-secrets.bin` and offers `seal`/`check-envelope
    --kind tls`; `--tls-mismatch-blob` emits a TLS blob.
  - release.py `verify --kind tls`.
  - `check_placeholder` covers range 2. The manifest has no per-envelope
    field (R1-F F7).

### Laws

- **New rule (R1-T T2, R2-T N1, R2-F N2), reported under L2.** A key-role
  PD has **at most one** pp caller (shared means two or more; existing
  fixtures with zero callers stay valid),
  counted as channels where the peer end is pp=true and the key end
  pp=false, excluding its PPC to `tpm`. Together with the existing "no PD
  calls two key PDs", this makes "no key PD is shared" a checked property.
  It replaces case 12's measured bound.
- **Unchanged.** L13: every key PD stays passive. L1's key-role exemption
  is unchanged.

### Gate enrolment (R1-T T1, S F5, F F5)

- Makefile `pds`, `host_crates` (tlskey-core), lint and lint-pds.
- ct-shape:
  - `ROOTS += ("pd-tlskey.elf", OPEN_ROOT)` with its baseline entries;
  - pd-tlskey in the "no Verus symbols" list;
  - key's baseline entries refreshed after the TLS code leaves.
- check-pins P9/P10/P11 crate lists += tlskey-core, pds/tlskey; the P11
  anchor for the RFC 6979 HMAC moves.
- The ct-harness residue covers a `Kind::Tls` open.
- Manifest keys (R2-T N6): UNIT-TLSKEY-CORE and UNIT-LIMITS (new);
  LINT-CRATES, LINT-PDS, REPRO-ARTIFACTS; CT-SHAPE-*, CHECK-PINS-RULES
  (19 → 18) and -FIXTURES, MEASURE-, PACKAGE-, RELEASE-, RESIDUE-CASES;
  UNIT-LAWS, UNIT-FIXTURES-TEST, KANI-TPM2-WIRE, UNIT-TPM2-WIRE,
  UNIT-SWTPM-INTEROP, UNIT-TPM2, UNIT-KEY-CORE, UNIT-SECRET-BLOB,
  UNIT-MKSECRETS, UNIT-LAYOUT, UNIT-INGRESS-CORE, UNIT-CONFIG,
  UNIT-RELEASE-TOOL, UNIT-TESTS, INTEGRATION-CASES.

### Testing (R1-T T2–T13, F F4/F6/F12)

- **Laws.** Fixtures `key_shared_by_two_callers_deny` and
  `key_single_caller_allow`; `key_non_passive_deny` kept. Selftest
  `laws-hs-tls-share-key` moves tls's channel to `key` and deletes `tlskey`
  with its MR and entries, so only the new rule can fire. Its needle names
  that rule.
- **tpm2-wire.**
  - Owner and attacker symbolic and distinct, `< CLIENTS`.
  - New harness `the_cap_is_withheld_until_every_client_finishes`.
  - New harness for the busy rule over three clients, asserting that Busy
    leaves `once` and `states` unchanged and that the client's later flow
    succeeds (R2-F N1, R2-T N4); `a_flushed_handle_number_is_usable_by_the_other_client`
    changes so the owner finishes before the other client starts, and
    its "no longer A's" check becomes a Fresh third client refused
    NotOwned on the reused handle (a Done A gets Finished before any
    ownership lookup; R3-T R3-1); the
    cross-client deny harnesses use a **Fresh** attacker (NotOwned is
    decided before Busy), plus one that starts after the owner finished
    without flushing (R3-F R3-1).
  - A `kani::cover!` after every `assume(owner_setup…)`.
  - The fixed tests updated: `command(3, …) == UnknownClient`, the
    three-client cap, `fuzz_one`'s client loop, swtpm_interop's cap test.
  - Each changed harness runs alone under the memory guard first.
  - Selftest: restoring the two-client busy form in `gate.rs` must fail a
    unit test over all six ordered client pairs.
- **Descriptor.**
  - test_measure: an overlap deny and an adjacent allow for each pair
    (0-1, 0-2, 1-2); out-of-image, wrap and zero-placeholder denies for
    range 2.
  - An 80-byte version-1 descriptor and a v2 with count 2 → "header"; a
    64-byte descriptor → length; v2 count 3 → allow.
  - Changing each of o2 and l2 (valid moves) changes `expected_pcr8` and
    the measure-variant PCR; a non-zero reserved word is refused by both
    adjudicators (deny fixture; R2-T N7).
  - run.py's measured-boot cases use three envelopes and include
    on-device refusals for the 0-2 overlap, the 1-2 overlap and a range-2
    wrap, batched in one measure-variant boot loop (R2-T N3).
  - One selftest per dropped boot.cmd line (each pair check, range 2's
    wrap check, the version compare), each with a failure-only needle
    naming its case.
- **Envelopes.**
  - Unit: a real Key envelope parsed as Tls → BadKind, and the reverse.
  - Package fixtures refuse swapped secrets and tls_secrets envelopes in
    both directions.
  - Case 8: PCR 8 reads as capped when only `tlskey` fails (R1-T T11).
- **tlskey-core and the TLS blob.**
  - The blob: allow; bad magic; versions 0 and 2; checksum flip; non-zero
    padding; an offsets pin; the Python body-length mirror.
  - Boot: one test per code (unseal, blob, scalar zero or ≥ n, point
    mismatch), plaintext wiped each time.
  - `allows()` refusals; a bucket refusal that spends no sign; RNDR
    failure → ERR_CRYPTO.
  - With RNDR and CNTPCT fixed behind the `Hw` seam (R2-T N2): the same
    `boot_seed` gives the same seed, a different `boot_seed` a different
    one, and a different scalar with the same `boot_seed` the **same**
    seed (the scalar is not an input); a selftest feeding the scalar into
    the hash must fail it.
- **Integration.**
  - Case 8: `tls` halts at init before listening.
  - The scalar count asserts one occurrence in guest RAM; `key`'s blob
    holds no scalar by construction.
  - Case 12 is a positive availability check: during a ClientHello flood a
    WireGuard handshake completes. `KeyWaitHighWater` is recorded, not
    asserted (drivers at 150 preempt `key`, so its level moves with load;
    R2-T N5, R2-F N3). The red-proved control is the single-caller law and
    `laws-hs-tls-share-key`.
  - Boot 6 (bad `key` blob): `tls` does not audit KeyUnavailable and
    reaches ready.
  - The probe keeps its gate (slowest handshake ≤ 1/3 of the timeout; else
    D3) and records TlsSignHighWater.
- **Migration** (R1-T T10, F F6). Each moved test keeps its assertion; the
  manifest delta is per key, and every removal is listed with its reason
  in the deviation log.
  - Retargeted to tlskey-core: `c5-tls-static-dh`, `c5-k-prime`,
    `c5-nonce-cap`, `c5-cv-content`, `c5-syn-burst`, `c5-syn-interval`,
    `c5-d5-codes`, `tls-scalar-scrub`, and key-core's TLS unit tests
    (A.2.5, the differential, cap, rejection, k').
  - Removed (subject gone): `c5-caller-bucket`, `c5-sign-wait`,
    `c5-seed-tag`, `c5-tls-boot-fail`, `c5-tls-wipe`, `c5-lock-pin`, and
    P17's fixtures.
  - Re-anchored: `key-wipe`, `measure-wrap`, `tls-key-halt`. The last
    targets tls's init halt; the sign-path halt gets a tls-core unit test
    mapping a `TlsSign` `ERR_UNAVAILABLE` to its halt reason (R2-T N8).
  - The key/tlskey code-range disjointness is checked by run.py's
    code-table mirror (no new dependency edge; R2-T N8).
  - The sealed-boot cap check also waits for `tls` ready (it is ready only
    after `tlskey`'s init returned BootSeed; R2-F N4).
  - New: `tlskey-wipe` on the case-8 boot.

### Residual added

- **RM6-8** Under TCG a signature takes ≈ 0.6–1.7 s of `tls`'s wall time,
  so about `HANDSHAKE_TIMEOUT / sign time` (≈ 5) handshakes can be in
  flight before some time out, and handshakes are sequential through
  `tls`. Adversarially, one valid ClientHello (a replayed key share will
  do) per sign time denies HTTPS under TCG, bounded only by the per-source
  cap (RM6-4), because `tlskey`'s bucket admits every forwarded handshake
  (R1-S N2). This affects HTTPS availability only (VE10); the VPN is
  unaffected (`tls`'s 0.05 budget bounds it); on hardware a P-256
  signature is well under a millisecond. If it binds in the slice-5 probe,
  D3 applies: re-split inside 0.95 (e.g. pq's measured 0.029 of its 0.05),
  never a budget outside the cap.

### Go/No-Go additions

| ID | Subject | Status |
|---|---|---|
| C12 | tlskey PD, its blob and envelope; key reverted; third envelope through M5's chain; the single-caller law | locked |

### Slice 4 rest (C4, C10 in the PD)

- Merge wip/m6-inner (C4: inner-core routing both directions, pds/inner
  `ntl`/`tln`) and wip/m6-proxy (C10 core: `tls-core::conn` proxy events
  and actions, the tls-core → http-wire edge); regenerate Cargo.lock once.
- crates/pds/tls: a second smoltcp `Interface`/`SocketSet` for the inside
  (inside IP, `ntl`/`tln`), eight backend sockets connected from
  `TLS_PORTS` round-robin on `connect`; drive `client_record`,
  `client_fin`/`client_gone`, `backend_connected`/`data`/`fin`/`rst`,
  `timers`, `to_backend`/`backend_sent`; abort and release the backend
  socket on `abort_backend` with the RST observed on `tln`; record every
  `Outcome` with its audit code (`BackendUnavailable` kind if missing).
- c8-head-wipe's mutation also removes the proxy's early head wipe (the
  head is wiped when rewritten as well as at close).
- run.py: inside tap with a raw-socket backend logging each connection's
  peer and bytes (echo for POST); cases 1 (now through the proxy), 2, 5,
  6, 13; `ip_forward=0`; the `https-residue` barriers move to the backend
  log as planned (C8); selftest cases from the C4 and C10 reports;
  manifest.

### Slice 5 (hardening, closing)

- Boot `https-flood`: case 9 (spoofed SYN flood; `TcpLimited{syn_global}`
  crosses a printed point first; VPN handshake and transport still work)
  and case 12 (ClientHello flood; a WireGuard handshake completes;
  `KeyWaitHighWater` recorded).
- Case 10 (per-source cap with free slots; slot recycling under
  server-initiated closes; ninth connection RST) and the 8-concurrent
  handshake probe from four sources (RM6-8 measured; D3 if it binds).
- Kani: the full suite after the slice-3c lock change on z1mn, the cache
  copied back to gx10; tpm2-wire's changed harnesses alone first.
- Phase 2 Step 2-4 and 2-5 (self R-check), then Phase 3 review, the final
  solo `make check`, a full selftest after it (z1mn), docs/PLAN.md M6 row.

## Re-plan R2 (2026-10-25, after code review round 1; D3 stop rule on RM6-8; revised after its review rounds 1–6)

**Trigger.** Code review round 1 (T8) made the 8-concurrent probe fail when
no handshake completes. On the round 1 tree it then failed: 8 of 8
handshakes from four sources reset at 10.4 s, the handshake timeout. The
probe had been passing vacuously, since 4209823 printed PASS on the same
8-of-8 failure. RM6-8 is "D3 if it binds", and it binds. Findings of R2's
review are cited R2-F*/S*/T*.

**Evidence** (`https flood` boot alone, gx10, no solver on the host, TCG):

| Tree | `tls` budget | 8 concurrent handshakes |
|---|---|---|
| 7ce0d18 (slice 5) | 0.05 | all 8 done at 8.19 s, within 1 ms of each other (3.48 s on 2026-10-24) |
| round 1 | 0.05 | all 8 reset at 10.4 s, together |
| round 1, data 0.15 / tls 0.10 (experiment only) | 0.10 | all 8 done at 6.43 s, together |
| round 1, egress after each serve (experiment only), run 1 | 0.05 | 7 done at 2.10–5.81 s, staggered; 1 client read timeout at 25.5 s |
| same tree, runs 2–4, per-port diagnosis | 0.05 | 24 of 24 done at 1.21–7.70 s, staggered; the stall did not recur |

**Root cause.** `Tls::pass` serves every connection, then sends:
- `ingress` on both links;
- `serve(i)` for all `MAX_CONNS`;
- `poll_egress` once.

It notifies `ingress` only in `end_pass`. A ClientHello costs the hybrid
exchange plus a `TlsSign` call. The sign alone is 0.4–1.2 s of wall time on
`tls`'s 0.05, since the passive `tlskey` runs on `tls`'s scheduling context.
So a pass that meets eight ClientHellos computes all eight flights before
any leaves. No client can send its Finished until the last flight is
computed, and the eight complete together or time out together.

This is an availability defect independent of the budget: under load the
server serves nobody instead of the earliest. Doubling the budget only
moved the cliff (6.43 s, still in lockstep). It is also the widening D3
forbids, and it would take 0.05 from the VPN's `data`.

**Decision (C13).** The budget, the L13 split and `MAX_CONNS` stay. The
pass becomes, in this order:

1. **Ingress** on both links, as today.
2. **Serve every connection with its ClientHello held back.**
   - Deferral happens at one point only: the `take_record` call in `proxy`,
     when the slot `awaits_hello` and does not hold this pass's turn.
   - Everything else in `serve(i)` still runs for every slot every pass:
     gone detection, timers (the handshake deadline counts from admission,
     conn.rs `Phase::Open{Handshake, since}`), the IDLE raise, FIN handling.
   - Records past a ClientHello (client Finished, application data) are
     never held back.
3. **Egress** on both links, then notify `ingress`/`inner` for what was
   sent: `mem::take` of the link's `sent` flag. Other connections' Finished
   replies and backend SYNs leave before the expensive step (R2-F3).
4. **The hello turn.** One eligible slot, if any, has its ClientHello
   served, then a second egress.
   - **Eligible:** `Phase::Open{Handshake}`, the session in
     `AwaitClientHello`, and a complete record buffered. Free and reset slots
     also sit in `AwaitClientHello`, hence the phase guard (R2-F6).
   - **Choice:** earliest admission, the smallest Handshake `since`, i.e.
     earliest deadline first (R2-F2). On a tie, the lowest slot index. A
     later admission cannot pass an earlier one, so a slot waits at most
     for the hellos admitted before it, which is fewer than `HS_CAP`
     (below). A re-armed slot gets a new, larger `since` through `open()`.
   - **The turn is per connection:** the holder consumes every record of
     its ClientHello in this serve, until the hello completes or is
     refused. A non-final fragment never ends the turn (R2-S3, T7).
   - **A slowloris partial** is never eligible: it holds no complete
     record.
   - **Once per pass, after the last egress:** `after_egress` (the RST log
     and `RstWait` passes) and `halt::after_sign` run here, not after each
     egress. `outside.rsts`/`inside.rsts` are cleared only at the start of
     the pass (R2-N3).
5. **Another pass is due** when `any_full(..)` holds, or when this pass's
   turn consumed at least one record and an eligible slot is still waiting
   (`tls_core::conn::pass_due`). `Pass::serve` returns it, so a waiting
   hello needs no unrelated wakeup (R2-F1, S1, T1).
   - Each extra pass consumes a record of the holder, from a finite
     receive buffer.
   - `end_pass` still notifies and flushes every pass.
6. **Each `poll_egress` takes a fresh `now()`**, monotonic and
   non-decreasing, so a flight sent after a 1.2 s sign is not stamped 1.2 s
   in the past. A stale stamp starts smoltcp's retransmit timer already
   expired (R2-F4).

The decisions live in `tls-core::conn` as pure functions, with unit tests,
and the PD applies them:
- `Slot::awaits_hello`;
- the turn choice over the slots' (eligible, since) pairs;
- `pass_due`;
- the handshake cap at admission (below).

Per-connection egress (R2's first draft) is dropped: once a pass holds at
most one expensive step, it has no observable effect (R2-F4, T2).

**The handshake cap (R2-F5/N2, S2).** C13 reorders the work; it does not
reduce it. The last of `n` concurrent handshakes completes, from its
admission, after about `n` × (hybrid exchange + sign) + RTT + the Finished.
The measurements already put `n = 8` near the 10 s timeout (8.19 s, 7.70 s).
So R2 decides the mechanism now and sets its value from C13's measurement:
- **`HS_CAP`:** connections in the Handshake stage at once.
  - It is a `tls-core::conn` constant, compile-time asserted to
    `4 ≤ HS_CAP ≤ MAX_CONNS`.
  - The floor of 4 has two reasons:
    - **The ordering predicate needs it** (R2-T-R3-1, round 4 R4-N1).
      `pass_due` starts the next pass at once, before A's Finished can
      make its round trip. So the turns of passes 1–3 sign A, B and C,
      pass 3 also handles A's Finished and sends the backend SYN, and A's
      request reaches the backend in pass 4's step 3. Only a fourth flight
      leaves after a receipt.
    - **It keeps `HS_CAP > MAX_PER_SOURCE` (2)**, so one source cannot hold
      every handshake place (R2-S6).
- **Admission:** the check is a pure function with the cap as a parameter,
  `admit_with_cap(source, now, cap)`. `Table::admit` calls it with
  `HS_CAP`, so the cap logic is testable whatever value is measured
  (R2-T-R3-5).
  - The refusal precedence is fixed: `PerSource`, then `Full`, then
    `HandshakeCap` (R2-F-R3-3; round 6 R6-M1).
    - `HandshakeCap` means a free slot was withheld because `cap` slots are
      in Handshake. With no free slot the refusal is `Full`.
    - So `HS_CAP = MAX_CONNS` is truly inert, and the existing
      `table_is_full_at_max_conns` keeps its `Full`.
  - A refused connection is aborted with a RST, like the existing refusals,
    and audited as `TlsClosed(HandshakeCap)`. That is a new kind in the
    closed table: `AdmitRefusal::HandshakeCap` → `Closed::HandshakeCap`,
    with audit-event's name table and completeness tests.
- **What the cap is for:** it bounds the latency of the last admitted
  handshake below `HANDSHAKE_TIMEOUT_NS`, by bounding the queued signing
  work. A connection keeps its slot from admission, so the cap does not
  reserve slots for anyone (R2-F-R3-3).
- **What it costs,** recorded under RM6-7 in the deviation log:
  - A real-source attacker needs only ⌈`HS_CAP`/`MAX_PER_SOURCE`⌉ sources,
    not ⌈`MAX_CONNS`/2⌉, to deny all new handshakes with idle connects
    renewed every 10 s.
  - A refusal burst holds free slots in Aborting for up to
    `MAX_RST_PASSES` passes.
- **The value:**
  - **Measurement:** the C13 tree's `https flood` boot with the cap inert
    (`HS_CAP = MAX_CONNS`), 3 runs on each of two hosts with no solver.
  - **Which runs count** (round 4 R4-N2):
    - A *complete* run met the completion rule.
    - A *capacity* run is decided only from what the probe observes
      (round 5 R5-M1). Admission order is not observable: the ports
      admitted in one pass share `since` and are ordered by slot index,
      which the sniffer cannot see. The run must satisfy all of these:
      - the ordering predicate holds;
      - every failed port timed out, with no first ServerHello or one
        among the last k crossings, where k is the number of failed ports;
      - every port whose first ServerHello crossed before those
        completed;
      - no gap between consecutive first ServerHello crossings exceeds
        twice their median. The predicate guarantees at least 4 crossings,
        so at least 3 gaps; the median of an even count is the mean of the
        middle two.

      That is queueing at the inert cap, not a stall. The earliest-deadline
      order itself is proven by the turn unit tests (re-arrival), not by
      the probe.
    - Any other failure is a stall. It goes to diagnosis and feeds
      nothing.
  - **`c`:** the largest gap between consecutive first ServerHello
    crossings, over the complete and capacity runs. The gap includes the
    other connections' work in its pass, so it is a conservative
    over-estimate.
  - **`L`:** the largest last-completion time over the complete runs.
    It is ∞ if any capacity run occurred.
  - **The rule:** `HS_CAP = MAX_CONNS` when `L ≤ ⅔ · HANDSHAKE_TIMEOUT_NS`.
    Otherwise `HS_CAP = min(MAX_CONNS - 1, ⌊(⅔ · HANDSHAKE_TIMEOUT_NS) / c⌋)`,
    so a failed first rule always yields a real cap (R2-F-R3-2).
  - **The stop:** a result below 4 is not taken, and neither is a set of
    six runs with no complete or capacity run. Either is a D3 stop: the
    re-plan goes back to the budget split (R2-S6, T-R3-1, R4-N1). With
    `⅔ · HANDSHAKE_TIMEOUT_NS` = 6.67 s, a floor of 4 needs `c ≤ 1.67 s`.
  - **The record:** the measurement, `c`, `L` and the value go in the
    deviation log as RM6-8, with each run's classification (complete,
    capacity, stall) and the observations behind it.
  - **Measurement versus gate (round 5 R5-M2):**
    - The measurement runs are not the gate. A capacity run fails the
      completion rule by design.
    - The probe therefore prints, on its failing path too, each port's
      first-ServerHello and completion times and its classification
      (admitted, refused, failed phase), before it raises.
    - When the value is `HS_CAP < MAX_CONNS`, the `https flood` gate is run
      again on the capped tree, 3 times on gx10 and on z1mn. Those runs
      exercise the admitted, refused and `TlsClosed(HandshakeCap)` checks.

**RST loss at the outside TX tier (R2-S4; round 2 R2-S5, F-N1).** Every
`tls` segment, RSTs included, goes through `TxTier::Tls`
(`tx_free > TX_RESERVE + TLS_TX_SHARE`). `tls` counts an abort's RST as
dispatched once it reaches the `tli` ring and releases the slot, so a RST
that `ingress` drops under a TX burst is never resent.

No exemption is made. `tls_egress` cannot tie a RST to an admitted
connection:
- a compromised `tls` (A3) can emit RSTs to any address;
- a remote attacker elicits bare RSTs from smoltcp with stray non-SYN
  segments, at the TCP data meter's rate.

An exempt tier would therefore hand the buffers that keep Rosenpass
answers, cookie replies and ARP replies to RSTs. That would break I8 and
its proof (`tls_tier_is_at_or_above_unsolicited`,
`tls_egress_accepts_only_conforming_packets`).

The loss is recorded as a residual equivalent to a RST lost in the network:
- a client with data outstanding retransmits and is reset by the re-armed
  listener's RST;
- only a client idly waiting for a response waits for its own timeout, and
  only for a connection that was being aborted.

FIN uses sequence space and smoltcp retransmits it while the socket lives;
the first draft's claim otherwise was wrong.

Unit tests (ingress-core) pin the tier for a bare RST|ACK:
- refused at `tx_free == TX_RESERVE + TLS_TX_SHARE`;
- admitted at `TX_RESERVE + TLS_TX_SHARE + 1`.

**Diagnosis (R2-T5, T6; round 2 R2-T-N2).** There is no audit counter
line: coalescing prints totals 1, 65, …, and TxNoBuffer is shared by every
tier. The probe therefore attributes per port:
- **The phase** a connection failed in: handshake, request write or
  response read.
- **That port's segments**, from the sniffer, each way, with timestamps.
- **The backend's receipt of that client's request.**
  - Each client adds a marker field, `X-Probe: <client port>`, which
    http-wire forwards unchanged.
  - `BackendConn` records the `time.monotonic()` of its first chunk.
  - The probe is given `backend`.

Audit totals in the record are lower bounds. The reproduction budget is 3
runs on each of two hosts after C13. A stall's attribution decides what
happens to it:
- a cause inside C13 is fixed;
- any other cause is recorded with a deterministic control, never as
  flake.

**Probe enforcement and its controls (R2-T2, T3; round 2 R2-T-N1).**
- **The ordering predicate is judged first.** It covers whatever was
  observed, before any other check:
  - "first ServerHello" for a port is the first crossing of the server's
    segment at seq = ISN+1 whose payload starts `16 03 03 .. .. 02`;
    retransmits are ignored;
  - "receipt" is the backend's first-chunk time for that port's marker;
  - green when some receipt precedes the last first-ServerHello;
  - red, with the needle "https concurrent probe: no request reached the
    backend before the last server flight", when there is no receipt at
    all, or no receipt precedes the last first-ServerHello;
  - every other failure is raised after this verdict.

  Under lockstep all flights leave before any Finished is processed. Under
  C13 the gap is milliseconds of RTT against seconds of signing. Neither
  depends on host load.
- **Admitted versus refused, per port from the sniffer (R2-T-R3-2,
  F-R3-1).**
  - *Refused:* a server RST with no earlier server payload on that port,
    arriving less than `HANDSHAKE_TIMEOUT_NS` after its SYN. That is a
    one-sided protocol bound, not a load threshold.
  - *Admitted:* every other port.
- **Completion:**
  - every admitted port completes;
  - admitted ≥ min(`HS_CAP`, conns), since a straggler admitted after a
    Finished may lift admitted above `HS_CAP`, so the bound is a minimum;
  - refused > 0 only when conns > `HS_CAP`;
  - no `TlsTimeout(Handshake)` line since the mark. An absence is
    checkable despite coalescing.
  - An admitted port with no ServerHello fails with its own needle,
    "https concurrent probe: client N admitted but got no server flight",
    raised after the ordering verdict.
- **The refusal audit (R2-T-R3-3):**
  - `TlsClosed(HandshakeCap) total=1` is expected since the mark if and
    only if the sniffer counted a refusal.
  - Refusal counts come only from the sniffer, because coalescing prints
    1, 65, ….
  - This depends on the probe being the boot's first `HandshakeCap`
    producer: case 12's hello flood runs after it. That ordering is
    recorded next to the probe.
- Times are printed as RM6-8 data, on the passing and the failing path.
  No time threshold is asserted.

**Rejected.**
- **Raising `tls`'s budget** (to 0.10, taking from `data`): it widens the
  budget and moves the cliff without removing the lockstep. It also cuts
  the VPN's crypto budget.
- **A longer HANDSHAKE_TIMEOUT_NS:** it widens the bound the slowloris
  defence rests on.
- **Rotation as the turn order:** the deadline counts from admission, so
  rotation can let the oldest handshake expire while a newer one is
  served (R2-F2).
- **Exempting RSTs from the TLS tier,** at the Answer or Unsolicited tier
  or on a meter: elicited and compromised-`tls` RSTs would take the
  answer and unsolicited buffers. A first-come meter does not even
  guarantee the abort's RST (round 2 R2-S5, F-N1).
- **A half-closed client** (hello plus FIN before its turn) still gets
  its turn. That is accepted: such clients are bounded by the per-source
  cap and the SYN limits, and the sign is `tls`'s own budget (R2-F7).

**Acceptance.**
- **Unit (tls-core):**
  - `awaits_hello`: true only in Open{Handshake} with AwaitClientHello;
    still true after the first fragment of a split hello; false for free
    and reset slots.
  - The turn: older versus newer, in both index orders; the tie; an
    ineligible incomplete record; re-arrival (slot 0 re-armed with a newer
    `since` every pass, while slot 7, older, gets the turn first).
  - `pass_due`: a deny/allow pair. Due when a record was consumed and an
    eligible slot waits. Not due when nothing waits, or when the turn
    consumed nothing (unless `any_full`).
  - The cap, through `admit_with_cap` with a cap below `MAX_CONNS`:
    - at `cap` slots in Handshake an admission is refused with
      `HandshakeCap`;
    - at `cap - 1` it is admitted;
    - a slot that leaves Handshake frees a place;
    - with no free slot the refusal is `Full`, even when `cap` slots are in
      Handshake;
    - `PerSource` is returned in preference to both;
    - with `cap = MAX_CONNS` no admission is ever refused `HandshakeCap`
      (inertness).
  - A `tick` regression: a slot in Handshake reaches `Timeout::Handshake`
    10 s after admission. This is existing behaviour that C13 must not
    change, not evidence of deferral.
- **Unit (ingress-core):** the bare RST|ACK pair above. The existing I8
  proofs stay unchanged.
- **Selftest, unit gate, one mutation each:**
  - the turn ignores `since` and takes the lowest eligible index (red: the
    re-arrival test; the tie test stays green);
  - `pass_due` is forced false;
  - the cap check is removed (red: the cap pair).
- **check-pins:** a rule anchored inside
  `impl ring::pass::Pass for Pass` in crates/pds/tls/src/main.rs (that file
  has three `fn serve`; R2-T-R3-4). The rule fails when the anchor is
  missing, as P18 does. Within the anchor, `serve` must return `any_full(..)`
  `||` `tls_core::conn::pass_due(..)`.
  - Deny fixtures: `&&` in place of `||`; a dropped term; a missing anchor.
  - An allow fixture.
  - A pins-gate selftest that removes `|| pass_due(..)` from the real
    main.rs, with the rule's code as its needle.

  Steps 3 and 6 (egress before the turn, a fresh `now()` per egress) are
  review-only and recorded as such in the deviation log.
- **Selftest, test gate:** a mutation in crates/pds/tls/src/main.rs that
  serves every eligible ClientHello in one pass (the lockstep). Its needle
  is the ordering predicate's, judged first.
- **Integration (`https flood`):**
  - the ordering predicate holds, and every admitted handshake completes;
  - times, sign high-water, the per-hello gaps and the last completion are
    recorded;
  - the diagnosis lines are absent.

  It runs 3 times on each of two hosts with no solver: gx10 and z1mn. If
  the measurement sets `HS_CAP < MAX_CONNS`, those runs are made on the
  capped tree.
  mrx33, a third arm64 worker set up 2026-10-25, is excluded from timing
  gates. It fails cookie boot a ("WgCookieSuppressed during the paired
  flood") at 4209823 too (2 of 2), so its TCG timing is outside what the
  existing cases are calibrated for.
- **Verification environment:** TCG wall time varies with host load (3.48
  s versus 8.19 s on the same tree). The gate runs only on a host whose
  process list shows no live cbmc, kani-gate or cargo-kani.

### Go/No-Go additions (R2)

| ID | Subject | Status |
|---|---|---|
| C13 | `tls` pass: ClientHello held back, one hello turn per pass (earliest admission), the hello served after an egress, another pass while one waits, fresh egress time; `HS_CAP` at admission (value from measurement); RSTs stay in the TLS tier (residual); the concurrent probe enforced with a first-judged ordering predicate and per-port diagnosis | locked |

### Implementation checklist (R2)

- crates/tls-core/src/conn.rs, conn/proxy.rs:
  - `Slot::awaits_hello`, the turn choice and `pass_due`;
  - `HS_CAP` with its admission check, `AdmitRefusal::HandshakeCap` and
    `Closed::HandshakeCap`;
  - unit tests;
  - a `pub` accessor for the Handshake `since`.
- crates/audit-event: the `HandshakeCap` closed kind, its name, and the
  completeness tests. Also the pds/tls `names_match` table.
- crates/pds/tls/src/main.rs:
  - `Tls::pass` in C13's order;
  - the held-back hello at `take_record`;
  - `Pass::serve` returns `any_full || pass_due`;
  - a fresh `now()` per `poll_egress`;
  - a notify after each egress that sent;
  - `after_egress`/`after_sign` once per pass after the last egress.
- crates/ingress-core/src/tests.rs: the bare RST|ACK tier pair. No change to
  the tiers or proofs.
- tests/integration/run.py:
  - the concurrent probe, with `backend`, the `X-Probe` marker, the
    first-ServerHello times and the first-judged ordering predicate;
  - per-port diagnosis and completion of the admitted handshakes;
  - `BackendConn` first-chunk time;
  - INTEGRATION-CASES unchanged.
- tools/check-pins with fixtures; tools/check-selftest (three unit-gate
  cases, one pins-gate case, one test-gate case).
- tests/manifest.txt, expected deltas (R2-T-R3-6):
  - UNIT-TESTS, UNIT-TLS-CORE and UNIT-INGRESS-CORE (+2);
  - UNIT-AUDIT-EVENT, if its completeness tests gain cases (check-selftest
    derives AUDIT_EVENT_TESTS from it);
  - CHECK-PINS-RULES 19 → 20 and CHECK-PINS-FIXTURES (+4);
  - INTEGRATION-CASES stays 77.

  Case 12's hello flood now also counts `HandshakeCap` refusals as
  "ended"; that is recorded.
- Deviation log:
  - R2's measurements, each run classified (complete, capacity or stall)
    with its evidence, `HS_CAP`'s value and its derivation, and RM6-8;
  - the stall's attribution, if one is seen;
  - the RST-loss residual;
  - steps 3 and 6 recorded as review-only.
