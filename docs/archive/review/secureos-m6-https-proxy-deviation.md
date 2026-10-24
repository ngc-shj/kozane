# Coding Deviation Log: secureos-m6-https-proxy

## Slice 1 (C1, C2, C3 echo)

Gates run: make pins/lint/lint-pds/unit/laws/image green; Kani alone per
harness — `wire::parse_tcp_checks_every_accepted_header` (10/10 covers),
`ingress-core::{tls_tier_is_at_or_above_unsolicited (1/1),
tls_egress_accepts_only_conforming_packets (3/3),
tcp_branch_admits_only_https_to_us (7/7), respond_is_total_and_bounded
(7/7; now through the TCP re-parse)}`; integration boots `https` and `raw
frames` green; selftest cases laws-tls-{pqkey,budget,priority,hd} and
c2-{tcp-checksum,syn-fin,tls-egress-src,tls-tier,syn-src-bucket} red with
their needles.

Deviations:

- **L13 sum in exact arithmetic (C1 said "no new law code").** The eleven
  tainted ratios sum to 0.9500000000000001 in floating point, so the
  at-cap system was refused. The checker now sums exact fractions (u128)
  and rounds once; fixtures for at-cap allow and one-µs-over deny. This is
  the root-cause fix, not an epsilon.
- **rfc6979 `=0.6.0` with sha2 `=0.11.1` as key-core dev-dependencies.**
  rfc6979 0.4 pulls hmac 0.12/digest 0.10 "mac" and would change
  mce460896's P16 closure; 0.6 uses digest 0.11 and leaves it untouched.
  Host tests only.
- **`tls_egress(cfg, packet, tx_free) -> Result<Frame, EgressRefusal>`**
  (`Dropped(DropReason)` or `TxReserve`); field violations use the new
  egress-only `DropReason::TcpEgressRefused`; the tier is `TxTier::Tls` with
  `TLS_TX_SHARE = 16`, asserted ≥ `RP_ANSWER_SHARE`.
- **Audit bases:** `TCP_LIMITED_BASE = 0x0200` (0x0140 is pinned unknown by
  an existing test); TLS_REFUSED 0x0220, TLS_CLOSED 0x0240, HTTP_REFUSED
  0x0260, TLS_TIMEOUT 0x0280 reserved for slice 3.
- **New DropReasons 17–23**: TcpBadLength, TcpBadOffset, TcpBadChecksum,
  TcpBadPort, TcpBadFlags, TcpBadOptions, TcpEgressRefused (egress only);
  segments over 1480 bytes are TcpBadLength. `parse_tcp` sits outside
  `verus!`; `parse_frame` and its spec are untouched.
- **Every TCP failing the branch rules is `NoService`**, a spoofed source
  included (C2's "other TCP → NoService").
- **Bucket constants** (C2/F-N11 "recorded in slice 1"): SYN per source
  burst 4, 1 per 250 ms; SYN global burst 16, 1 per 50 ms; data burst 64,
  1 per 100 µs (≈ 14.6 MB/s of 1460-byte segments); asserted that a source
  never exceeds the global bucket.
- **Backend links mapped but unused** in `tls` and `inner` (Microkit refuses
  a `setvar_vaddr` with no symbol); forwarding lands in slice 4.
- **`PassIo::serve_tls`** in ingress, between `serve_data` and the tick.
- **Channel ids:** key `CH_TLS = 4` (id 2 is what the `two_key_channel`
  selftests inject); ingress 7, inner 4, timer 5, audit 8; tls: ingress 1,
  inner 2, timer 3, key 4, audit 5.
- **`tls` halt codes** NO_CLOCK 1, RNDR 2, INIT_FAILED 3 (KEY_UNAVAILABLE
  arrives with D5 in slice 2/3); smoltcp seed from RNDR until the hedged RNG
  (slice 3).
- **run.py:** `tls` in READY_LINE; the reason-list check compares sets
  (`DROP_REASONS + FORWARD_ONLY + EGRESS_ONLY`); preflight requires openssl
  with X25519MLKEM768 and curl on OpenSSL ≥ 3.5.
- **Not yet done from slice 1's list:** the first CPU probe (ML-KEM-768 +
  X25519 + HKDF at 0.05) needs tls-core's exchange; it moves to slice 3
  with the second probe. `make test it_boots=...` exits 2 on filtered runs
  (no INTEGRATION-CASES line); filtered boots are run through run.py
  directly.
