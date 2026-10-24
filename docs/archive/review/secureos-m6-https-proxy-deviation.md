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

## Slice 2 (C5, C11)

Gates run: make pins/lint/lint-pds/unit/laws/image green;
tests/tools/test_mkcert.py 18/18. Not run (by the slice's rules): Kani,
Verus, make test/check, check-selftest. Hand red-proof on a throwaway copy:
c5-k-prime fails `two_k_prime_values_give_different_r_for_the_same_hash`
alone; a mkcert without NameConstraints fails the four OpenSSL negative
fixtures and the two constraint fixtures. Cargo.lock unchanged.

Constants (C5):

- **`TLS_SIGN_BURST` 32, `TLS_SIGN_INTERVAL_NS` 50 ms (20/s),
  `TLS_BOOT_CALLS` 1.** One sign per admitted handshake: the refill equals
  the global SYN refill (50 ms) and the burst covers the SYN burst (16) plus
  the boot call with room; neither changes what `hs` can wait, which the
  per-call invariant bounds.
- **`SIGN_COST_NS` 20 ms, PROVISIONAL** until slice 3 records the maximum of
  20 TCG runs × 2. HACL* P-256 signs in about 0.1–0.3 ms natively; 20 ms
  allows a 60–200× TCG slowdown. Bound to libcrux-p256 0.0.9's lock entry by
  check-pins P17 (`SIGN_COST_LIBCRUX_P256`).
- **`HS_KEY_WAIT_MAX_NS` = REKEY_TIMEOUT / 10 = 500 ms** (in `hs-core`): an
  initiation costs two key calls, so both at the bound stay within a fifth
  of the 5 s retry window. The invariant evaluates to (ceil(20 / 0.5) + 1) ×
  10 ms = 410 ms ≤ 500 ms; it holds up to `SIGN_COST_NS` 24.5 ms, so the
  slice-3 measurement must come in at ≤ 12.25 ms per sign (× 2) or D3's stop
  rule applies.

Deviations:

- **The blob's TLS check lives in `secret-blob`
  (`Blob::parse_checking_tls`).** The only way to wipe [80:112] after the
  checksum without a public unchecked constructor: it verifies, hands the
  scalar to the caller's judgement, wipes a refused scalar in place and then
  takes the long-lived borrow. `key_core::validate` takes `&mut` region and
  returns `Validated { blob, tls }`; `Oracle::new` takes that.
- **`Oracle::handle` takes `&mut Buckets` and the entropy source** (one PPC's
  whole context) and charges the caller's own bucket; the PD holds
  `Buckets::new()`. `BootEntropy` is renamed `Entropy` (it also feeds k').
- **A refused TLS key answers before the bucket**: `TLS_SIGN` with a
  `TlsKeyError` costs `tls` nothing and does no work.
- **HMAC-SHA256 through `tpm2::crypto::hmac`** (libcrux-hmac): key-core gains
  no dependency edge. `libcrux-p256` gets `expose-hacl` (features are not in
  the lock) for `ecdsa_sign_p256_sha2`. Secrets use `tpm2::Secret`; no
  zeroize edge for key-core.
- **Scrub depth `key_core::SCRUB_DEPTH` 32 KiB, not measured**: chosen far
  above P-256/HMAC frames inside the 128 KiB stack; the scalar residue case
  (T8, slice 3) adjudicates. The PD scrubs after the boot (TLS check,
  accepted or refused) and after every `TLS_SIGN`-labelled call.
- **`KeyWaitHighWater` (0x0057) is gated by `CostHighWater`** (now carrying
  its event constructor: `CostHighWater::key_wait()`), as `RpCostHighWater`;
  `hs` reports the longest call since the last report after each wakeup and
  once after init (the boot seed call: the baseline).
- **Config shape:** `tls_ports = { start, count }`, `backend = { ip, port }`
  inline tables in `[gateway]`; `MIN_TLS_PORTS` 8 (pds/tls asserts
  `TLS_PORTS.1 >= MAX_CONNS`); a backend port of 0 is refused;
  `MAX_TLS_CERT` 3072 bytes (the Certificate message must fit one 4 KiB
  server record).
- **Placeholder certificate committed** (`config/keys/tls.der`, public only):
  issued by mkcert for 10.0.2.15 to a P-256 key that was discarded, like the
  placeholder gateway key; no private key is committed. Deployments get a
  matching pair from mksecrets.
- **mksecrets/mkcert interface:** mksecrets writes `tls.pub` (PEM SPKI),
  runs `python3 tools/mkcert` in a private temp directory it removes (only
  public material), accepts only mkcert's four known file names, and writes
  `tls.der`, `devca.pem` (and with `--test-negative` the negative leaves)
  into the deployment. `--tls-name` defaults to the template's
  `outside_ip` (IP mode). `--tls-mismatch-blob` writes
  `secrets-tls-mismatch.bin`: the same gateway key, seed and peers with
  another valid TLS scalar (case 8).
- **mkcert negatives:** the other-form leaf in IP mode is
  `gateway.example`, not under `invalid` (a dNSName constraint `invalid`
  permits its subdomains); the other-name leaf in name mode is `not-<name>`
  (not a subdomain of the permitted name).
- **P6 fixtures expect P17 too** when the lock is unreadable or has no
  packages: P17 fails closed there, as P16 does.
- **Deferred to slice 3: `KEY_CALLERS` gaining `tls`, the `TlsKeyError`
  code reader in run.py, `tls`'s halt `KEY_UNAVAILABLE`.** All need `tls`'s
  init to call `key` (`BOOT_SEED`, C7), which needs the pd-tls → key-core
  edge in Cargo.lock that slice 3 adds with tls-core; adding `tls` to
  `KEY_CALLERS` now would make every sealed-boot case wait for a line `tls`
  never prints. run.py gains the blob offsets (`KEY_BLOB_GATEWAY_PRIVATE`
  [16:48], `KEY_BLOB_TLS_PRIVATE` [80:112]); its packaged boots get v3 blobs
  through mksecrets.
- **ct-shape not run here**: pd-key's `open_sealed` closure is unchanged in
  source, but pd-key gained code; `make ct-shape` (and `make package`'s run
  of it) is the check.

### Slice 2 verification (orchestrator)

- Gates green (pins, lint, lint-pds, unit, laws, ct-shape — CT-SHAPE-SYMBOLS
  99 unchanged, ct after its record went stale with tpm2/secret-blob); full
  integration 45/45; selftest c5-* (12), mkcert-constraints, key-wipe red
  with their needles.
- **A slice-1 test defect surfaced here:** run.py's stack-report check
  counted every `StackHighWater` occurrence against pq's lines, so `tls`'s
  own report (slice 1) read as a garbled pq report in the rp gate boot.
  Slice 1 ran only the `https` and `raw frames` boots. The check now treats
  a garbled report as any occurrence that is not a whole line of some
  producer, and takes each PD's marks from its own lines.
