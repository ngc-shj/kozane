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

## Slice 3a (C6, C7 host side, C10's conn)

Gates run: make pins/lint/lint-pds/unit/laws/image. Not run (by the
slice's rules): Kani, Verus, bolero, ct, ct-shape, mir, make test/check,
check-selftest. The selftest cases added here were red-proved by hand on
throwaway copies under build/ (the session scratchpad is not mounted in
the dev container): each failed with its needle.

Lock (one change for the rest of M6, owner decision 2026-10-24):

- **New leaf crate `ct`** holding the repo's `ct_eq`, moved verbatim from
  `wg_core::crypto`, which re-exports it (`pub use ct::ct_eq`), so tpm2,
  key-core and wg-core compile unchanged. tls-core depends on `ct`, not on
  wg-core. tools/ct-harness's own lock gains `ct` (tpm2 → wg-core → ct).
- Edges added now so Cargo.lock changes once: tls-wire and http-wire
  dev-dep bolero `=0.13.4`; tls-core → ct, tls-wire, zeroize `=1.8.1`
  (featureless, P16), dev-deps libcrux-p256 (`expose-hacl`) and
  libcrux-hkdf; pd-tls → tls-core, tls-wire, http-wire, key-core (labels and
  words, as pd-hs), wire (reading its own transmitted packets for the abort
  RST, C8) and zeroize (socket storage wipe). Unused for now; no
  unused-dependency lint is enforced. No package version changed.
- **MIR-CRATES 8 → 9 expected**: tls-wire joins kani_crates and is now in
  pd-tls's dependency closure.

Deviations and decisions:

- **HKDF over libcrux-hmac, not libcrux-hkdf (C7 said libcrux-hkdf).**
  libcrux-hkdf 0.0.9's expand allocates (`vec!`/`Box`, hacl-rs `alloc`) and
  the `tls` PD has no heap. Every TLS 1.3 output with SHA-256 is at most one
  hash long, so HKDF-Expand is its first block T(1) = HMAC(PRK, info ‖ 1);
  Extract is HMAC(salt, IKM) (RFC 5869). libcrux-hkdf moved to a tls-core
  dev-dependency and the unit tests compare against it; RFC 8448 and the
  OpenSSL keylog fixture check the schedule end to end.
- **Hedged RNG keyed with HMAC-SHA256** (the `pq` pattern over libcrux-hmac,
  which tls-core already has) rather than BLAKE2b: no blake2 edge.
- **KeyUpdate must end at a record boundary too** (RFC 8446 section 5.1;
  C6 listed ClientHello and the client Finished): the read key changes after
  it. Refused with `NotAtRecordBoundary`.
- **Our bounds for linear duplicate checks:** at most 64 extensions
  (`DuplicateExtension` beyond) and 16 key_share entries (`Decode` beyond);
  real clients send about 20 and 1–3.
- **`Refusal` lives in tls-wire** (both crates' reasons, 32 codes, the width
  reserved for `TLS_REFUSED_BASE`); `alert()` maps each, None for the
  peer's own alert and for input after close. Alerts where RFC 8446 leaves
  the choice: record version and an over-long handshake message →
  decode_error; supported-but-no-share (RM6-6) and missing
  signature_algorithms → handshake_failure; duplicate extension →
  illegal_parameter.
- **Anything but a ClientHello is refused from its first byte**, not
  buffered until complete.
- **The server flight is one protected record per message** (EE, Cert, CV,
  Finished), each at most 4 KiB; no middlebox-compatibility CCS from the
  server (OpenSSL and curl need none).
- **A plaintext alert after our ServerHello** (a client that could not use
  it) is `PeerAlert` (not answered); any other plaintext handshake or alert
  record after the ServerHello is unexpected_message.
- **early_data's 16 KiB counts the skipped records' bodies** (ciphertext
  bytes); the unit cases are 16 384 accepted, 16 385 refused.
- **Sequence numbers:** u64::MAX is never used; application data stops at
  u64::MAX − 1 so a closing alert always has a nonce.
- **Close sequencing in `conn`:** close_notify (backend FIN, self-generated
  response) drains, lingers ≤ 2 s, then aborts; a fatal alert drains then
  aborts without the linger; backend RST, client close before the response
  end, errors and every timeout abort at once (wiped first). The backend
  socket's RST is tracked only once the head stage has opened it (slice 4).
- **`SCRUB_DEPTH_EXCHANGE` 48 KiB, PROVISIONAL**, not measured: above
  libcrux ML-KEM-768 encapsulation frames at the PD's opt-level inside the
  128 KiB stack; the slice-3b ct-harness residue case asserts the painted
  high-water within it.
- **The host test client reuses tls-core's schedule and record code**; the
  RFC 8448 (all SHA-256 values, checked against Python as well) and keylog
  fixtures check those independently.
- **check-pins:** P11 becomes `TAG_SETS` (tpm2, key-core, pds/tls: hmac/tag;
  tls-core: finished/verify_data anchored on handshake.rs; pds/tls also
  finished/verify_data); P18 the L14 constructor rule (crates/ and tools/);
  P19 the code-point tripwire in tls-core, narrowed against false
  positives: two-digit hex only for 0x1d/0x1e (0x17 is application_data,
  0x18 KeyUpdate, 0x20 the CertificateVerify padding) and decimal byte pairs
  only for 23–25, 29 and 30 (`0, 32` is a Finished length).
- **`Table::new` is not `const`** (libcrux's `Sha256::new` is not): slice 3b
  initializes the PD's table at init.
- **Fixture capture scripts** in tests/tls/: `capture_client_hellos.py`
  (raw listener; OpenSSL 3.5.7 s_client and curl 8.14 with and without
  `X25519MLKEM768`, `-groups X25519`, `-tls1_2`), `der_fixture.py` (five
  OpenSSL-verified signatures covering each INTEGER shape),
  `capture_keylog.py` (s_server/s_client through a recording relay, keys
  and records decrypted by Python `cryptography`; s_client's `k` command
  needs `-ign_eof` off).

### Slice 3a verification (orchestrator)

- Gates green: pins, lint, lint-pds, unit, laws, ct, ct-shape, mir, bolero
  (5 targets; the tls-wire seeds had to be in the index for the committed-
  seed check, and were committed with feb7ec1 by mistake — they belong to
  this slice); selftest's 18 new cases red with their needles.
- **Kani harness narrowed:** `client_hello_is_total_and_refused_within_96_bytes`
  walked 96 symbolic bytes through `client_hello` and again through `walk`;
  cbmc passed 32 GiB on gx10 and was stopped before the 40 GiB cap. The
  walker is its own harness, so the ClientHello harness now proves only
  `client_hello`'s totality over 64 bytes (past the fixed fields into the
  extension block), covering a refusal decided there.
- Kani for this slice was still running at commit time (tls-wire on gx10,
  the full suite after the lock change on z1mn); results are recorded with
  slice 3b.
- HKDF is built on libcrux-hmac (T(1) expand) because libcrux-hkdf 0.0.9's
  expand allocates and `tls` has no heap; checked against libcrux-hkdf in a
  host test and by RFC 8448.

## Slice 4 part 1: http-wire (C9)

Implemented in an isolated worktree in parallel with slice 3a and merged
(crates/http-wire only, plus the bolero target, Makefile, manifest and five
selftest cases). Gates: pins, lint, unit (UNIT-HTTP-WIRE 64), bolero (6
targets); selftest c9-{te-refusal, duplicate-cl, connection-names-cl,
xff-strip, body-413} red with their needles. Kani for its four harnesses was
running at commit time.

Deviations:
- **`head_end(bytes) -> Result<Option<usize>, HttpRefusal>`** added: the PD
  must tell "wait for more" from "refuse"; a bare CR or LF refuses at once,
  so an LF-only client cannot hold a slot until the timeout.
- **`rewrite` also drops a bare `Proxy:` field** (httpoxy, CVE-2016-5385);
  the contract listed only `Proxy-*`.
- **Stricter than RFC 9110:** Content-Length with a leading zero is refused
  ("0" alone is fine) so no backend reads it as octal; its parse saturates
  just above MAX_BODY (any digit count → 413, overflow-free); Host must be a
  non-empty reg-name or strict IPv6 literal with port 0..65535, no userinfo.
- 8 KiB head = request line through the blank line's final CRLF (8192
  accepted, 8193 → 431). 501 covers CONNECT, absolute/authority/asterisk
  form, any Transfer-Encoding and Upgrade; precedence after all lines pass:
  missing Host (400), Expect (417), 413.
- The rewrite Kani harness is bounded at a fixed request line
  (`GET / HTTP/1.1`), at most 16 symbolic field bytes and at most 2 fields
  (its dropped-field check nests over the fields; 40 symbolic bytes of whole
  head timed out at 90 minutes), below the plan's 96 B / 4 fields. (This
  entry said 64 B / 3 fields, an earlier bound; corrected in code review
  round 1, T6.)

## Slice 3b (C7, C8 in the PD; probes)

Gates run by the implementer: make pins/lint/lint-pds/unit/laws/image/ct/
ct-shape. Not run (by the slice's rules): Kani, Verus, bolero, make
test/check, check-selftest; every integration case and every `test`-gate
selftest case below is unrun. Hand red-proofs on throwaway copies under
build/: conn-reset-session and tls-audit-names red with their needles; the
ct cases as recorded by the ct-harness work below. Root Cargo.lock
unchanged; tools/ct-harness/Cargo.lock gains libcrux-ml-kem 0.0.11,
tls-core and tls-wire.

Decisions and deviations:

- **One slot per listener, admission at SYN-RECEIVED.** The PD maps each
  of its eight listeners to the `conn` slot it admitted (MAX_CONNS is
  `tls_core::conn::MAX_CONNS`), so `Table::admit`'s `Full` cannot occur. A
  per-source refusal still needs the C8 abort sequence, so `conn` gained
  `Table::refuse`: a free slot straight into Aborting (no session, no
  source, only the client RST awaited), released by the same
  `abort_pass` decision as every other abort.
- **The slots are reset in place.** `Slot::open`/`abort_pass` built a
  fresh `Slot::new()` (about 47 KiB) by value; `Table::new` (370 KiB)
  cannot be built on a 128 KiB stack at all. `Session::reset` and
  `Slot::reset` now zero and re-initialise in place (same state as `new`,
  unit-tested by a released slot serving a second handshake); the PD writes
  its static table slot by slot at init.
- **The PD reads whole records; socket rx 17 KiB (C10 said 16 KiB).** A
  record is taken off the socket only once complete (`peek_slice` of the
  header, then `recv_queue` ≥ 5 + length), into one PD-wide record buffer;
  the socket's receive buffer therefore holds the largest record (16 645
  bytes). This saves a per-connection 16 KiB reassembly buffer. A header
  that fails its checks is handed over alone, so the session refuses it at
  once. The server's records go through one 8 KiB PD-wide `out` buffer;
  `FLIGHT_MAX` (certificate + 2 KiB) is asserted within it and within the
  empty send buffer. Static state is asserted ≤ `TLS_STATE_MAX` (1 MiB,
  defined in the PD).
- **`Slot::append_head`** moves an AppData step's plaintext into the head
  buffer and wipes it from the record buffer (the head and record buffers
  were both reachable only through `&self`/`pub` fields).
- **Abort RST observed by the PD's own transmit path:** `TxToken::consume`
  parses every packet that reached `tli` with `wire::parse_ipv4_packet` and
  `parse_tcp` and logs (peer address, port) of each RST from the HTTPS
  port, per pass. After the pass's egress poll each aborting listener
  reports `abort_pass(Client, dispatched)`; on Release the socket is
  removed, its buffers zeroed through the static (raw places, never a
  reference to another listener's buffers) and a new listener made, before
  the next poll. `dispatched` is also true when the socket had no 4-tuple
  left at abort time (the peer's RST, a TCP timeout, or a RST in
  SYN-RECEIVED that put it back to Listen): smoltcp has nothing to send
  then, and waiting eight passes would only delay the release. A socket
  found in Listen with a slot is treated as reset, so a new client never
  inherits a slot.
- **No integration observable for the RST observation or the client
  socket's storage wipe** (as T-R7-1 for the backend): the socket buffers
  hold ciphertext only, and the interface answers any later segment for a
  forgotten 4-tuple with its own RST, so removing the observation would
  leave every barrier green. The decision is `conn`'s (unit-tested:
  conn-rst-exhausted and the dispatched-on-pass-k tests); the PD's call
  sites are the reviewed part. Likewise the zeroing of the message
  registers after `TlsSign`/`BootSeed` (mirroring pd-hs) has no gate that
  can see it: the boot seed is legitimately live in the hedged RNG.
- **Stack scrubs:** besides the two the plan names (after `exchange`, in
  tls-core, and after each `TlsSign`, in the PD's signer), the PD scrubs
  after every `Slot::on_record` and after sealing its response and
  close_notify. Rust moves of `Secret`s (`HybridSecret` out of the
  exchange's `Result`, the schedule's secrets, KeyUpdate's replacements)
  are copies nothing wipes, and the record keys' copies sit in libcrux's
  dead ChaCha20-Poly1305 frames; the closed-connection residue case would
  otherwise rest on what later calls happen to overwrite. Also once at the
  end of init (the boot seed's copies).
- **`TlsSignHighWater` (0x0058)**, a value event gated by
  `CostHighWater::tls_sign()`, carries the longest `TlsSign` wall time
  (CNTPCT around the PPC) since the last report. run.py prints it with the
  probe's handshake times; SIGN_COST_NS and P17's entry are moved together
  from that measurement by the orchestrator (C5).
- **Audit kinds decoded:** `TlsRefused(<Refusal>)`, `TlsClosed(<reason>)`,
  `HttpRefused(<status>)`, `TlsTimeout(<stage>)`, coalesced per value like
  `FrameDropped`. TLS_CLOSED's reasons are the new `conn::Closed`:
  the five `CloseCause`s, `SlotsFull`, `PerSource` and `PeerReset`. The
  name tables live in audit-event (which depends on none of the enums,
  and adding the edge would change the root lock); the PD asserts at
  compile time that each table matches its enum (`Refusal::name`,
  `Closed::name`, `Timeout::name`, `Status::code`).
- **`tls` halt table:** NO_CLOCK 1, RNDR 2, INIT_FAILED 3, KEY_UNAVAILABLE
  4. A `TlsSign` answered Unavailable refuses that handshake (internal_error,
  slot wiped), then at the end of the pass `tls` audits `KeyUnavailable`
  and halts. `tls` does not probe `TlsSign` at init: it would spend a
  bucket token the C5 invariants do not budget, so the failure shows at the
  first HTTPS handshake (case 8 drives one).
- **run.py, slice 3b adaptation of the C8 barriers (no backend yet):** the
  host-observed barrier for cases 1/2 is the fixed response on connection
  A, which A requests only after `k` and `K`, so it proves the server read
  under client secret 2 and wrote under server secret 1; the response and
  close_notify are queued, and the slot wiped, in the same step. Case 3's
  barrier is the plan's (the abort RST, then a SYN from 10.0.2.77
  answered). With no streaming backend, a closed connection's secrets
  cannot be checked "present" before its close; the cases therefore become
  one scan: every handshake and traffic secret of A (client 0-2, server
  0-1, Python HKDF-Expand-Label checked against OpenSSL's keylog N lines),
  their record keys and IVs, and A's marker (a `Proxy-Selftest` header:
  s_client takes a line starting with `k`/`K` as a command, so the
  `Keep-Alive` marker of slice 4 cannot be typed through it) are absent,
  while a live connection B's CLIENT_TRAFFIC_SECRET_0 is present. B holds
  its slot in the head stage, so the scan must finish within the 10 s head
  timeout (a slow host fails the control by name, never passes falsely).
- **run.py, other boots:** `https` (handshake cases with s_client and
  curl, a wrong CA from deployment B and a wrong name via `--resolve`,
  NoPqGroup, NoTls13, 20 probe handshakes with the canary, `tls`'s stack
  headroom (the M4 C8 rule, reaching the exchange scrub), the scalar
  count), `https residue` (slowloris first, then the residue case) and
  `tls key failure` (deployment A's `--tls-mismatch-blob` packaged on A's
  image and TPM; HTTPS attempt, tls's KeyUnavailable code 18 and Halted 4,
  a Rosenpass + WireGuard handshake on the tap, the rejected scalar absent
  in both byte orders while the blob's gateway key is present).
  INTEGRATION-CASES 45 → 54 (the echo case goes, ten come).
- **Probe:** only the sequential 20 are run here; the 8 concurrent
  handshakes of C10 need four source addresses (MAX_PER_SOURCE 2) and stay
  with slice 5's hardening boots.
- **ct-harness residue mode (T-R4-1):** tls-core joins tools/ct-harness
  with every libcrux crate it pulls `=`-pinned to the root lock (ml-kem
  0.0.11 with `mlkem768` only, curve25519 0.0.9, chacha20poly1305 0.0.10,
  hacl-rs 0.0.6, hmac 0.0.9, intrinsics 0.0.9, macros 0.0.4, platform
  0.0.4, poly1305 0.0.7, secrets 0.0.7, sha2 0.0.9, sha3 0.0.11, traits
  0.0.9). Two runs on the painted stack: `exchange-depth` (no scrub; fails
  `RESIDUE-DEEP` above `SCRUB_DEPTH_EXCHANGE`) measured 34 040 B, so the
  provisional 48 KiB stands; `exchange` (exchange then the scrub from the
  same frame, the result dropped in place) with needles for the X25519
  ephemeral (raw and clamped), the ML-KEM randomness m, the SHA3-512 G state
  over m ‖ H(ek) (holding K ‖ r), the ML-KEM shared secret (from the
  client's decapsulation, checked equal to G's K) and the X25519 secret.
  RESIDUE-CASES 27 → 29. libcrux-internal forms with no public function to
  compute them (the message polynomial, noise vectors, X25519 limbs) are not
  needles: a declared gap.
- **ct-shape identity-only roots (T-R6-1):** (pd-tls,
  `tls_core::hybrid::exchange_with_randomness`) and (pd-tls,
  `tls_core::hybrid::scrub_session_stack`) get the identity check only (no
  contained, forbidden or shape check, not in the shape subjects, so libcrux
  stays out of the baseline); the RNG-generic `HybridSecret::exchange` shim
  is excluded by name (the McEliece `encaps` precedent). CT-SHAPE-SYMBOLS
  99 → 138 (38 for the exchange's closure, 1 for the scrub). Three build
  artefacts surfaced and were fixed where they arise: anonymous rodata
  labels (`<anon.N>`, numbered per object) are now named by a digest of
  their bytes, pointers in them to symbols followed two levels (a panic
  Location's file, line and column are compared); LLVM's memcmp → bcmp
  rewrite on the harness's linux target (no switch short of `no_builtins`,
  which would change all libcalls) makes memcmp and bcmp one closure stop,
  like memcpy, while the forbidden check still sees raw names; and the
  harness recorded absolute source paths for the repo's crates (path
  dependencies outside its workspace), so the `ct-harness` recipe remaps
  `$(CURDIR)/` away. CT-SHAPE-FIXTURES 52 → 63.
- **Selftest cases added:** ct: tls-exchange-residue,
  tls-exchange-scrub-depth; ct-shape: tls-identity; unit:
  conn-reset-session; lint-pds: tls-audit-names; test: tls-key-halt,
  c8-head-wipe, tls-scalar-scrub, https-probe-canary (the four `test`
  cases unproven: QEMU is not run here; tls-scalar-scrub assumes HACL's
  limbs survive in key's dead frames without its scrub).

### Slice 3b verification (orchestrator) and the D3 stop rule

- Gates green (pins, lint, lint-pds, unit, laws, image, ct, ct-shape);
  integration boots `https`, `https residue`, `tls key failure` all pass:
  OpenSSL and curl complete TLS 1.3 with X25519MLKEM768 against the dev
  CA, wrong CA/name refused, classical-only → handshake_failure (L14),
  TLS 1.2 → protocol_version, residue cases clean with a live control,
  slowloris closed at 10.1 s, the TLS-only key failure leaves the VPN up.
- **`tls` stack raised 0x20000 → 0x30000.** The high-water was 116 KiB
  (ML-KEM-768 work on the stack), leaving 14.7 KiB free against the
  16 KiB rule; now 80 KiB free.
- **Probe:** handshake (curl appconnect − connect) max 2.05 s over 20, limit
  3.33 s. **TlsSignHighWater 0.64–1.72 s** — the sign runs in the passive
  `key` on `tls`'s 0.05 budget, about 35–85 ms of CPU under TCG.
- **D3 stop rule fires.** C5's per-call wait `(ceil(SIGN_COST/TLS_BUDGET)+1)
  × PERIOD ≤ HS_KEY_WAIT_MAX_NS` cannot hold: with SIGN_COST ≈ 85 ms × 2 it
  needs a `tls` budget above the 0.25 per-PD cap. Widening
  HS_KEY_WAIT_MAX_NS to fit would be the workaround the rule forbids.
  The plan is re-planned (amendment "Re-plan R1"): the TLS signing key
  moves out of `key` into its own key PD, so `hs` can no longer wait on a
  TLS signature at all.

## Slice 3c (C12: tlskey, key reverted, third envelope, single-caller law)

Gates run (all exit 0): make pins, lint, lint-pds, unit, laws, image,
uboot, ct, ct-shape; tests/tools test_measure, test_package, test_release,
test_ct_shape, test_check_pins, test_check_selftest. Not run (by the
slice's rules): Kani, Verus, make test/check, QEMU, check-selftest, bolero,
mir, repro. The tpm2-wire harnesses were type-checked under `--cfg kani`
against a throwaway shim (deleted). Red-proofs on throwaway copies under
build/ (deleted): every new or retargeted `unit`/`laws` selftest case fails
with its needle (c5-tls-static-dh, c5-k-prime, c5-nonce-cap, c5-cv-content,
c5-d5-codes, c5-syn-burst, c5-syn-interval, c12-gate-busy, c12-seed-scalar,
c12-envelope-kind, c12-sign-halt, laws-hs-tls-share-key), and every one of
the 179 injections still finds its anchor exactly once.

Cargo.lock, one change: `limits`, `tlskey-core` and `pd-tlskey` added;
ingress-core → limits; key-core loses libcrux-p256, rfc6979 and sha2 (they
move to tlskey-core, which also takes ct, limits, secret-blob, tpm2 and
zeroize); pd-tls swaps key-core for tlskey-core. No external package
added or removed. tools/ct-harness/Cargo.lock unchanged.

Decisions:

- **key reverts byte for byte.** key-core, hs-core and pds/key are their
  pre-slice-2 (M5) sources; key-core's Cargo.toml is M5's. secret-blob's
  `key` blob is v2 again, keeping the named offsets (GATEWAY_PRIVATE_AT,
  BOOT_SEED_AT) run.py reads; a v3 blob (with a scalar) is refused by a
  test. `hs` keeps KeyWaitHighWater (observability, its comment updated).
- **tlskey's codes:** `CODE_BASE` 0x40; a failure `key` has too keeps
  `key`'s number above the base (unseal and blob codes, RNDR 0x49);
  ScalarInvalid 0x47 and Mismatch 0x48 take GatewayKeyMismatch's and
  PeerMismatch's places; 0x4a stays unused (no seed derivation can fail:
  the per-boot seed is `secret_blob::blake2s`, infallible). The collision
  test is in tlskey-core (own range, distinct); disjointness from key-core
  is run.py's code-table mirror (`check_key_code_tables_apart`, a new
  single case: no dependency edge between the crates).
- **The plaintext wipe is tlskey-core's, not the PD's.** `Oracle::boot`
  takes the region mutably and zeroizes it on any of its failures before
  returning, so the plan's "plaintext wiped each time" is unit-tested (one
  test per code); the PD only unseals, calls boot, and scrubs its stack
  once boot returned (covering the unseal and the scalar check) and after
  every `TLS_SIGN`-labelled call. `tlskey-wipe` removes that zeroize.
- **The TLS blob's reserved word** other than zero is `BadVersion` (the
  header word as a whole), not a new BlobError variant: one would have
  changed `key`'s and `pqkey`'s code tables.
- **BootSeed** answers the per-boot seed itself (one caller: no tag), and
  is charged to the bucket (TLS_BOOT_CALLS 1, as in slice 2).
  `Bucket::default()` is `tls`'s production bucket.
- **tls's halt reasons moved to `tls_core::halt`** with `after_sign`, so the
  sign-path halt (unreachable in practice now that an Unavailable tlskey
  halts tls at init) keeps a red-provable control: a tls-core unit test and
  `c12-sign-halt` (R2-T N8). run.py's `halt_reason("tls", …)` reads it
  there.
- **Gate:** Busy comes after `check_auth` (the last validity/ownership
  check) and before `once()`; `Gate` derives Clone/PartialEq/Eq so the unit
  test and the busy harness compare the whole gate before and after a Busy.
  `refusal_code` gives Busy 9 for exhaustiveness; the PD answers it
  RSP_BUSY. tpm2's FakePpc and swtpm_interop's PD model use the gate's Busy
  (the model now runs three client threads).
- **BUSY_TIMEOUT_NS** = FLOW_MAX_NS (M5's 120 s for one flow at the smallest
  key PD budget, pqkey's 0.1) × (CLIENTS − 1) = 240 s.
- **check-pins:** P17 retired; the rules keep their names (P18, P19 not
  renumbered), CHECK-PINS-RULES 19 → 18. key-core stays in P9/P10 (it still
  holds Key32 secrets); P11's key-core set is replaced by tlskey-core's
  (anchor src/lib.rs) and pds/tlskey's.
- **ct-shape:** pd-tlskey's 20 baseline entries are pd-key's (identical
  shapes, justifications carried over); pd-key's own entries did not change
  (its open_sealed closure is the same). Evidence the sign path left `key`:
  `nm` finds 0 `ecdsa_sign`/`sign_rfc6979` symbols in pd-key.elf, 3 in
  pd-tlskey.elf. The "no Verus symbols" check covers pd-tlskey through the
  Makefile's `pds` list. One fixture added (a call into tlskey's open past
  its root).
- **mksecrets:** `tls-secrets.bin` (its boot seed drawn on its own) and,
  with --tls-mismatch-blob, `tls-secrets-mismatch.bin` (renamed from
  `secrets-tls-mismatch.bin`: it is a TLS blob now, same boot seed, another
  valid scalar).
- **limits:** its tests read ingress-core's source (re-export present, no
  own definition, the per-source bucket within the global one), as the
  crate is a dependency-free leaf.
- **Descriptor chain (delegated part):** the on-device "range-2 wrap"
  refusal uses (image_len − 0x10, 0x20), which only range 2's
  `len <= image_len − offset` line refuses (a true 64-bit wrap is the 32-bit
  loop's, still pinned by range 0's case); on-device refusals for the 0-1
  overlap and a version-1 descriptor were added so that each dropped
  boot.cmd line has a case that fails (selftests measure-pair-01/-02/-12,
  measure-range2-wrap, measure-version); package-waiver gains TLS_SECRETS.
- **run.py:** KEY_CALLERS (tls → tlskey-core), the code tables read with
  CODE_BASE, three-key dicts for the sealed and proxy cases, the cap wait
  and the proxy's relay boot also wait for `tls: ready`, proxy counts 3;
  boot 6 fails if tls audits KeyUnavailable and waits for its ready; case 8
  packages a's key blob with the mismatched TLS blob and asserts the init
  halt before ready (failure-only alternation), HTTPS refused, the VPN
  handshake, the scan, and PCR 8 read as capped after the boot.
  INTEGRATION-CASES 54 → 60 (five measure-variant refusals, the code-table
  case), computed, not run.
- **Case 12 is not in run.py** (the `https-contention` boot belongs to slice
  5's hardening boots, with the multi-source probe); its amended form
  (positive availability only, KeyWaitHighWater recorded) is slice 5's.

Selftest migration:

- Retargeted to tlskey-core: c5-tls-static-dh, c5-k-prime, c5-nonce-cap,
  c5-cv-content, c5-d5-codes (now the own-range test), c5-syn-burst,
  c5-syn-interval (needles say C12), tls-scalar-scrub (pds/tlskey).
- Removed, subject gone: c5-caller-bucket (one caller per key PD),
  c5-sign-wait (SIGN_COST_NS and the wait invariant retired), c5-seed-tag
  (no per-caller seed), c5-tls-boot-fail (a TLS failure is tlskey's whole
  boot failure now, tested per code), c5-tls-wipe (parse_checking_tls gone;
  the wipe is tlskey-wipe's), c5-lock-pin (P17 retired), and P17's three
  check-pins fixtures.
- Re-anchored: key-wipe (M5's key PD), measure-wrap (six-value loop),
  tls-key-halt (tls's init halt).
- New: laws-hs-tls-share-key, tlskey-wipe, c12-gate-busy, c12-seed-scalar,
  c12-envelope-kind, c12-sign-halt, measure-pair-01, measure-pair-02,
  measure-pair-12, measure-range2-wrap, measure-version.

### Slice 3c verification (orchestrator)

- Gates green (pins, lint, lint-pds, unit, laws, image, uboot, ct,
  ct-shape; tests/tools suites). Full integration 60/60 on gx10 at the
  first run: three-envelope measured boot with descriptor v2 (five
  on-device refusals), case 8 (TLS-only key failure: tls halts before
  listening, VPN up, rejected scalar absent, PCR 8 capped), TLS interop,
  residue. Probe: max handshake 1.67 s (limit 3.33 s), TlsSignHighWater
  up to 1.24 s, now on `tls`'s own budget only.
- Selftest: 29 new or retargeted cases red with their needles
  (laws-hs-tls-share-key, c12-*, c5-* retargets, measure-pair-*,
  measure-range2-wrap, measure-version, measure-wrap, key-wipe,
  tls-key-halt, c8-head-wipe, tls-scalar-scrub, tlskey-wipe,
  https-probe-canary, and slice 3b's conn/ct/identity cases).
- tpm2-wire's six changed or new Kani harnesses were queued on z1mn
  (memory-guarded, alone) at commit time; the full Kani suite follows the
  lock change. Results are recorded with slice 4.

## Slice 4 part 2: C4 and the C10 core merged

Built in parallel worktrees (C4 on wip/m6-inner, the C10 core on
wip/m6-proxy on top) while slice 3c ran, merged after it. Two trivial
conflicts (both sides appended); Cargo.lock gains only `tls-core →
http-wire`. Gates green; selftest c4-{inner-src, inner-port-range,
tln-dst-ip, tln-dst-port, tln-src-port-range} and proxy-{truncation-rst,
early-client-fin, 413-no-connect, connect-timeout-wipe} red with their
needles. inner-core's two new Kani harnesses passed on z1mn.

Decisions recorded from the two reports:
- C4: inner's refusals of `tln` packets reuse `DropReason::TcpEgressRefused`
  (the audit line's `src=inner` separates them from ingress's); inbound
  segments that do not match stay `NoService`.
- C10: 502 Bad Gateway for every backend-unavailable cause (refused, reset
  while connecting, 5 s connect timeout), with `BackendUnavailable` and the
  timeout stage recorded; a backend RST after connect is always a client
  RST without close_notify; exactly Content-Length body bytes go to the
  backend and anything after is wiped; the head is wiped as soon as it is
  rewritten (so c8-head-wipe's mutation must also remove that wipe once
  the PD drives the proxy); a client half-close aborts both sockets.
- **http-wire Kani:** the whole-head harness over 32 symbolic field bytes
  timed out at 90 minutes on z1mn (memory fine). It is split into
  field-line, request-line and Connection-value harnesses plus a whole-head
  harness over a fixed request line and 16 field bytes (at most 2 fields).
  Transfer-Encoding, duplicate Content-Length and Content-Length values are
  covered by unit tests and bolero. KANI-HTTP-WIRE 4 → 7.

## Slice 4 part 3: the proxy in the PD (C3 inside, C8, C10)

Gates run by the implementer (each exit 0): make pins, lint, lint-pds,
unit, laws, image; tests/tools test_check_selftest, test_harness_signals,
test_stack_headroom. Not run (by the slice's rules): Kani, Verus, make
test/check, QEMU/run.py, check-selftest, ct, ct-shape, mir, bolero. Every
integration case and `test`-gate selftest case below is unrun; every one
of the 192 selftest injections finds its anchor exactly once (checked on a
copy). Root Cargo.lock unchanged.

Decisions:

- **`BackendUnavailable` is a fixed, coalesced audit kind, code 0x0059**
  (FIXED 61 → 62, its own counter slot): attacker-drivable (a backend kept
  down), so coalesced like the other `tls` kinds. `audit` names fixed kinds
  through `Event::name`; no audit PD change was needed.
- **`Slot::backend_rst_pending()`** (tls-core, unit-tested): a clean close
  aborts the backend while the client still drains close_notify, so the PD
  removes the backend socket and wipes its storage when the backend's RST
  wait ends, not only at the slot's Release. The decision (dispatched, or
  eight passes) stays `conn`'s.
- **One device type over both links.** `Link` holds a ring pair, its
  buffers and its own RST log; `Dev` lends it to one poll together with
  the PD's single `Audit` (moved out of the outside device). The outside
  log records client RSTs from the HTTPS port by client; the inside log
  records RSTs to the backend by (backend address, our source port).
- **Inside interface:** `INSIDE_IP`/32 with a default route to itself (as
  outside: `inner` frames every segment to the backend's neighbour entry);
  its own ISN seed from the hedged RNG. Backend sockets: rx 8 KiB, tx
  16 KiB, Nagle and delayed ACK off, no smoltcp timeout (the slot's
  connect, idle and lifetime timers bound them); the local address is
  given explicitly.
- **Ports:** round-robin over `TLS_PORTS`, skipping a port another backend
  socket still holds. A socket that cannot be made is the backend being
  unavailable: `backend_rst` in BackendConnect, so 502.
- **Flow control:** a client record is handed over only while
  `reads_client()`, and after the handshake only with `MAX_CLIENT_OUT` free
  on the client socket (during the handshake the flight fits the empty
  buffer, checked as before). Backend chunks, the backend's FIN and its
  close without one wait for the same room. `timers` runs every pass,
  ungated: it writes only in BackendConnect (502), when nothing else is
  queued; a send that does not fit becomes `error()` (a client RST).
- **Backend events:** connected = `may_send()` (Established or CloseWait,
  so a backend that FINs right after connecting ends with close_notify
  after an empty response rather than a 502); the FIN is remembered when
  seen; the FIN and a close without one (RST, refused connect, smoltcp
  timeout: state Closed) are reported only once the receive queue is
  empty, so bytes received before a RST still reach the client before its
  RST. The client's FIN is reported only with no complete record waiting.
- **Stack scrubs:** after every client record (as before), and after every
  other slot call that sealed records (`to_client` > 0: backend chunks,
  close_notify, a 502), from the calling frame through an inlined helper.
  They replace the slice-3b scrubs after the fixed response and its
  close_notify, which are gone with the fixed-response path.
- **413 without connect at PD level** has no PD control of its own: the
  PD opens a backend socket only on `Next.connect`, the head-time decision
  is `conn`'s (proxy-413-no-connect); the integration case asserts the
  backend's connection count unchanged. The backend socket's storage wipe
  stays the declared gap (T-R7-1), one call site (`release_backend`).

run.py:

- **Inside NIC on a tap (`tapi0`) for the https boots only**: the kernel
  end is the backend host (neighbors[0]: 10.99.0.2, its MAC), the
  gateway's inside MAC static; `net.ipv4.ip_forward` is read and must be 0
  (not written). The VPN boots and the tls-key-failure boot keep the dgram
  inside host. check_harness_matches_config gains `gateway.backend`.
- **Raw backend:** a listener thread and one thread per connection, which
  owns the socket; the test's sends, FIN and SO_LINGER-0 reset are queued
  to that thread (a close from another thread while it blocks in a read
  would not send the RST). Each connection logs its peer, every byte, and
  how it ended. Unheld connections get `backend_response` once the request
  is complete (GET: a 24.7 KB binary body, six server records, so its FIN
  arrives while earlier bytes still wait for client room; POST: the body
  echoed, its SHA-256 above 16 KiB), then FIN.
- **Exact-byte requests from Python's ssl** (OpenSSL 3.5.7's default
  groups offer an X25519MLKEM768 key share; checked against s_server
  without HelloRetryRequest), verifying the dev CA and the IP name.
  s_client and curl stay for case 1 (negotiated group, chain, name), the
  probe and case 13's `-msg` output.
- **Case 2:** the backend's bytes compared with a literal of `rewrite`'s
  output for a head carrying every dropped field kind; POST bodies of 0, 1
  and MAX_BODY bytes followed by a pipelined request must arrive as
  exactly the rewritten head and the body (timeout: the 120 s lifetime);
  MAX_BODY + 1 through curl `-H 'Expect:'` must answer 413 (curl may also
  report its upload cut short), audit `HttpRefused(413) total=1`, no
  backend connection.
- **Case 5:** the spoofed `Forwarded` is not refused (http-wire drops it):
  its "status" is 200 with the field absent from the backend log. Each
  refusal is followed by a valid request that must be the backend's only
  new connection.
- **Case 6** also has the allow side (a head of exactly 8 KiB proxied).
- **Case 13:** s_client `-msg` must end its read with `read:errno=104`
  and print no received close_notify (checked in one wait, so a hidden
  truncation fails by name), and the sniffer must see the server's RST;
  the client FIN is a TCP FIN without close_notify (`SSLSocket.shutdown`)
  after the response started, and the backend must see ECONNRESET.
- **https-residue barriers on the backend log (C8):** connection A's head
  (with the Keep-Alive marker) and first body part logged → scan: both
  handshake secrets and the marker absent (the head is wiped once
  rewritten), client secret 0 present; `k`, the second part logged → client
  secret 0 absent, 1 present; `K`, the third part logged and the backend's
  first response bytes received (sent after our KeyUpdate) → server secret
  0 and client secret 1 absent, server secret 1 and client secret 2
  present; then the backend finishes, the abort RST and the barrier SYN →
  every secret form of A and the marker absent. The control B is opened
  only after the third scan (its idle timeout and lifetime, read from the
  Rust source, must not pass before the last scan; checked by name) and
  held in response streaming. **B's own marker is asserted absent**, not
  present: with the head wiped at rewrite (part 2's decision) a live
  connection's marker no longer exists in `tls`, so the "marker present"
  control the plan describes cannot exist without undoing that wipe; the
  scan's control is B's CLIENT_TRAFFIC_SECRET_0. Both markers must be
  absent from the backend log. Body parts avoid s_client's command
  letters (each write's first byte).
- **test_harness_signals:** its teardown-on-entry fixture executes every
  real teardown; its environment gains `backend` and `inside` (None).
- INTEGRATION-CASES 60 → 70: https proxy rewrite, https post bodies,
  https body 413 at head time, https smuggling refused, https head 431,
  https backend reset truncates, https client fin aborts backend, https
  residue handshake secrets, https residue client key update, https
  residue server key update.

Selftest (manifest has no per-case key):

- `c8-head-wipe` also removes the proxy's early head wipe; its needle is
  now "marker still in guest RAM" (the first scan that sees it, any
  connection).
- New `test` cases on boot `https` (unproven, QEMU not run):
  `proxy-pd-backend-room` (the PD marks more as sent than the backend
  socket took), `proxy-pd-fin-drain` (FIN reported with bytes still
  queued), `proxy-pd-backend-rst` (a close without FIN reported as a FIN),
  `proxy-pd-client-fin` (the client's FIN not reported).

Manifest: UNIT-TESTS 1200 → 1202, UNIT-AUDIT-EVENT 47 → 48,
UNIT-TLS-CORE 94 → 95, INTEGRATION-CASES 60 → 70.

### Slice 4 part 3 verification (orchestrator)

- ct-harness's lock needed the `http-wire` edge the C10 merge added (its
  own lock); `make package` depends on it.
- Integration `https` + `https residue`: 21/21 through the proxy (backend
  bytes exact, POST bodies, 413 at head time, smuggling refusals, 431,
  backend reset truncation, client FIN abort, residue via backend-log
  barriers).
- **The `ip_forward` check is removed.** `/proc/sys` is read-only in the
  container (in the test netns too), so it can be neither set nor relied
  on. The control that "nothing reaches the backend around the gateway"
  is the backend's peer-address assertion (every peer is the inside IP);
  client and backend share the netns, so a bypass would show another
  peer.
- **Two PD-level selftest cases replaced.** `proxy-pd-client-fin` and
  `proxy-pd-fin-drain` mutated code every normal close uses, so the first
  case failed before theirs. The early-client-FIN decision is red-proved
  in tls-core (`proxy-early-client-fin`). The FIN-after-drain decision
  moved into tls-core as `backend_end`, red-proved by `proxy-fin-drain`.
  The PD calling these on every close is shown by every integration case
  that closes normally.
- `c8-head-wipe` went red with its needle when run alone; its one failure
  inside a batch was the residue boot's first slowloris connect timing out
  (not reproduced; to be diagnosed if it recurs).

## Slice 5: hardening cases (cases 9, 10, 12, the concurrent probe)

Not run by the implementer (by the slice's rules): Kani, Verus, make
test/check, QEMU/run.py, check-selftest. Every integration case and
`test`-gate selftest case below is unrun. No production code changed;
root Cargo.lock unchanged.

Boot `https flood` (new), in order: case 10's recycling leg and the ninth
connection, case 10's per-source cap leg, the concurrent probe, then
Rosenpass for peer 1 (started after the probe so pq's exchange does not
overlap the RM6-8 measurement), case 12, case 9 last (its spoofed SYNs hold
listeners until their timeout).

Decisions:

- **Client sources are kernel sockets** bound to `CLIENT_IPS`
  (10.0.2.101-105/32 on the tap, removed with it), not spoofed TCP: the
  gateway frames every reply to the router MAC, so real TCP stacks complete
  handshakes from distinct sources. Five: MAX_CONNS / MAX_PER_SOURCE fill
  the table, one more is the ninth connection's (checked against the Rust
  constants by name). Case 9 uses the spoofing helper: `RpSpoof` is split
  into `Spoof` (any frames) and `RpSpoof(Spoof)`, behaviour unchanged.
- **VPN transport in an https boot:** the inside NIC is the backend tap, so
  its host answers peer 1's ping; a /32 route to peer 1's tunnel address
  via the gateway's inside address (removed with the tap).
- **Case 10 order:** the recycling leg runs first, on a fresh table, so a
  slot that fails to return is attributable; then the cap leg. Every slot
  used is awaited back (the server's abort RST, after which the PD
  releases and re-listens in the same pass) before the next leg.
- **Recycling red-proof differs from the plan.** "Without the abort
  (TIME-WAIT kept) a cycle fails" cannot hold as written: the cycling
  client closes after close_notify, so the server is the passive closer
  (no TIME-WAIT), and the PD re-creates the listener socket on every
  release, discarding any TCP state. The abort is red-proved by the
  per-cycle barrier instead: each cycle must see the server's abort RST
  before the next SYN, and each next SYN must be accepted first time (a
  refusal fails by name). `https-recycle-abort` replaces the PD's
  `s.abort()` with `s.close()`; the first cycle's barrier fails. The held
  connections' idle gaps and age are checked against IDLE_TIMEOUT_NS and
  LIFETIME_NS by name (T-R4-2).
- **Per-source refusal shape:** admission happens as the socket leaves
  Listen, so the abort's RST normally replaces the SYN-ACK
  (ECONNREFUSED); a reset or EOF before any TLS is accepted too. Either
  way the sniffer must see the server's RST, `TlsClosed(PerSource)
  total=1` is awaited and the backend sees nothing; a completed handshake
  fails ("the cap did not refuse it").
- **The ninth connection** is refused by smoltcp (no listening socket:
  RST to the SYN), with no audit: asserted by ECONNREFUSED, the sniffed
  RST and no backend connection.
- **Concurrent probe (RM6-8):** MAX_CONNS handshakes from four sources
  started together, each then fetching the backend's response. No timing
  gate: per-handshake times, failures (a server handshake timeout under
  TCG), whether `TlsTimeout(Handshake)` was audited and TlsSignHighWater
  are printed as RM6-8's measured value for D3. It fails only if a client
  gets no slot (the probe would not hold MAX_CONNS), a response differs,
  or a connection ends without the server's RST.
- **Case 12:** the ClientHello is captured on the tap from one verified
  Python (OpenSSL 3.5) exchange, reassembled from the sniffed segments.
  A flood connection counts a flight when the server's first byte is a
  handshake record (`tls` builds the whole flight, signature included,
  before sending any of it), then is reset so its slot frees. Overlap:
  MAX_CONNS flights before the WireGuard handshake starts (bounded by
  MAX_CONNS × a third of the handshake timeout, the probe's gate, plus
  10 s) and one more after it completes. An unloaded handshake first
  proves pq's key reached `hs`; KeyWaitHighWater before and during the
  flood is printed, not asserted.
- **Case 9:** 200 SYN/s from 256 spoofed sources: each source well under
  its SYN refill and the total over twice the global refill (checked by
  name). The case awaits a `TcpLimited(SynGlobal)` line with total ≥ 65
  since the flood began (≥ 64 refusals), then, the flood still running and
  verified at the judgment, a WireGuard handshake and a ping through it.
- **Two unit-gate selftest cases fill gaps:** the plan has case 9 rely on
  ingress-core unit red-proofs, but only the per-source SYN bucket had
  one; and the plan's mutation list names the per-source cap, which had
  none. Both red-proved on a throwaway copy (needles printed; copy
  deleted).

Selftest (new): `c2-syn-global-bucket` (unit; "---- tests::syns_from_many_
sources_get_the_global_burst_and_then_are_limited stdout ----"),
`conn-per-source-cap` (unit; "---- tests::per_source_cap_admits_two_and_
another_source_still_gets_a_slot stdout ----"), and on boot `https flood`
(unproven): `https-syn-flood` (global SYN bucket removed; "the flood did
not cross the global SYN bucket"), `https-per-source-cap` (cap removed in
tls-core; "the cap did not refuse it"), `https-recycle-abort` (above;
"the server's abort: no RST from the server to port").

Manifest: INTEGRATION-CASES 70 → 76 (https slot recycling, https ninth
connection refused, https per-source cap, https concurrent probe, https
clienthello flood, https syn flood).

### Slice 5 verification (orchestrator)

- Boot `https flood` 6/6: slot recycling (9 server-closed cycles, 7 held
  alive), ninth connection RST, per-source cap (TlsClosed(PerSource)),
  the concurrent probe, the ClientHello flood with a WireGuard handshake,
  the spoofed SYN flood (TcpLimited(SynGlobal) past 65) with a WireGuard
  handshake and a tunnel ping. Selftest c2-syn-global-bucket,
  conn-per-source-cap, https-syn-flood, https-per-source-cap,
  https-recycle-abort red with their needles.
- **RM6-8 measured:** eight concurrent handshakes from four sources all
  completed in 3.48 s under TCG (handshake timeout 10 s); none timed out.
  D3 does not bind.
- Case 9's spoofer was judged right after it started (nothing scheduled
  yet); it now waits for the first second's frames on the tap
  (`wait_delivered`) before the judgment loop.
- The ct pass record must be refreshed after any tls-core change (the
  harness links tls-core since slice 3b).

## Phase 2 self-check fixes

Not run by the implementer (by the step's rules): Kani, Verus, make
test/check, QEMU/run.py, check-selftest. The run.py edits and every
`test`-gate selftest case below are unrun. Root Cargo.lock changes once
(new package `secret`; edges pqkey-core → ct, rosenpass-core → ct and
secret, tls-core → secret, tpm2 → secret), so the Kani cache keys change.
tools/ct-harness/Cargo.lock: package `secret`, tls-core and tpm2 → secret,
ct-harness → tls-wire.

Decisions:

- **One constant-time compare.** `rosenpass_core::crypto::ct_eq` is
  `pub use ct::ct_eq` (callers unchanged); pqkey-core's private
  fixed-size copy is gone, its two boot checks call `ct::ct_eq`. ct's doc
  names every user, direct and through the wg-core/rosenpass-core
  re-exports.
- **One secret container, crate `secret`** (zeroize =1.8.1 only):
  `Secret<N>` with the union of the three APIs (`zero` const,
  `from_bytes`, `copy_from`, `as_bytes`/`as_mut_bytes`, rosenpass-core's
  `expose`/`expose_mut`, `wipe`, `is_zero`, `ZeroizeOnDrop`) and `wipe`.
  tpm2 and rosenpass-core re-export `Secret`, tls-core `Secret` and `wipe`,
  so every path callers use still resolves. Not Clone/Copy/Debug is pinned
  by three compile_fail doctests in the crate. **Deviation:**
  rosenpass-core's `Secret::ct_eq` method is dropped, not carried over: it
  had no caller in any tree, and keeping it would give `secret` a ct edge
  against the leaf's dependency rule (every compare goes through
  `crypto::ct_eq` on `expose()`). check-pins P9/P10 cover `crates/secret`
  (SECRET_CRATES), with a fixture each (CHECK-PINS-FIXTURES 255 → 257).
- **The handshake's scrub now covers the hybrid secret's whole life
  (essential fix, Critical tier).** The new residue case (below) drove a
  ClientHello through `Session::on_record` with the old placement (scrub
  right after `HybridSecret::exchange`) and no scrub after the call: kem-ss,
  x-ss and kem-g hit at about 9 KiB below the caller. The exchange's frames
  were clean; the copies came after the scrub: the destructuring move of
  `exchanged?`, the move into `KeySchedule::new`, and HKDF-Extract's HMAC
  block over the IKM. In the PD the post-call `scrub_if_sealed` covered
  them whenever the call sealed records; tls-core itself guaranteed
  nothing. The exchange, ServerHello and `KeySchedule::new` now run in
  `handshake::hello_keys` (`#[inline(never)]`), and `on_hello_record` calls
  `scrub_session_stack()` as soon as it returns, Ok or Err; only the
  schedule leaves it. Measured depth of the whole ClientHello call below
  the caller: 50312 bytes, all scrubbed (hello case clean with no scrub
  after the call). `SCRUB_DEPTH_EXCHANGE` unchanged.
- **Residue case `hello` (C7 at its production call site).** The same
  client share and randomness as the `exchange` case, a ClientHello built
  from tls-wire's constants, the randomness replayed through the `Rng`
  seam, a fixed public signature; session and buffers on the heap; the
  harness scrubs nothing after `on_record`. Needles: the `exchange` case's
  (eph raw and clamped, kem-rand, kem-g, kem-ss, x-ss). Output checked:
  Flight, every drawn byte consumed, the ServerHello's share equal to the
  direct exchange's. RESIDUE-CASES 30 → 31. Red-proved on a throwaway
  copy: without the production scrub, kem-rand, kem-g, kem-ss and x-ss hit
  in case hello. With the old placement plus a PD-style scrub after the
  call, removing the production scrub stayed green (the post-call scrub
  reached the exchange's frames in the harness's layout), which is why the
  harness adds none.
- **ct-shape identity: zero-size object symbols name nothing (tool fix).**
  After the pqkey-core change, pd-pqkey's `mce460896::hash_32b` referenced
  an unnamed panic Location at 0x2029a8 that the zero-sized static
  `log::logger::NOP` shares (the linker places a ZST where the next data
  starts); the normaliser printed `<log::logger::NOP>` against the
  harness's `<addr>`. A false identity failure from layout, not code.
  `Binary` no longer takes zero-size OBJECT symbols as labels (they own
  no bytes); sized symbols and zero-size non-object labels are unchanged.
  Fixture "a zero-size object symbol names no address" (red without the
  fix; CT-SHAPE-FIXTURES 64 → 65). **No policy/ct-shape.toml entry
  changed**: every baseline shape and identity root held (CT-SHAPE-SYMBOLS
  158); the moved `Secret` drops are inlined or outside the closures.
- **audit-event: no clamping onto a real code.** `TlsRefused` fills all 32
  codes of its range, so neither clamping nor capping at 31 variants is
  possible without merging refusals. A value above 31 of any `tls` kind
  now encodes to `TLS_KIND_UNKNOWN` (0x02a0, after the four ranges, in no
  name table) and counts in its own coalescing slot; it decodes as
  `Decoded::Unknown`, which `audit` prints as an unknown code. Tests: the
  per-kind check (0x20, 0x21, 0xffff → unknown; 0x1f still the range's
  last) and the separate count; both red on a scratch copy with the old
  clamp. Completeness: tls-wire `refusal_all_lists_every_variant_once`
  and http-wire `status_all_lists_every_variant_once` (an exhaustive
  position match against ALL's indices and its last). `http_wire::Status::ALL`
  is new and pd-tls's `names_match` uses it.
- **run.py.** `tls key failure` waits for any `Halted reason=(\d+)` of
  `tls` and fails "tls halted with reason=N, want KEY_UNAVAILABLE (M)".
  The POST loop catches a failed exchange whose backend holds the
  forwarded head and part of the body and fails "the POST body of N bytes
  stalled after K bytes at the backend"; any other failure is re-raised as
  it was. The wrong-CA and wrong-name curls must exit 60
  (CURLE_PEER_FAILED_VERIFICATION) or print a verification error; else
  "https a wrong CA|a wrong name: curl failed with exit N, not on
  certificate verification".
- `pds/audit`'s `TcpLimited` arm uses `named()` (same line format);
  laws.toml's comment lists `tls` among `timer`'s notify targets.

Selftest (new): `tls-hello-scrub` (ct; the production
`scrub_session_stack();` after `hello_keys` removed; regex: both
"RESIDUE-HIT kem-ss case=hello " and "RESIDUE-HIT x-ss case=hello "),
`bolero-tls-wire` and `bolero-http-wire` (bolero; injected panic on inputs
of 20 bytes or more; "selftest-bolero-tls-injected",
"selftest-bolero-http-injected"; both red on a scratch copy). Changed:
`tls-key-halt` (needle "tls key failure: tls halted with reason="),
`proxy-pd-backend-room` (the broad "https post 1048576: " replaced by
"https post: the POST body of 1048576 bytes stalled after "),
`tls-exchange-residue` (comment only: the production call site has its own
case).

Manifest: UNIT-TESTS 1203 → 1213, UNIT-SECRET 7 (new), UNIT-AUDIT-EVENT
48 → 49, UNIT-TLS-WIRE 55 → 56, UNIT-HTTP-WIRE 64 → 65, LINT-CRATES 29 → 30,
CHECK-PINS-FIXTURES 255 → 257, CT-SHAPE-FIXTURES 64 → 65, RESIDUE-CASES
30 → 31.

## Phase 3 round 1 fixes

Code review round 1 (docs/archive/review/secureos-m6-https-proxy-code-review.md).
Gates run by the implementer: make pins/lint/lint-pds/unit/laws/image/ct/
ct-shape/bolero/mir. Not run (by the round's rules): Kani, Verus, make
test/check, check-selftest. Unit- and ct-gate selftest cases below were
red-proved on a throwaway copy; `test`-gate cases are written but unrun.

- **F1, a reset listener's new client (security).** smoltcp puts a socket
  reset in SYN-RECEIVED back to Listen, and a SYN in the same ingress batch
  takes it again before the pass's `serve` sees Listen; the new client
  inherited the admitted slot, its source (X-Forwarded-For) and its
  per-source count. `Conn::serve` now treats the client as gone also when
  the socket's remote endpoint is not the admitted `l.peer` (address and
  port), or is None outside Closed/Listen, and retargets `l.peer` to the
  current endpoint first, so the abort's RST to the new client is the one
  `after_egress` awaits. Normal handshakes are unchanged (the endpoint
  equals the admitted one). The comment that claimed Listen alone caught it
  is rewritten. Integration case `https rst inherit` (residue boot, after
  slowloris so its PeerReset line is the boot's first, total=1): SYN from
  10.0.2.78:52000 answered, then its RST (seq ISN + 1) and a SYN from
  10.0.2.79:52001 in one burst; wants a RST to 52001, TlsClosed(PeerReset)
  and no backend connection. If the two segments were taken in different
  passes the case fails naming whether p2 got a SYN-ACK. Selftest
  `https-rst-inherit` (endpoint check removed).
- **F2.** `Slot::error` on a Draining or Lingering slot (the unsent bytes
  were its close_notify or alert) aborts it, with TlsClosed(Error), instead
  of doing nothing until the linger or idle bound.
- **F3.** A ClientHello with more than `MAX_EXTENSIONS` extensions is
  `Refusal::Decode`, not `DuplicateExtension`.
- **F4.** Stale `key`/`TlsKeyMismatch`/128 KiB references now name `tlskey`,
  its `Mismatch` (code 8) and the 192 KiB stack.
- **F5, `TX_BUF` 8 → 9 KiB (C10 said 8 KiB).** The client send buffer holds
  two `MAX_CLIENT_OUT` (4169 B) writes, so a record can be queued while the
  previous one is unacknowledged; asserted (`2 * MAX_CLIENT_OUT <= TX_BUF`).
  +8 KiB static over eight connections, inside `TLS_STATE_MAX` (1 MiB,
  asserted).
- **S1, the inside TX tier.** `inner_core::from_tls` takes the inside TX
  ring's free count and refuses (`FromTls::TxReserve`, audited as
  `TxNoBuffer`, as `ingress` audits its `TxReserve`) unless more than
  `INNER_TX_RESERVE` (NET_BUFFERS / 2) + `TLS_TX_SHARE_INSIDE` (16) buffers
  are free, refusing at equality; the share is asserted inside the range at
  compile time, and inner-core's own `NET_BUFFERS` is asserted equal to
  layout's in pd-inner. pd-inner's `drain_tls` takes at most `TLS_DRAIN`
  (layout::NET_BUFFERS) segments per notification through `ring::pass::drain`
  (pd-inner now depends on `ring`): `tls` runs at `inner`'s priority and can
  refill `tln` while it is drained. The bound is `drain`'s, red-proved by
  `unbounded-drain`; a PD-constant mutation needs QEMU, so no separate
  unit-level case exists for it. Unit pair at the boundary; selftest
  `s1-inner-tls-tier`. The inner-core Kani harness passes a symbolic
  `tx_free` (unrun here).
- **S2, check-pins P20.** `exchange_with_randomness` may be named only in
  hybrid.rs, tls-core's unit tests (src/tests.rs, which call it with fixed
  randomness) and tools/ct-harness/, plus tls-core's `pub use hybrid::{..}`
  re-export. Three deny fixtures (a call in pds/tls, an aliased import in
  tls-core, a call beside the re-export) and two allow fixtures (the
  harness and a comment; tls-core's tests); the two unterminated-literal
  fixtures now also expect P20, which lexes every source it reads.
- **S3.** The RFC 6979 candidate refusal probability is ≈ 2^-32 per
  candidate (P-256's order lies ≈ 2^224 below 2^256), ≈ 2^-256 for the
  8-candidate cap; code and plan corrected.
- **S4.** `rewrite` drops True-Client-IP, X-Client-IP, X-Cluster-Client-IP,
  CF-Connecting-IP, Fastly-Client-IP, X-Original-Forwarded-For and
  Client-IP. Unit pair: each (either case) rewrites byte for byte as the
  head without it; `X-Client-IP-Hint` passes unchanged. The rewrite Kani
  harness's dropped-field loop grows from 8 to 15 names (unrun here).
- **S5.** mkcert's docstring: a permitted dNSName subtree is NAME and its
  subdomains.
- **T1.** MIR-CRATES 9 → 10: `make mir` checks http-wire since its Kani
  enrolment.
- **T2.** Selftest `c2-tcp-offset` (the data-offset rule removed and the
  options/payload `get` refusals made lenient, so the named test reddens)
  and `c2-tls-egress-syn` (tls_egress's bare-SYN refusal removed).
- **T3.** Selftest `residue-secret-drop` (`Secret`'s drop-time zeroize
  removed) and `residue-wipe-state` (the read/write traffic secret wipes in
  `wipe_state` removed), both on the residue boot, needles only the scan's
  absence failure prints; the live controls are asserted first.
- **T4.** A failed slowloris connect names the SYNs that crossed the tap,
  the gateway's answers, the sniffer's drops and the TcpLimited/TlsClosed
  audits since boot; no retry or wait.
- **T5, `SCRUB_DEPTH_EXCHANGE` 48 → 52 KiB (measured).** `hello_keys` is
  `pub` (doc: for the ct-harness only) and the residue mode's `hello-depth`
  run calls it from the closure frame with no scrub after: 35 912 B below
  that frame against 34 040 B for the exchange alone, 27 % headroom under
  48 KiB, so the constant is 52 KiB (31 %). The `tls` stack high-water was
  128 752 B of 196 608 B in the last https boot (s4p), so the 4 KiB stays
  well inside STACK_HEADROOM_MIN. No scrub cost was documented, so none is
  re-measured. RESIDUE-CASES 31 → 32; selftest `tls-hello-scrub-depth`
  (constant 34 KiB: only `hello-depth` exceeds it); `tls-exchange-scrub-depth`'s
  anchor follows the new value.
- **T6.** The rewrite harness's doc and this log's Slice 4 part 1 entry
  state its real bounds (fixed request line, ≤ 16 symbolic field bytes,
  ≤ 2 fields); the harness body is unchanged.
- **T7.** compile_fail doctests carry their error codes, each checked by
  compiling: E0599 (clone; the doctest now clones an owned value, since
  `.clone()` on a reference clones the reference and fails as E0308),
  E0382 (moved twice), E0423 (private constructor), E0277 (Default in
  tls-core, Debug in secret). `l14-clone`'s needle names the Clone doctest
  by its line, read from the source.
- **T8, T9.** The concurrent probe fails when no handshake completed and
  records a D3 breach when a handshake failed with TlsTimeout(Handshake)
  audited since its start. T9 was tried and rejected: TlsSignHighWater
  prints only on a new maximum, so a since-mark window over the sequential
  probe was empty on the gate run; the whole-boot maximum is the measurement.
- **T10.** `check_secret_forms`, run first in the residue case: run.py's
  `hkdf_expand_label` reproduces RFC 8448 section 3's server handshake key
  and IV (checked against the RFC text) and every ChaCha20 key and IV of
  tls-core's keylog fixture.
- **T11, integration cost.** Guest-RAM snapshots (2 GiB each) per https
  boot, from the code: https 1 (tls scalar count), https residue 4,
  https flood 0, tls key failure 1. Wall time per boot is not in the logs
  (build/s4p-it.log, build/s5-it.log carry no timestamps; their mtimes give
  only end times), so it is not recorded.
- **Environment.** M7 is QEMU-only (owner, 2026-10-24): VE10 (board timing:
  throughput and handshake under real hardware) and VE11 (RNDR quality on a
  board) cannot be verified in M6 or M7 and become residuals RM6-9 (VE10)
  and RM6-10 (VE11), open until a board exists; VE9 (browser/WebPKI) stays
  blocked-deferred.

#### Round 1 gate runs: VPN boots failing under a concurrent solver

Three `make test` runs of the round 1 tree failed in VPN boots that this
round did not touch:

- gx10: cookie boot a, "no ping reply through peer 2's session".
- gx10: rp gate boot, "the spoofed endpoint got no CookieReply under load".
- z1mn: rp gate boot, the same message.

Each of those runs shared its host with a cbmc process. On gx10 it was a
superseded http-wire harness loop that an earlier kill had missed; it ran
for 3 h. On z1mn it was the full Kani suite. A fourth run on gx10, started
after that loop was gone and with no solver on the host, passed both boots;
it then failed in the https boot on the T9 change, recorded under T9.

These rp and cookie cases are timing-sensitive (M3b). Integration runs
therefore share a host with no solver. Before a run, the host's process
list is checked for cbmc, kani-gate and cargo-kani.
