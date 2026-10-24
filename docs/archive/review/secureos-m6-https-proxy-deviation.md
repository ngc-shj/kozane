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
- The rewrite Kani harness is bounded at 64 bytes / 3 fields (its dropped-
  field check nests over the fields), below the plan's 96 B / 4 fields.

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
