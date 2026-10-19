# Coding Deviation Log: secureos-m2-5-cookies-keepalive

Implementation decisions not spelled out by plan rev 6, or departing from it.

## Batch 1a (C1, C2)

- **`cookie_key` and `crypto::mac16` return `Result`.** The plan's
  signatures had bare values. Both reuse `crypto::hash`/`mac`, which return
  `Result`, and the crate denies `unwrap`/`expect`. The error is
  unreachable in practice (only above 4 GiB of input).
- **Extra public items:**
  - `crypto::xaead_seal`: the XChaCha seal the plan named, with no
    signature given;
  - `crypto::XNONCE_LEN`;
  - `wg_wire::INITIATION_MAC2_OFFSET` (132);
  - `CookieSecret::new()` and `Default`, for clippy `new_without_default`.
- **Byte orders:**
  - the port is big-endian in the cookie;
  - the reply-nonce counter is little-endian in
    `HASH(secret ‖ counter)`;
  - receiver is little-endian (the wire format).
- **Oracle:** `tests/tools/cookie_vectors.py` is a pure-Python HChaCha20,
  self-checked against draft-irtf-cfrg-xchacha-03 §2.2.1 and §A.3.1,
  combined with `cryptography`'s ChaCha20Poly1305 and `hashlib.blake2s`.
  Its outputs are pinned in `crates/wg-core/src/tests_cookie.rs`.
- **The adapter-level deny test** (zero-key mac2 rejected through the real
  adapter) is batch 3's, in the ingress PD. Batch 1a pins the same
  property on the C1 functions.

## Batch 1b (ring, audit-event, C5 constants)

- **`Sender::in_flight()` / `free()` propagate `reclaim()` errors.**
  - On `BadDesc`, reclaim stops at the bad descriptor, so a count would be
    stale. They return the error instead.
  - The ingress PD (batch 3) treats such an error as "under load" and "no
    TX reserve", which fails safe.
- **New `Pool::mine_count()`**, the helper behind the two accessors.
- **Exact key calls per exit path** (hs-core test), with the bound 3
  unchanged:
  - 0 calls: BadInput, BadMac1;
  - 1 call:
    - es refused;
    - es zero DH;
    - enc_static decrypt;
    - UnknownPeer;
    - PeerOutOfRange;
  - 2 calls:
    - ss refused;
    - enc_timestamp decrypt;
    - Replay;
    - Flood;
    - Entropy;
    - IndexExhausted;
  - 3 calls: psk refused, NoBuffer, accept.

  The plan's "decrypt 2" splits in two: enc_static fails after 1 call,
  enc_timestamp after 2.
- **Audit codes** 0x0034..0x003b for the eight new events.
  `Event::is_coalesced()` lists every variant explicitly, so a new event
  must be classified. `FIXED_SLOTS` goes from 31 to 39.
- **Not changed:**
  - `crates/pds/audit` decodes generically;
  - the C5 cross-crate assertions are added once ingress-core's constants
    exist.

## Batch 2a (C7)

- **Promotion does not clear `unacked_since`.** Promotion moves the old
  `current` to `previous` and destroys nothing. The peer is still owed a
  reply, and the new `current` carries the keepalive.
  - "`current` dropped" in the plan is read as destroyed, i.e. `tick`
    expiry.
  - Pinned by `promotion_keeps_the_debt_and_the_new_current_carries_the_keepalive`.
- **`keepalive()` runs on every `data` notification,** not only on timer
  notifications. The timeout check never fires early; it can only fire
  sooner within the [10 s, 11 s) window.
- **A failed outbound seal leaves the state armed.** `keepalive()` disarms
  the peer if `current` still cannot seal at fire time.
- **A keepalive whose send to `ingress` fails** (ring full) is consumed,
  like a failed outbound send. It is not retried.
- **Keepalives are not audited.** No event exists, and the plan names none.

## Batch 2b (C3)

- **Two extra `Gate` fields and `take_expired()`;** `TickReport` has no
  `expired` field.
  - `in_load` is the last announced load state. It makes `WgUnderLoad` and
    `WgLoadCleared` strictly alternate.
  - `expired_edge` holds the backstop edge that `classify` raises.
  - Only `classify` can hit the 120 s backstop, since `tick` rotates at
    118 s, so the edge is taken like `take_load_entered()`.
- **`udp()` is folded into `respond`,** and `respond` takes a separate
  cookie buffer so it cannot alias the frame buffer. `classify` and
  `respond` carry `#[allow(clippy::too_many_arguments)]`, as hs-core does.
- **`ingress_core::NET_BUFFERS` is a local constant,** so `Cargo.lock` was
  not touched mid-batch. Equality with `layout::NET_BUFFERS` is asserted at
  compile time in hs-core's tests, and again in the ingress PD (batch 3).
- **`pass_plan.flush` counts frames moved.** The PD calls `audit.flush()`
  every pass regardless (a no-op when nothing is pending), so `tick` edges
  are flushed too.
- **The TX reserve threshold** is the private constant
  `TX_RESERVE = NET_BUFFERS / 2`. A reply needs `tx_free > TX_RESERVE`.
- **A clock going backwards:**
  - a secret born "in the future" counts as expired in `classify`, which
    fails closed, and `tick` rotates it;
  - the retry interval uses saturating elapsed time.
- **The C5 const assertions** are in hs-core's tests (they need ingress-core
  constants), with dev-dependencies on `ingress-core` and `layout`. The
  assertion messages are the check-selftest needles:
  - "C5: forwarded burst plus ih backlog can exhaust key's bucket";
  - "C5: hs can spend key calls faster than key refills".

## Batch 3 (C4)

- **The cookie adapter is its own module,** `crates/pds/ingress/src/cookie.rs`,
  and has no seL4 dependency.
  - It takes its fill function as a `fn` pointer: the PD passes
    `cpu::fill_random`, and tests can inject a failing one.
  - The nonce counter advances before sealing, so a nonce is never reused,
    even when a seal fails.
  - Batch 4 makes the adapter's deny/allow test permanent: wg-core's tests
    include `cookie.rs` by path, with ingress-core as a wg-core
    dev-dependency. Batch 3 only ran it in a throwaway crate.
- **Side-fix:** `ingress` halts on CNTFRQ = 0, as `hs` and `data` do.
  Otherwise a zero clock would keep the cookie secret from ever ageing,
  against L12.
- **Channel ids:** `timer` uses channel 3 and `ingress` uses channel 5.
  `notify = false` at `ingress`'s end, and `pp` is false on both ends.
- **Per-frame inputs:** backlog and TX free are read fresh for each frame.
  `reclaim` on an empty ring costs two ring pops.
- **Flushing:** `audit.flush()` and the wake-ups run on every pass,
  unconditionally, so `pass_plan().flush` is not consulted.
- **No `WgLoadCleared` without traffic:** no audit line marks a timer
  tick. A `WgLoadCleared` with no frame arriving is the indirect evidence
  of the timer path.

## Batch 4 (C6, gates, M3/CF)

### Adapter host test

- **Location:** `crates/wg-core/tests/ingress_cookie_adapter.rs`, an
  integration test of wg-core with ingress-core as a dev-dependency. It
  includes `crates/pds/ingress/src/cookie.rs` by `#[path]`.
  - A test module inside `wg-core/src` would compile `cookie.rs`'s
    `wg_core::` paths only with `extern crate self as wg_core;` in
    `lib.rs`. The integration test is a crate of its own, so neither
    `cookie.rs` nor `lib.rs` changes.
  - The unit gate counts it as `UNIT-INGRESS-COOKIE-ADAPTER` (6 tests).
- **The failed refill after a good fill** uses a thread-local switchable
  fill function, because the adapter's `fill` field is private to its
  module.
- **Red-proved on a throwaway copy** (outside the repository, then
  deleted). Each mutation of `cookie.rs` failed the test named:
  - counter not advanced: `sealed_replies_follow_the_counter_and_restart_after_rotate`;
  - counter not reset on rotate: the same test;
  - fixed source port in `mac2_valid`: `filled_adapter_accepts_the_correct_mac2_for_its_source_only`;
  - fill result ignored: `failed_fill_denies` and `failed_fill_after_a_good_one_denies`;
  - `clear` emptied: `cleared_adapter_denies`.

### C6 harness choices

- **Topology** as planned: the tap `tapo0` plays the router (10.0.2.2/24,
  `outside_router_mac`), with the gateway's MAC as a permanent neighbour.
  - Python peers are UDP sockets on 10.0.2.2.
  - wireguard-go uses `Endpoint = 10.0.2.15:51820` and `ListenPort = 51900`.
  - Spoofed frames leave through AF_PACKET with `PACKET_QDISC_BYPASS`, so
    a full tap queue drops them as a wire would.
  - The sniffer uses a classic BPF filter for UDP port 51900, an 8 MiB
    `SO_RCVBUF`, and aborts on any `PACKET_STATISTICS` drop.
- **Probe-free paired case.** Boot a measures C *after* the paired case
  and checks the paired flood rate against 0.8·C then. Its rate is fixed
  at 1.4 × refill, which lies inside [1.2 × refill, 0.8·C] whenever
  C ≥ 2 × refill.
  - A probe first would make `WgUnderLoad total=1` the probe's.
  - Under `integration-cookie` (no cookies at all), a probe first would
    also abort on C before the attribution assertion could fail.
- **How C is counted.** C is the rate of the cookie path:
  `WgCookieSent` plus `WgCookieSuppressed` totals.
  - The probe runs unpaced for 2 s, while the injector offers about
    1 M frames/s. Then the flood pauses until an ARP round trip proves the
    queues drained, which takes 0.5–1.5 s.
  - C = answered / (drain time − probe start). The totals are read 0.3 s
    after the drain, and the next flood starts at once, within the 1 s
    hysteresis.
  - Line timestamps cannot give the rate: a starved handler loop flushes
    audit only once its input empties. A fixed settle time was tried too:
    the drain under a stuck loop outlasted it, and C came out negative.
- **The TX reserve binds at saturation, not before.**
  - Every probe shows `WgCookieSuppressed`, about 3–8 % of the answered
    initiations (for example 193 of about 2 400): at full `ingress` CPU,
    `eth_out` drains slower than `ingress` replies.
  - Below capacity it never appeared in any run.
  - The paired case asserts the plan's fresh-counter check: no
    `WgCookieSuppressed total=1` during its band flood.
  - In boot b the probe has already printed `total=1`, so flood step 1
    asserts that no new `WgCookieSuppressed` line appears during step 1.
  - Plan "Cookie replies" says to add a handshake-class TX reservation if
    the reserve binds before CPU. It binds only at C, so no reservation was
    added. **Open for the Phase 3 review.**
- **What C measures:** the rate of the cookie path seen from outside. With
  the committed budgets that rate is set by `eth_out`, not `ingress` (see
  "Loop mutations" below).
- **Flood step 2:**
  - a 1 s warm-up over capacity comes before the first ping;
  - Python-peer pings go out 1 s apart, and each is answered within 3 s.
    Queueing at over capacity delays a reply by about 1 s: with a 1 s wait
    per try, the measured survival fell to 0.10–0.17.
  - wireguard-go is closed after step 1. Step 2's ping uses the Python
    peer's session, made under load right before step 2, and its age is
    checked against REJECT_AFTER_TIME.
- **Attribution** also requires the sniffed mac2 to equal
  `MAC(cookie, msg[..132])` for a cookie opened from a reply to
  wireguard-go. This is stronger than "non-zero".
  - Every attribution failure, in the paired case at port A and in flood
    step 1, starts with `cookie attribution failed`.
  - With the mac2 requirement removed, the paired case fails first.
- **Keepalive deny side:** the 13 s window fails on a keepalive (empty
  plaintext). Late echo replies to extra ping tries are ignored.
- **Every timing and band constant is named once** at the head of the
  cookie section of run.py. `ARRIVAL_INTERVAL_NS`, `UNDER_LOAD_AFTER_NS`,
  `KEEPALIVE_TIMEOUT_NS` and `REJECT_AFTER_TIME_NS` are read from the Rust
  sources.

### CF: C under TCG (settled: feasible)

- **Command:** each `python3 tests/integration/run.py` run (and the scratch
  driver that runs boots a and b alone) prints `capacity probe: C = …`.
- **Per-run C** under the committed budgets, over 26 probes: 740–1 652/s.
  The first 22 used a fixed settle time; the last 4 (740, 831, 854 and
  1 046/s) use the drain barrier, which is more conservative.
  - Sustained C during flood step 2 (`flood processed / sent` over 40–80 s
    at 3.1–5.0 k/s) was 940–1 040/s, giving a flood survival of 0.19–0.33.
- **Outcome:** C ≥ 2 × 200/s holds with margin. `ARRIVAL_*` is not
  retuned, and the accepted cost stays 200/s (plan, R6).
- **The limit is `ingress`'s MCS budget** (1 ms per 10 ms): C is `ingress`'s
  L13 share of the emulated CPU.

### Retry budgets (failure by chance below 1e-3)

- **Rule:** `tries_for(p) = ceil(ln 1e-3 / ln(1 − p))`.
- **Below capacity:** `s1` is measured over the 4 s precondition flood as
  answered/sent from the coalesced totals. Line granularity is taken from
  the safe side, and frames sent while the lines settle are not credited.
  - wireguard-go: `1 + tries_for(s1²)` attempts of 5.334 s, plus 3 s.
    Each attempt needs a surviving initiation and, from the second on, a
    cookie.
  - pings: `max(3, tries_for(s1))`.
  - Measured `s1`: 0.87–1.00, giving 2–6 attempts (13.7–35.0 s) and
    3–4 pings.
- **Flood step 2:** a frame survives about C / rate. The rate is the fixed
  `STEP2_RATE` × C, so this is the constant 1/3, not a measurement; it is
  scaled by 0.5 for the gap between probe C and sustained C (observed
  0.6–1.0). Step 2 measures its own survival afterwards (code review T1):
  - `s2 = 0.5 / 3 = 0.167`, so 38 tries (40 s);
  - P(fail) = 0.833^38 = 9.6e-4;
  - at the lowest measured ping survival, 0.20, it is 0.80^38 = 2.1e-4.
  - Measured ping survival at 3·C with a 3 s wait: 6/30, 12/30 and 5/20.
  - In full runs with the final design, the reply came on tries 1–6.
- **Allow side (no flood):** a scratch boot with the smallest budgets
  (survival 1) and no flood:
  - wireguard-go handshook in 0.2 s (deadline 13.7 s);
  - `ping` succeeded on try 1 of 3;
  - the Python peer's pings were answered on try 1 under both the 3-try
    and the 38-try budget;
  - no `WgUnderLoad` was printed.

### M3: key-exhaustion measurement (settled: branch 2)

- **Mutation**, applied only in a throwaway copy of the tree (`/tmp/m3repo`,
  outside the repository): `Gate::initiation` returns
  `Initiation { mac2_checked: false }` right after the arrival meter. That
  disables the forward bucket, mac2 gating and the per-source bucket.
- **Flood:** a scratch script reusing run.py's tap boot. It sends 60 s of
  peer-1 initiations from 10.0.2.2: real key, a fresh ephemeral each, and
  increasing timestamps (pre-generated).
  - Command: `REPO=/tmp/m3repo RATE=<r> SECS=60 python3 m3.py <dir>`.
- **Results** (coalesced totals; true counts are at most 63 more per kind):
  - offered 1 500/s: `HandshakeOk` 2 177 and `HandshakeFlood` 3 585, so
    hs handled about 96/s, which is about 230 key calls/s;
  - offered 3 000/s: `HandshakeOk` 2 177 and `HandshakeFlood` 5 057, so
    about 121/s, which is about 280 key calls/s;
  - `ingress` logged `TxNoBuffer` for the rest, because `ih` was full and
    hs was the bottleneck.
  - No `HandshakeKeyRateLimited` appeared. hs's own budget keeps it far
    below `key`'s 2 000 calls/s refill.
- **Outcome: branch 2.** The clause and `integration-key-exhaustion` are
  dropped, and "`key` unreachable" rests on C5 and Kani (b).
- **Side observation:** under that saturating flood, the audit PD
  (priority 50, the lowest) printed nothing until the flood ended. hs's
  rate is therefore taken from the final totals over the flood's duration,
  not from per-second samples.

### check-selftest cases

- **C5, gate `unit`, needles = the assertion messages:**
  - `c5-forward-burst`: ingress-core `FORWARD_BURST` 16 → 22;
  - `c5-backlog`: hs-core test `IH_BACKLOG` `+ 1` → `+ 7`;
  - `c5-interval`: key-core `KEY_INTERVAL_NS` `/ 2_000` → `/ 500`;
  - `c5-key-calls`: an extra `key.dh` on hs-core's accept path; needle
    `key calls exceeds KEY_CALLS_PER_HANDSHAKE`.
- **C3, gate `unit`:** `arrival-interval-order` (5 ms → 4 ms) and
  `arrival-burst-order` (16 → 17).
- **C4, gate `laws`:** `laws-timer-ingress`.
- **C6, gate `test`:** `integration-cookie` uses `observe_load(..) || true`
  to forward regardless of mac2; needle `cookie attribution failed`.
- **Not added here:** `ingress-unbounded-loop` and `ingress-late-notify`.
  They were resolved after batch 4 as unit-gate cases; see "Orchestrator
  follow-up after batch 4".
- **Red-proved** by `tools/check-selftest <case>`, every case `ok`:
  - the seven `unit` and `laws` cases;
  - `integration-cookie`;
  - re-run because their needles or the harness changed: `integration`,
    `integration-residue`, `integration-count` and `manifest`.
- **Needles moved:**
  - `integration-count` is now `INTEGRATION-CASES: 10 < manifest 11`;
  - `manifest` is now `UNIT-AUDIT-EVENT: 17 < manifest 18`.

### Loop mutations cannot fail the flood case under TCG (resolved by the follow-up below)

- **Plan premise:** C4 assumes that a flood above `ingress`'s capacity
  keeps its input ring non-empty. Then an unbounded `from_outside` never
  returns, and a loop that notifies only at its end never notifies, so the
  established session's ping fails in Flood step 2.
- **Not so here.** `ingress`'s input is fed by `eth_out`. That driver has
  priority 150 and the same 1 ms per 10 ms budget, and it carries every
  frame in and every cookie reply out. It saturates first, so `ingress`'s
  ring keeps emptying.
- **Evidence** (scratch builds outside the repository, then deleted):
  - **`tools/check-selftest ingress-unbounded-loop`**, committed budgets:
    `make test` exited 0 with `INTEGRATION-CASES 11`, so the mutant passed
    Flood step 2.
  - **Unbounded build, 5 000/s floods of three compositions for 20–30 s
    each** (zero mac2, bad mac1, random mac2):
    - the Python peer's pings were answered 3/10, 3/10 and 1/10 times,
      within the correct build's 0.2–0.4 survival;
    - `eth_out` logged only 257–2 881 `RxNoBuffer` (`ingress` ring full)
      while about 100 000 frames were shed upstream of it.
  - **`eth_out` budget raised to 2.4 ms** (policy sum cap lifted in the
    copy):
    - the correct build's `ingress` then answered about 2 400/s, with
      43 649 `RxNoBuffer` in 19 s: it was now the bottleneck;
    - so with the committed budgets, `eth_out` caps the cookie path at
      about 850–1 000/s;
    - even so, the unbounded build answered step 2's ping on try 3.
  - **`ingress` budget cut to 600 µs** (C 470–630/s): the unbounded build
    answered step 2's ping on try 4. At 250 µs and 500 µs, C fell below
    400/s and the case aborted on CF.
- **Conclusion:** delivery into `ingress`'s ring has gaps, so an unbounded
  `from_outside` still returns within seconds, and a loop that notifies
  late still breaks. No outside flood under TCG makes either mutation fail
  the step-2 assertion. Neither case is added, because each would be
  permanently red. Step 2 stays as the allow side (the data path stays live
  over capacity).
- **Still evidence for the bounded loop:**
  - C3's `pass_plan` unit tests;
  - the loop structure in `crates/pds/ingress/src/main.rs`, which is
    review-only.
- **Open:** a red-provable check needs either a host-testable handler loop
  (moving the PD's loop over traits into a crate) or a decision to accept
  the above.

### Docs

- The Phase-3 entry check greps all of `docs/`, including the review
  record. There, the two marker tokens are reworded ("the M3 pending
  marker", "the CF feasibility marker"); nothing else in the record
  changed.

## Orchestrator follow-up after batch 4: handler loop made unit-testable

- **The problem:** batch 4 could not red-prove `ingress-unbounded-loop` and
  `ingress-late-notify` through the integration flood. Under TCG, `eth_out`
  saturates first, so `ingress`'s RX ring rarely fills, and a mutant still
  passes.
- **The fix:**
  - The loop moved into `ingress_core::run_passes(&mut impl PassIo)`. The
    trait methods are `serve_hs`, `serve_data`, `tick`, `serve_outside` and
    `end_pass`; each input receives its cap as `max`.
  - The PD's `notified()` only calls `run_passes` through a small `Pass`
    adapter, and its `from_*` loops use the `max` they are given.
- **Unit tests:**
  - every pass of an outside flood logs hs, data, tick, outside, end;
  - every input is capped at `PASS_FRAMES`.
- **check-selftest cases** (gate `unit`), both red-proved (exit 2, needle
  found):
  - `ingress-late-notify` moves `end_pass` after the loop;
  - `ingress-unbounded-loop` uncaps `serve_outside`.
- **Residual:** the PD's `from_*` loops honouring `max` rests on review,
  not a test. Each is a three-line `while moved < max`.

## Phase 2 self-R-check fixes

- **RT5 (testing).** The loop red-proofs did not execute the PD code that
  enforces the cap.
  - Every PD input loop is now `ingress_core::drain(max, step)`. Each step
    takes and handles one message and returns `false` when the input is
    empty.
  - Unit tests:
    - `drain` stops at exactly `max` with input remaining, and does not
      step again;
    - it returns fewer than `max` when the input runs dry.
  - `ingress-unbounded-loop` now removes `drain`'s bound, so the mutation
    lands in code the PD executes. It is red-proved.
- **R47 (functionality).** `levels()` no longer destructures `self` to
  dodge a spelling grep. The member-set check now names the primitive,
  `pdkit::send(&mut self.to_hs`, which matches once.
- **R29 (functionality).** Fixed two stale statements:
  - the `Buckets` doc that called `key`'s quota the backstop for floods;
  - this log's "open" heading for the loop mutations.
- **R17 (functionality).** The reason `Buckets` keeps its own bucket
  arithmetic (M2 code with its own Kani proofs) is now in `Meter`'s doc.

## Code review Round 1 fixes

Red-proofs ran on throwaway copies of the tree in the dev container's
`/tmp/rr1-*` (deleted after each run), or through `tools/check-selftest`.
No committed file was mutated to prove a test.

- **S1 (ARP replies bypassed the TX reserve).** `respond` passes `tx_free`
  to the ARP path; a request is answered only while
  `tx_free > TX_RESERVE`, otherwise `Outcome::ArpSuppressed`, which the PD
  audits as the new coalesced `ArpSuppressed` (code 0x003c, slot 39,
  `FIXED_SLOTS` 40). ARP replies stay.
  - Tests: `the_tx_reserve_refuses_an_arp_reply_at_exactly_half` and
    `an_arp_reply_is_sent_one_buffer_above_the_tx_reserve`; the existing ARP
    tests are the allow side (`answers_broadcast_arp_request_for_our_ip`
    now passes a full TX ring instead of 0). audit-event:
    `arp_suppressed_is_coalesced_and_counted_apart_from_arp_replied`.
  - Kani: `respond_is_total_and_bounded` asserts (e) for `ArpReplied` and
    covers `ArpSuppressed`.
  - Red-proofs: comparison removed and `<=` → `<` (the reply's `>` → `>=`)
    each fail `the_tx_reserve_refuses_an_arp_reply_at_exactly_half` and the
    Kani assertion `tx_free > NET_BUFFERS / 2`; `<= TX_RESERVE + 1` fails
    the allow-side test.
  - `arp_round_trip` (the harness's drain barrier) retries every 0.5 s, so
    a request suppressed under saturation is followed by one answered once
    the ring drains; the barrier's FIFO argument still holds.
- **T1 (step 2's survival was a constant).** After step 2 the flood stops,
  an ARP round trip proves the queues drained, and the cookie totals give
  the measured survival `s2m` (answered / sent, upper bound), which is
  printed. A failed ping with `s2m < s2` raises "flood step 2: measured
  survival … below the budget's assumption …; … not judged"; otherwise the
  regression message stands. The "Retry budgets" entry above is reworded.
  - Red-proofs (boot b only, ping verdict forced to fail in the copy):
    - step 2's actual rate × 10 with its band scaled, the budget's s2
      kept: `measured survival 0.050 below the budget's assumption 0.167`;
    - committed rate: `measured survival 0.454 (budget assumed 0.167)`, then
      the regression message "no ping reply through the established session
      in 38 tries over capacity".
  - Plan's "`serve_data` moving nothing" mutant is not usable here: it
    starves every reply to the inside, so the keepalive case, the
    precondition ping and step 1's ping fail long before step 2.
- **F2 (data's input loops were unbounded).** The loop moved to
  `ring::pass` (ring is no_std, host-tested, and both PDs and both cores
  can depend on it): `run_passes(&mut impl Pass)`, `drain(max, step)` and
  `any_full(moved, max)`. Each core supplies its order through its own
  `PassIo`: ingress-core hs, data, tick, outside (unchanged); data-core
  installs, inbound, outbound, keepalives, with `PASS_MSGS =
  layout::NET_BUFFERS`. The data PD's inputs are `drain` steps like
  ingress's. (Session expiry first stayed once per timer notification;
  superseded by "Orchestrator follow-up … expiry every pass" below.)
  - New dependencies: ring for ingress-core, data-core, pd-ingress,
    pd-data; layout for data-core (`Cargo.lock` updated). ring has no
    dependencies, so the C5 "no cycle" note still holds.
  - Tests: ring (end_pass every pass, idle pass, drain exact/dry,
    `any_full` K / K−1); ingress-core and data-core each: order per pass
    under a flood, inputs capped, K on any one input runs another pass,
    K−1 on all is the last pass (and ingress: K from data still runs the
    tick and outside).
  - check-selftest: `ingress-unbounded-loop` → `unbounded-drain` and
    `ingress-late-notify` → `late-notify`, both now editing
    `crates/ring/src/pass.rs`; the three order tests share the needle
    "each pass must end with end_pass", since cargo stops at the first
    failing crate (data-core). Both red-proved.
- **F3 (`PassActions.flush` had no consumer).** `pass_plan` and
  `PassActions` are gone; `continue_` is `ring::pass::any_full`, tested in
  ring and through both cores' `run_passes`. Not done: a host test that a
  pass with no wake flags notifies nobody; `Wake` and the notify calls stay
  in the PDs (seL4 channels), so it would need a further abstraction.
- **F1.** wg-core `noise.rs`'s module doc: mac2 is ignored there because
  `ingress` verifies it through `crate::cookie`; responses carry mac2 = 0
  (SC19).
- **T2 (integration-cookie's needle).** A run of the injected tree (HEAD
  458d791, `observe_load(..) || true`) failed at boot a with "cookie
  attribution failed: an initiation without mac2 under load got a
  handshake response", the specific detector, not the generic "no cookie
  reply". The needle is now that full message, re-red-proved: `tools/check-selftest integration-cookie` ok (exit 2,
  needle found).
- **T3.** Before step 1 the harness prints the highest
  `WgCookieSuppressed` total and the blind window (63 once any line was
  printed, else 0); a run printed "highest … 1; up to 63 suppressions in
  step 1 would print no line". The paired case's fresh-boot `total=1`
  check is the authoritative TX-reserve check; step 1's is auxiliary.
- **T4.** A behavioural `Fail` in the paired case or in step 1 first checks
  the flood's lower band over [start, now] (`check_low_band_first`); if the
  harness under-delivered, that message is raised, chained to the original.
- **T5.** The paired case requires the `WgMac2Accepted total=1` line to be
  read strictly after port A's first allow send.
- **T6.** `sender_in_flight_stays_within_pool` asserts
  `n <= usize::from(sent == Ok(true))`. Red-proof: `in_flight` over-counting
  by one (capped at M) fails the new assertion; the same mutant passes
  under the old `n <= M`.
- **T7.** The data-core test client seals and opens at its session's
  creation time and confirms at it; `expired_current_is_disarmed_…`
  installs peer 1 at T0 + 100 s, after peer 0's data, so no session seals
  before its install and `data`'s clock never goes back.
- **T8.** `ROTATE_AT_NS < COOKIE_SECRET_MAX_AGE_NS` and the ingress PD's
  NET_BUFFERS equality carry messages (hs-core's already had the same one).
  New unit-gate cases, both red-proved: `rotate-before-max-age`
  (`ROTATE_AT_NS` → 120 s) and `net-buffers-equal` (ingress-core
  `NET_BUFFERS` → 65, caught by hs-core's assertion).
- **check-selftest `manifest`:** its needle follows audit-event's new count,
  "UNIT-AUDIT-EVENT: 18 < manifest 19"; re-red-proved.
- **Counts:** ingress-core loses the moved `pass_plan`/`drain` tests
  (61 → 59); ring 24 → 30, data-core 44 → 48, audit-event 18 → 19.

### Orchestrator follow-up to the Round-1 fixes: expiry every pass

- **The gap:** after the F2 fix, `data` still ran `Data::tick` (session
  expiry and zeroization) once per timer notification, before the loop. A
  flood that kept an input full would keep the loop running, so expired
  sessions' keys would stay in memory, against L12.
- **The fix:**
  - data-core's `PassIo` gains `expire()`, called first in every pass. The
    PD implements it as `Data::tick(now)` plus `SessionExpired` audits.
  - `notified()` no longer distinguishes the timer channel. A timer
    notification is just another run of the loop, as in `ingress`.
  - The unused `TIMER` constant is removed.
- **Pinned by** the pass-order test, which now expects `expire` first in
  each pass.

## Code review Round 2 fixes

- **R2-F1 / S2:** the data PD's `notified` doc said expiry runs once per
  timer notification. It now says every pass expires first. The F2 bullet
  of the Round-1 fixes is marked as superseded.
- **R2-T5:** the paired deny oracle had become nearly vacuous: the count,
  the mark and the first allow send were microseconds apart. Two changes:
  - The deny step is conclusive only for the cookie reply to port B's
    *latest* initiation (`opens_for(gw_pub, r, b.sent[-1])`). An earlier
    try may still be in flight.
  - The `WgMac2Accepted` count runs only after `DENY_SETTLE_S` (1 s), so a
    port-B line that `audit` prints late appears before the count. The
    strict time check after port A's first send stays as defence in depth.

  Not red-proved by execution: the mutant would need `audit` to print late
  *and* B's handshake response to be lost. The change only adds a wait and
  narrows which reply counts.

## External review after code review (3fca70f)

- **C5 enforced only under `cfg(test)`.**
  - The key-budget assertions moved from hs-core's tests to `hs-core`'s
    library, beside `KEY_CALLS_PER_HANDSHAKE`. `ingress-core` and `layout`
    became normal dependencies of hs-core.
  - An image whose constants could exhaust `key` no longer compiles.
  - Red-proved on a throwaway copy: with `FORWARD_BURST = 22`, the
    production `pd-hs` build fails with "C5: forwarded burst plus ih backlog
    can exhaust key's bucket".
  - The selftest case `c5-backlog` now edits `hs-core/src/lib.rs`. All four
    C5/equality cases were re-run and are ok.
- **A keepalive or reply was consumed on seal, not on delivery.**
  - `OutboundOutcome::Sealed` carries `unacked`, the debt the seal
    cleared, and `keepalive()` returns the deadline it cleared.
  - When the send to `ingress` fails, the data PD hands the debt back with
    `Data::restore_unacked`, which keeps the earlier deadline. The keepalive
    loop then stops for that pass, so a full link is retried on a later
    pass rather than re-sealed at once.
  - Tests:
    - an undelivered keepalive is retried;
    - an undelivered reply restores the debt;
    - restoring no debt arms nothing.
  - Red-proved on a throwaway copy: a no-op `restore_unacked` fails the
    first two tests.
  - This supersedes batch 2a's "a keepalive whose send fails is consumed"
    entry.
- **Audit-trail date:** the code-review record's date is corrected to
  2026-10-19, the date of the commits.
