# Coding Deviation Log: secureos-m3b-cookie-gate

## Slices 1–5 (ring held receive → PD wiring)

Commits `c82f6b0`, `de7240e`, `1722444`. Each entry is a deviation from the
locked plan (rev 4) and its reason.

### The `ring` held receive (C3)

- **Return type:** `take_into` returns `Result<Option<Taken>, LinkError>`,
  where `Taken` is `Payload(len)` or `Unreadable`. The plan's sketch said
  `Option<len>`. The enum carries the post-`accept` copy failure that the F17
  note asked for.
- **`release()` with nothing held** returns `NoBuffer`. The plan did not say
  which error.
- **`recv_into` while a buffer is held** also returns `Held`. The plan named
  only a second `take_into`. Mixing the two calls is the same protocol
  break, so both fail the same way.
- **`pdkit::take`** returns `Take::{Empty, Skipped, Got}`. `Skipped` is a bad
  descriptor that holds nothing, so `pq`'s pass continues past it instead of
  ending early, as `recv` would.
- **The new `LinkError::Held` arms** in `pdkit::Audit::link_error` and
  `netdrv`'s audit map it to `RingCorrupt`. Only a local protocol bug reaches
  it, and a dedicated event would add an audit code for an unreachable path.

### The completion record (C3) and its audit events (C4)

- **The `RpReply` wire format:**
  - tag 1: `index[1] ‖ msg[1132 or 64]`;
  - tag 2: `NoReply`, nothing after the tag.
- **`index` range:** `msgs` checks the tag and the length only. The `index`
  range (`< peers`, or `RP_NO_PEER` for a RespHello) is checked in
  `RpGate::complete`, which knows the configured peer count.
- **`RpDatagram`** keeps all four lengths, although it now travels only
  `ingress`→`pq`. Narrowing it to the two request lengths would touch the
  existing `RP_LENS` asserts and tests for no behavioural gain, because `pq`
  answers any other length with `NoReply`.
- **Event codes:** `RpPqRecordStuck` is `0x0049` and `RpPqSyncDead` is
  `0x004a`, both never coalesced. `Event::FIXED` grows from 51 to 53, and
  `decode`'s first unknown code moves to `0x004b`.

### `pq` `one()`

- **An `Unreadable` input,** or one that does not decode, is audited
  `BadDescriptor`. It gets a `NoReply` record and is released as usual.
- **A failed `release`** is audited by `pdkit::release`. The link is then
  dead, and every later `take` reads `Empty`. There is no separate stop flag
  for that case.
- **`stuck`:** after a record that could not be enqueued, `one()` returns
  `false` at once, without taking, for the rest of the boot.

### The FIFO and `sync_pq` (C2)

- **Signatures differ from the plan's sketch** (names were not locked; see
  the memory note risk-tiered-review):
  - `PqSync::outstanding() -> Option<usize>`, from which the sync computes
    `r`. The sketch had `returned_snapshot`.
  - `next_record(&mut [u8; RP_RECORD_MAX]) -> Option<Option<usize>>`.
    `Some(None)` is an unreadable record.
  - `transmit(dst, reply) -> bool`.
  - `RpGate::complete(record, peers) -> Result<Completion, SyncDead>`.
  - `Completion::Reply { dst, kind, peer, msg }`.
  - `sync_pq(gate, io, peers) -> SyncOutcome::{Synced { relayed }, DiedNow, Dead}`.
    `DiedNow` lets the PD audit `RpPqSyncDead` exactly once.
- **New outcome `RpOutcome::PqDown`.** After `pq_sync_dead`, admission
  refuses with it before any meter is spent. The PD records nothing for it,
  because the stop was audited once.
- **`sent()` past capacity** sets `pq_dead`. `admit` already refuses at
  capacity, so only a PD bug reaches it.

### PD wiring (C3)

- **Where the sync runs:** it runs at the start of every outside frame, not
  only before a Rosenpass admission. The Rosenpass payload borrows the frame
  buffer, so the sync cannot run between classification and admission.
  Running it before the frame is handled is equivalent for room (no `pq`
  event can interleave within one handler run), and costs one reclaim plus
  an empty read per frame.
- **`serve_pq`** returns `relayed`, capped at `max − 1`. One sync empties an
  honest `pq`'s records, so the pass loop never needs to repeat for it.
- **`next_record` reads the link with `recv_into` directly,** not
  `pdkit::recv`. `recv` skips bad descriptors, and a skipped record would put
  the pairing out of step unnoticed. A link error therefore reaches
  `sync_pq` as unreadable, which kills the sync.

### Not yet done (later slices)

- **Session binding** (awaited and proven, `RpGate::replied`): `sync_pq`
  does not call `replied` yet. Its feed point is the `Completion::Reply`
  branch, after a successful `transmit`.
- **The cookie gate, lanes, TX tiers, `SecretLife` and the C1 crypto.**
- **Kani** for the new `ring`, `msgs` and `ingress-core` harnesses. They are
  written and lint-clean as `cfg(kani)`, but not yet run; Kani is run alone.
- **The FIFO red-proofs** (plan C2, items 1–12) and the check-selftest cases.

## C1, C5, C2–C4 (cookie crypto, SecretLife, gate, adapter, audit)

Commits `c909a0f`, `4710ea9`, `3d54604`.

### C1 — cookie crypto

- **Golden vectors:** they come from a new `rp-vectors --cookie` mode that
  reads the committed `spkm.bin` and InitHello seed. A full regeneration
  would have replaced every V02 vector and both 512 KiB keys.
- **`v02.txt`:** its `domain.cookie*` lines, the V02 BLAKE2b tree's, stay in
  the file but are no longer pinned. The next full regeneration drops them
  (README).
- **Additions to the planned signatures:**
  - `cookie::reply_nonce(secret, counter)`, a nonce derived on the SHAKE
    tree under a `secureos` label. It is local to the responder; upstream
    draws a random nonce.
  - `cookie::host_info`.
  - `rosenpass_wire::HEADER_LEN`, so the PD can assert ingress-core's
    session-id offset.

### C5 — `SecretLife`

- **`SecretLife::tick` takes `rotate` and `clear` closures.** `Gate` and
  `RpGate` lend their adapter to both closures through a local `RefCell`,
  because the two traits differ (`CookieCrypto`, `RpCookieCheck`).
- **Field paths:** the Kani harnesses and unit tests now reach the moved
  fields as `life.*`. Their assertions are unchanged.

### C2 — `RpGate`

- **`RpOutcome::ForwardHello` gains `cookied`.** The PD needs it to audit
  `RpCookieAccepted`; the single-constructor test still counts one
  constructor.
- **Proven priority applies only on the cookied lane.** Off load, every
  endpoint is unproven, because the endpoint alone proves nothing (a
  spoofer could otherwise spend a proven peer's credit). The plan implied
  this ("a spoofer of a proven endpoint gains nothing … only with a valid
  cookie"); the code makes it explicit.
- **The "below half" trigger and the reserve coincide:** with a burst of 8
  and a reserve of 4, an off-load unproven InitHello is refused at the
  reserve (4 tokens) before the meter can fall below half. That refusal is
  itself a trigger, so the gate engages at the same point. "Below half" can
  still hold the gate on its own after proven spends below the reserve, and
  is tested that way.
- **When an awaited entry is marked:** `conf_seen` and the budget
  decrement happen when the matched InitConf is classified for forwarding,
  not when `sent` confirms it. A send that then fails leaves `conf_seen`
  set. That is harmless: an EmptyData can only answer an InitConf that
  reached `pq`, and the budget is a bound, not a count.
- **"One reserved slot per awaited endpoint"** is implemented as: a matched
  InitConf may use a reserved slot only while no other InitConf entry from
  the same endpoint is in flight.
- **The conf-global awaited reserve is also `RP_CONF_AWAITED_RESERVED`
  tokens** (asserted below the burst of 8). So unmatched InitConfs stop at 4
  of 8 tokens, where M3a allowed all 8. The M3a meter test is rewritten for
  this.
- **WireGuard TX boundaries:** ARP and the WireGuard cookie reply move to
  the unsolicited tier (`TX_RESERVE + RP_ANSWER_SHARE` = 40). Their unit
  tests and the Kani `(e)` assertions now pin 40/41 instead of 32/33. This
  is the S2 change.
- **M3a's Rosenpass meter tests** are rewritten for the M3b semantics. A
  refusal now engages the gate, so "refused, then refilled" becomes
  "refused, and the gate engages". The off-load meter behaviour itself is
  unchanged.

### C3 — the PD

- **Audit of a refused CookieReply:** `NoCookieSecret` and
  `CookieSecretExpired` outcomes are audited `RpCookieSuppressed`
  (coalesced). The secret's own edges come from the tick and the gate's
  `take_*` methods (never coalesced).
- **Adapter tests:** the adapter (`rp_cookie.rs`) is tested on the host from
  `crates/rosenpass-core/tests/ingress_rp_cookie_adapter.rs`, by path, as
  the mac adapter is. rosenpass-core therefore gains a dev-dependency on
  ingress-core (no cycle: ingress-core does not depend on rosenpass-core).

### C4 — audit events

- **Codes:** `0x004b`–`0x0051` (`FIXED` 53 → 60).
- **The plan's `RpReplyBadIndex` and `RpReplyUncredited` are not added.**
  Every such condition is now a protocol violation, reported as
  `RpPqSyncDead` (plan rev 4).

### Kani slice

Each new or changed harness was run alone first (`cargo kani --harness
… --exact`, container capped at 40 GiB). Three needed changes:

- **`rp_refusals_before_admission_spend_nothing`** asserted `gate == before`
  for `RingReserved`. A ring refusal is a load trigger (plan, "Load
  state"), so it now asserts that only the load fields changed. `BadMac`
  and `TypeDropped` still leave the gate untouched.
- **`rp_forward_spends_its_own_meters_once`** asserted that every forwarded
  InitHello spent `hello_src`. The cookied lane spends `hello_cookied_ep`
  and `hello_cookied_ip` instead, so the harness now splits on `cookied`
  and checks each lane's own tables.
- **`rp_sync_relays_only_to_stored_sources_in_order`** ran out of memory
  (cbmc killed at 40 GiB, 1.27 M program steps). The scripted `pq`'s record
  count turned symbolic once its early end merged, so cbmc unrolled the
  drain to the unwind bound and multiplied the FIFO scans. The count now
  stays concrete (310 k steps). The harness is split into two: two
  records with every send refused, and `rp_sync_counts_only_sent_replies`,
  one record with any send result. Its unwind was raised from 12 to 20,
  because the awaited table has 13 slots.
- **The sync order check was too weak.** It accepted any awaiting entry
  with the reply's destination, so pairing a record with the newest
  awaiting entry passed. It now asserts I9a exactly: the reply to the j-th
  record goes to the source of the j-th entry awaiting its record. That
  check fails under two mutations: pairing with the newest awaiting entry,
  and sending to the next entry's source. Its first, iterator-based form
  failed in cbmc, although each of its four counterexamples passed on
  concrete playback; the index-loop form proves it.

### C2 follow-up — trigger 4 replaced by the legacy probe

- **An uncookied InitHello under load no longer refreshes load.** The plan
  listed it as a load trigger ("the spoofing keeps the gate up"). Against
  rosenpass 0.2.3, which has no CookieReply handler and retransmits its
  InitHello, that trigger kept the gate up for as long as an old client
  kept trying, so the old client never got through (VE13).
- **Removing it alone was not enough (external review, Major 1).** Load
  then cleared 60 s into a sustained spoof. A spoofer of one address at
  one per 20 s finds the per-source meter refilled each time, so it is
  never refused and nothing re-engages the gate. It would get an InitHello
  to `pq` (up to 16.1 s of work, MCE-COST) every 20 s. The compile-time
  rationale "a spoofer at one per 20 s never sees the gate drop" was false
  for that code.
- **The legacy probe:** after load clears, the first uncookied InitHello
  forwarded within `RP_LEGACY_PROBE_NS` (= `RP_UNDER_LOAD_AFTER_NS`, 60 s)
  is let through, and it re-arms load at once. The check sits in
  `rp_forward_hello`, the single constructor.
  - **Bound:** while a spoofer keeps sending, at most one uncookied
    InitHello reaches `pq` per clearance, so one per
    `RP_UNDER_LOAD_AFTER_NS` instead of one per source period. That is at
    most 16.1 s of `pq` work per 60 s, about 27 %, against 80 % without
    the probe. `RP_LEGACY_PROBE_NS >= RP_HELLO_SRC_INTERVAL_NS` is asserted,
    so a spoofer at the per-source rate always lands in the window.
  - **VE13:** a 0.2.3 client still completes after each clearance, because
    the probe is forwarded.
  - **Tests:** `a_spoofer_at_the_source_rate_gets_one_init_hello_to_pq_per_clearance`
    runs ten minutes at one per 20 s; the two window-edge tests pin "never
    before the first load" and "not past the window". The Kani harness
    `rp_forward_spends_its_own_meters_once` asserts that a forward in the
    window re-arms load. Selftest `rp-legacy-probe` removes the re-arm.
  - **Integration:** the spoof and global-drain cases now bound the
    RespHellos to spoofed sources by the `RpLoadCleared` lines since load
    engaged. The spoof case adds `RP_HELLO_IN_FLIGHT` for spoofs already
    forwarded when load engaged.
- **Residual risks (R6 / SC26):**
  - **Legacy clients are serialised.** Once a load has happened, every
    0.2.3 client's InitHello within the window re-arms load. Several
    0.2.3 clients therefore get about one exchange per 60 s between them
    until the window lapses with none arriving. Master clients are
    unaffected (cookie lane).
  - **The probe cadence.** A spoofer that pauses for longer than the
    window after a clearance finds the gate fully off. That is the same as
    the plan's design, whose load also cleared after 60 s without spoofs.
  - **A low-rate rotating spoof** (fresh addresses at under one per
    `RP_HELLO_GLOBAL_INTERVAL_NS`) never drains the global meter. It never
    engages the gate either, and it gets InitHellos to `pq` at the global
    meter's rate. This is the M3a meter sizing, unchanged by M3b; the
    plan's R6 row gains it as (7), and the two above as (6).
  - The I1 unit test and the Kani I1 assertion pin that an uncookied
    InitHello *under load* leaves `under_load_until_ns` unchanged.

- **The conf-global awaited reserve is pinned at its boundary.** The test
  `unmatched_confs_stop_at_the_awaited_reserve_of_the_global_meter` now
  asserts the token counts: the last unmatched InitConf forwarded finds
  `RP_CONF_AWAITED_RESERVED + 1` tokens, and the next one finds
  `RP_CONF_AWAITED_RESERVED` and is refused without spending. Three
  mutations fail it: `<` for `<=`, a floor one higher, and spending before
  the check.

### C6 — the flood cases

- **Case 3 (proven reserve) is not run in the integration suite.** Under
  TCG, `pq` takes about 10 s per handshake and the ring holds two InitHellos
  in flight, so the gateway forwards about one InitHello per global refill
  (10 s). The global meter therefore never drains to the reserve from the
  wire. I3 is covered by the unit tests (`rp-proven-reserve`) and by the Kani
  harness `rp_unproven_never_takes_the_proven_reserve`.
- **Cookie attribution uses the RespHello, not `RpCookieAccepted`.**
  `RpCookieAccepted` is coalesced, so its count does not identify one
  client. `rp_attribute_cookie` instead finds, in the sniffer, a CookieReply
  that opens for one of the client's InitHellos, then a later InitHello from
  that client that carries a valid cookie, then a RespHello after it that
  names that InitHello's sidi (external review, Medium 5: a RespHello to
  another initiation from the same port no longer satisfies it).
- **The spoofers fail closed (external review, Major 2).** `RpSpoof`
  counts only datagrams the tap took (ENOBUFS is counted as dropped), and
  each case that relies on an attack calls `verify` at its judgment point.
  `verify` fails if the thread raised, has stopped, or delivered under
  90 % of its schedule.
- **`sync_pq` runs at the start of `outside_one` and in `serve_pq`,** not
  inside the payload borrow. The borrow of the received frame would
  otherwise overlap the transmit of `pq`'s replies.

### C7 — the guest-RAM OSK scan

- **The scan covers all of guest RAM** (`0x4000_0000`, 2 GiB), not only
  `OBJECT_RAM`, because the OSK may be copied anywhere that `hs` or `pq`
  touched. Its positive control is a live OSK, which `hs` must still hold.
  The scan prints how often the control occurs, for the T7 copy census;
  that count is not asserted.
- **`Monitor.pmem` unlinks the dump on every path,** monitor failures
  included.
- **Red-proof (external review, Major 3):** selftest
  `integration-expiry-residue` leaves the expiry tick's entry `Live`.
  `fresh` still refuses the stale PSK, so the expiry case passes, and the
  scan itself fails with `expired OSK still in guest RAM`.
- **Copy census (T7):** in the passing run, peer 0's live OSK occurs 4
  times in guest RAM at both scans. Recorded, not asserted.

### Selftest slice

All 20 new or changed cases are red under their mutations. Two were not at
first, and each exposed a test that no longer exercised its control:

- **`rp-sid-binding`:** `a_replayed_init_conf_from_a_spoofed_endpoint_proves_nobody`
  replayed only after E was proven. By then E's awaited entry was
  consumed, so removing the endpoint check changed nothing. The test now
  also sends X's EmptyData while E's own is still owed, which is the window
  where only the endpoint check protects E's entry.
- **`integration-rp-src-meter`:** with the legacy probe, the genuine
  InitHello sent right after a clearance re-armed load, so its replay drew
  a CookieReply whatever the per-source meter did. `rp_deny_cases` now
  waits past the probe window (`wait_rp_gate_off`) before the pair.
