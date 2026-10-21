# Plan: secureos-m3b-cookie-gate (rev 4, scope M3b = SC26, plus SC27)

M3b closes SC26: the Rosenpass path's denial-of-service gaps that M3a left
open, and the guest-RAM OSK residue scan. In M3a, one spoofed mac-valid
InitHello every 20 s as a peer's source takes that peer's per-source
token, about 0.1 pkt/s from rotating sources takes the global meter, and
fake InitHellos filling the `ingress`→`pq` link refuse InitConfs. L8 turns
each into a WireGuard outage 180 s later (R6). M3b adds an upstream-compatible
Rosenpass cookie gate at `ingress`, engaged by meter refusals, plus
reserved shares for proven peers and for awaited InitConfs. Each share is
bound to the Rosenpass session ids, not to an address alone.

Images stay dev-only after M3b. SC23 (cmr) stays an open waiver in
`policy/waivers.toml`, and SC20 (release kernel) stays enforced by
`tools/package`'s debug-only refusal [F8].

Base: `feature/m3-rosenpass` at `e581e79`. Review IDs cite this plan's
review artifact. M3a IDs:
- **M3a plan:** SC26, C2 (the `PQ_KEY` bucket assertion), C4, VE9, VE10.
- **M3a code review:** S-3 and F3.
- **M3a plan review:** T8 and T10.

Upstream is rosenpass master `9e72f1eb871c4c403e99e9b78262fff8dd8d7357`.

## Project context

- **Type:** `mixed`.
- **Test infra:** unit tests, Kani, bolero and the QEMU integration suite
  behind `make check`, plus check-selftest. There is no CI.
- **Verification environment:**
  - M3a VE1–VE10 still apply.
  - **VE11: cookie golden vectors.**
    - `tools/rp-vectors` already emits the cookie domain labels
      (`main.rs:173-175`). It gains the SHAKE-tree values plus
      `cookie_value`, `cookie_field` and a sealed CookieReply, each
      computed by upstream functions.
    - The vectors are regenerated in the `rosenpass-oracle` stage, so the
      dev image is rebuilt with `--network host`.
    - `verifiable-local`.
  - **VE12: full guest-RAM dump.** One QEMU `pmemsave` of the 2 GiB guest
    RAM (`-m size=2G`, base `0x4000_0000`) per assertion. There is no
    polling loop: each scan runs once, after a deterministic event.
    `verifiable-local`.
  - **VE13: 0.2.3 has no CookieReply handler** (M3a feasibility). That
    client cannot complete while the gate holds. Its allow case runs after
    `RpLoadCleared`. `verifiable-local`.
- **Every acceptance path is verifiable-local.**

## Upstream cookie mechanism (facts this plan relies on)

All read at `9e72f1eb` (paths relative to `rosenpass/src/`). Each is
pinned by a golden vector or an interop run (C1, C6).

- **Responder side, behind `experiment_cookie_dos_mitigation`:**
  (`protocol/protocol.rs` `handle_msg_under_load`, L2033-2170)
  - InitConf is processed without a cookie check.
  - An InitHello is processed only if its envelope `cookie` field matches,
    under the current or the previous secret.
  - Otherwise the responder sends a **CookieReply**:
    `0x86 ‖ reserved[3] ‖ sid[4] = InitHello.sidi ‖ XAEAD(cookie_key, nonce[24], cookie_value, ad = InitHello.mac)`,
    zero-padded to 1092 B. It carries no mac (`msgs.rs` L339-371).
    `MSG_COOKIE_REPLY = 0x86` already exists in `rosenpass-wire`
    (`lib.rs:23`) [F7].
- **The hash tree** is a `mix` chain over keyed SHAKE256. `KH(k, d)` =
  SHAKE256(k ‖ d), 32 bytes out (`keyed_shake256.rs`), and every `.mix(x)`
  replaces the key with `KH(key, x)`. The chain starts from a zero key,
  mixes in the protocol string
  `"Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 SHAKE256"`
  (`hash_domains.rs` L112-118), then a domain label [F2]:
  - `cookie_key = root.mix("cookie-key").mix(spkm)`
  - `cookie_value = root.mix("cookie-value").mix(secret).mix(host_info)[..16]`
  - `cookie = root.mix("cookie").mix(cookie_value).mix(msg[..cookie])[..16]`
- **The secret:** 16 B, rotated every 120 s; the current and previous
  secrets are tried (`constants.rs` L30-33).
- **Master initiator, not feature-gated:**
  - It opens a CookieReply with the cookie key derived from its `spkt`
    (our `spkm`) and the mac of its last message.
  - It keeps the cookie value for 120 s.
  - It retransmits the **same bytes** at once, with only the cookie field
    overwritten (`handle_cookie_reply` L4263, `seal_cookie` L3198,
    `register_immediate_retransmission`).
- **Under-load detection** is local. Upstream's app server uses a
  poll-ratio heuristic (`app_server.rs:48-52`), which does not fit a PD.
  This plan uses meter refusals instead [F11].

## Objective

1. **Rekeys survive spoofing.** An attacker who cannot receive at a
   peer's address cannot keep that peer from completing a Rosenpass
   exchange (S-3). This holds while the TX path has the capacity C6
   measures.
2. **Peers behind one address.** Up to `MAX_PEERS` (8) peers behind one
   IPv4 address each keep a fresh PSK (F3).
3. **InitConf has its own share.** No InitHello traffic can take the link
   share InitConfs need. An awaited reserve is held for the InitConf of
   the exchange `ingress` answered.
4. **Proven peers are prioritized** under a drain of the global InitHello
   meter by a non-spoofing attacker.
   - A proven endpoint may spend below the reserve that unproven senders
     cannot.
   - Each configured peer's standing is its own, and no other peer and no
     replay can take it.
   - Proven slots refill at 8 tokens per 120 s at most, below the meter's
     12 per 120 s.
   - This is a priority, proved by Kani (I3), not a completion guarantee
     under every interleaving. C6 case 3 measures completion, and
     contention delay is the R6 residual (4) [S12].
5. **Residue.** After expiry or supersession, a peer's OSK occurs nowhere
   in guest RAM (L12, M3a T10).

## Requirements

- **Upstream-compatible:** a master initiator completes under load with
  no client configuration change.
- **Pre-authentication cost:** the cookie check needs no KEM and no `pq`
  time. A CookieReply is exactly as large as the InitHello that caused it
  (1092 B; WireGuard's is 64 B out for 148 B in) [S10].
- **No new trust:**
  - The cookie secret stays in `ingress`.
  - `pq` gains no new channel.
  - Every reserve is decided by `ingress` from bytes it handed to the
    driver itself (S1).
- **The C2 key-bucket assertion stays true and red-proved:** every
  `ForwardHello` still spends the global InitHello meter.

## Design

### Load state (`RpGate`)

- **Trigger [S-3]:** load holds from any of these until
  `RP_UNDER_LOAD_AFTER_NS` after the last one:
  - an InitHello refused by a meter (`RateLimited`) or by the link
    (`RingReserved`);
  - the global InitHello meter below half;
  - while load holds, a mac-valid InitHello without a valid cookie.
- **Edges:** only the edges are stored, as in `Gate`. Unlike
  `Gate::observe_load`, the refresh takes a per-message input, "this
  message refreshes load", which the classifier passes after deciding the
  lane [F4].
- **The refusal is the trigger:** there is no arrival-rate trigger,
  because a 0.05 pkt/s attack never crosses one. That attack is refused on
  the victim's first InitHello, and the refusal engages the gate. The
  below-half trigger watches the meter's level, not traffic.
- **`RP_UNDER_LOAD_AFTER_NS` = 60 s, asserted ≥ `RP_HELLO_SRC_INTERVAL_NS`**
  [F6]. The rationale is three spoof periods: a spoofer at one per 20 s
  never sees the gate drop between spoofs, even if it loses two packets.
  - Cost to honest master clients: about one RTT per rekey.
  - Cost to 0.2.3 clients: they wait for the clear.

### Lanes

- **Off load:** as in M3a, the per-IP meter and then the global meter
  (unproven rule below).
- **Under load:**
  - **Without a valid cookie:** an InitHello spends no meter, adds nothing
    in flight, and gets a CookieReply (TX tier 2, below).
  - **With a valid cookie,** checked by `ct_eq` against the current and the
    previous secret with no early exit [S3]: it spends, in order,
    1. `hello_cookied_ep`, the per-endpoint `(ip, port)` meter, with the
       `RP_HELLO_SRC_*` constants;
    2. `hello_cookied_ip`, the per-IP cookied cap: burst `MAX_PEERS`, one
       per 15 s (120 s / `MAX_PEERS`);
    3. the global meter.

    A later refusal does not refund an earlier spend, as in M3a.
  - **Three tables [F13]:** the off-load `hello_src` (keyed by IP) and the
    two cookied ones are separate.
    - `SourceMeters` becomes generic over its key (`Ipv4` or `Endpoint`),
      and each table has `N = BUCKETS` slots with the M3a LRU rule.
    - A token spent in one table neither carries over to nor refunds
      another, so a peer refused per IP off load starts with a full
      per-endpoint meter once it is cookied.
    - That is the point: the cookie, not the IP, is what entitles it.
- **The cookie proves the endpoint:** the sender receives at that
  `(ip, port)`.
  - The F3 NAT's peers past the first are refused per IP. That engages the
    gate.
  - After their next retransmission (≤ 10 s, upstream backoff) they get a
    CookieReply and proceed per endpoint [F9].
  - Off load the meter stays per-IP, as M3a's F3 reasoning requires.

### Session binding: awaited and proven [S1, S7, S8]

- **The awaited table:** when `pq_one` hands a RespHello for E to the
  driver, `ingress` records `(E, sidi, sidr, at, conf_budget,
  conf_seen=false)`.
  - The ids are read through `rosenpass-wire`'s RespHello parser, never by
    raw offsets.
  - The table is keyed by `(E, sidr)`.
  - Its capacity `RP_AWAIT_SLOTS` is asserted ≥ `RP_HELLO_GLOBAL_BURST +
    ceil(RP_AWAIT_CONF_NS / RP_HELLO_GLOBAL_INTERVAL_NS) +
    RP_HELLO_IN_FLIGHT + 1`. More RespHellos than that cannot occur within
    `RP_AWAIT_CONF_NS`, so a live entry is never evicted. A full table
    refuses to record; it never evicts a live entry.
- **A matched InitConf:** one from E whose `(sidi, sidr)` equals a live
  entry for E, with `conf_budget > 0` (starts at `RP_CONF_SRC_BURST`).
  - Only a matched InitConf may take an awaited-reserved link slot or
    conf-global token.
  - Forwarding it decrements the entry's budget and sets `conf_seen`.
  - An unmatched InitConf uses only the unreserved share.
  - **Why the match proves the exchange:** the biscuit's ad binds
    `(sidi, sidr)` (`responder.rs:427`, ICR3 `:445`). An InitConf that `pq`
    accepts with E's sidr therefore belongs to the exchange whose RespHello
    went to E.
  - **Who can produce it:** only the real peer at E, or an on-path
    observer at E (out of scope).
- **Proven, per configured peer:** `pq`'s replies carry the configured
  peer's index (C3, the `RpReply` record).
  - **When a mark is set:** an EmptyData for E is handed to the driver,
    its `sid` equals the sidi of a `conf_seen` awaited entry for E, and its
    index is `< config::PEERS.len()`. A fresh export and a retransmission
    both count, so a suppressed EmptyData followed by a retransmission
    still proves E.
  - **What it stores:** proven slot `[index]` := `(E, at, credit)`, and the
    awaited entry closes.
  - **Bad index:** an out-of-range index records nothing and is audited.
- **Proven reserve:**
  - A cookied InitHello from an endpoint that is no proven slot's endpoint
    within `RP_PROVEN_NS` may spend a global token only while the meter
    holds more than `RP_HELLO_PROVEN_RESERVE` (4) tokens. At exactly 4 it
    is refused.
  - A proven endpoint may spend to zero, but only while its slot's
    `credit` allows: burst 2, refilled at one per 120 s.
  - All proven slots together then refill at most 8 tokens per 120 s.
    That is within the global meter's refill of 12 per 120 s. The bursts
    (8 × 2 = 16) can exceed the meter's burst of 8 only once, after which
    the refill rate binds.
- **A floor, not a quota [F14]:** the reserve is a floor on the shared
  meter. Recent spends from any lane, including a proven peer's own
  admission, lower the headroom left to unproven peers until the meter
  refills.
- **The total is unchanged:** the reserve shapes the global meter and adds
  no capacity, so `pq`'s load and the C2 assertion are unaffected.
- **What each attacker can do:**

  | Attacker | Effect |
  |---|---|
  | Cache replay of a captured InitConf from X | Proves nothing: X has no entry carrying E's sidr |
  | X made awaited by a spoofed InitHello off load | Proves nothing: the attacker never sees sidr_X |
  | An insider peer | Can rewrite only its own slot |
  | A compromised `pq` | Can already withhold every `PskInstall`, which is the L8 outage itself. Its replies cannot change `Gate` or `Buckets` state. The FIFO below admits at most one reply per forward, of that forward's type, sent to that forward's stored source. So it can neither fabricate awaited or proven state for an endpoint `ingress` did not forward from, nor aim replies, nor hold the TX tiers [S9, S11] |

### Reply ownership: the `InFlight` FIFO and completion records [S11, S13, S14, F16, F17, R4-F1–F3; SC27 brought into scope]

**What was withdrawn, and why:**
- **Rev 3's timed reply credits.** An unanswered forged InitConf held a
  credit for about 33 s, so about 20/s of them saturated the table (S13).
- **The time-graced variant from Round 3.** It rests on `pq`'s wall time
  and on when `ingress` happens to read a reclaim (S15).
- **Rev 4's first draft,** "a return completes an unanswered entry". Round
  4 (F16) showed that a batch of returns cannot tell which request had no
  reply. If `pq` refused j and answered j+1, the RespHello for j+1 could be
  paired with j and go to j's source, even with an honest `pq`.

**What replaces them:** the `InFlight` FIFO plus one ordered completion
record per input.

- **The entry:** `(kind, src: Endpoint, state)`, where `state ∈
  {AwaitingRecord, CompletedReply, CompletedNoReply}`.
  - It is pushed, as `AwaitingRecord`, only after the `ingress`→`pq` send
    succeeded.
  - Admission checks room without pushing, so `unsent()` goes away.
  - **Lifetime:** an entry exists until `ingress` observes its buffer's
    return in a sync snapshot, not until the physical return. The gap only
    holds capacity longer, which is the safe side.
- **The completion record (`RpReply`, C3):** `pq` emits exactly one record
  per input, in input order:
  - `Reply { index, msg }`, a RespHello or an EmptyData;
  - or `NoReply`, for every refusal, decode failure and error path.

  No record carries an endpoint.
- **The order contract, both directions (C3):**
  1. `pq` takes one input and holds its buffer.
  2. It enqueues exactly one completion record.
  3. Only then does it return the input buffer.
  4. It takes no next input before that return. A held receive in `ring`
     enforces this.
  5. If the record cannot be enqueued, `pq` does **not** return the input.
     It holds it and stops its Rosenpass path for good (fail-closed, no
     resend state).

  - **Structurally, an honest `pq` never hits step 5:** the `pq`→`ingress`
    link has `≥ RP_IN_FLIGHT` buffers (asserted), and at most
    `RP_IN_FLIGHT` records are ever outstanding.
  - **Cross-ring ordering:** `pq`'s Release on the completion ring
    happens-before its Release on the `ingress`→`pq` return ring (program
    order). That return synchronizes-with `ingress`'s Acquire in the
    return snapshot (`ring` shmem, Release/Acquire indices, `shmem.rs:79-88`).
    So any return `ingress` counts has its record already visible.
- **The sync**, a pure `ingress-core` function (C2, T18), in this order:
  1. **Snapshot** the returns, checked and never saturated:

     ```text
     len_before  = fifo.len
     outstanding = to_pq.in_flight()          // validated reclaim
     r           = len_before - outstanding   // checked
     ```

  2. **Drain** the completion link until it is empty.
  3. **Assign** each record, in order, to the **first `AwaitingRecord`
     entry** in the FIFO. A `Reply` must fit that entry's kind (RespHello
     for InitHello, EmptyData for InitConf) and decode strictly. Valid ones
     set `CompletedReply`; `NoReply` sets `CompletedNoReply`.
  4. **Check** that the oldest `r` entries are all Completed.
  5. **Retire** those `r` entries, and only if the check passed.

  `ingress` runs the sync in `serve_pq` and before every admission.
- **Why every interleaving is safe:**
  - A return in the snapshot had its record published first, so the drain
    reads it.
  - A return after the snapshot is not retired in this sync.
  - A record drained for an unreturned entry leaves it Completed, and the
    entry is retired by a later sync.
- **Protocol violations:** each sets the sticky `pq_sync_dead` state
  (below). They are:
  - a record with no `AwaitingRecord` entry (extra or duplicate);
  - a kind mismatch;
  - a malformed record, or an `index` outside `< MAX_PEERS` / `0xFF`;
  - a snapshotted return whose entry is still `AwaitingRecord` after the
    drain;
  - `outstanding > len_before`, or `r > len`;
  - a drain that reaches its cap without emptying the link.
    `RP_IN_FLIGHT < PASS_FRAMES` is asserted, so an honest `pq` never
    triggers it.
  - **Link errors:** a link error while snapshotting also sets it. `ring`
    already treats a failed link as dead for good.
- **`pq_sync_dead` is sticky, until reboot [R4-F2]:**
  - **Why:** once records and returns disagree, which entries can be
    trusted cannot be recovered. Guessing a resynchronisation is the more
    dangerous choice.
  - **While it holds:** no new forward to `pq` is admitted, and no `pq`
    record is relayed. Awaited and proven state is not updated, and the
    FIFO is not retired by guesswork.
  - **Audit:** the violation is audited once (`RpPqSyncDead`, never
    coalesced).
  - **What keeps running:** WireGuard and every other path.
  - **Who can trigger it:** only a buggy or compromised `pq`. A compromised
    `pq` can already cause the same Rosenpass outage by withholding
    `PskInstall`.
- **The `in_flight()` floor [R4-F3]:** `Sender::reclaim` accepts a returned
  descriptor only for a buffer this side lent and has not taken back
  (`pool.accept`, `link.rs:74-85`). So `pq` cannot report returns it was
  never lent, or return one buffer twice. A premature return of a lent
  buffer is the step-4 violation (`AwaitingRecord` after the drain).
- **Relaying a `CompletedReply`:**
  - **Destination:** it goes to the entry's **stored** `src`, never to
    anything derived from the record. `index` is used only for the proven
    slot.
  - **Selection:** the destination comes from the pure selection function
    `RpGate::complete(record) -> Completion { dst: Endpoint, … }` (C2).
    That function also passes the same stored `src` to `RpGate::replied`
    [T19, R4-F1].
  - **TX refusal:** if TX refuses a valid reply, that is not a protocol
    violation. The record is consumed and the entry stays `CompletedReply`;
    no resend is relayed, so there is no amplification.
  - **`RpGate::replied`** is fed only after a successful hand-off to the
    driver.
- **Same-kind reordering is not detectable.** Records carry no request id,
  so a compromised `pq` can present the RespHello it made for a later
  InitHello as an earlier one's record.
  - An honest `pq` cannot, because the order contract is serial.
  - A compromised `pq` that does so is bounded: one record per input, sent
    to the assigned entry's stored `src`.
  - **It cannot escalate to a false proof [R4-F1]:** every awaited and
    proven lookup is keyed by the FIFO's stored `src`. A swapped reply can
    therefore only pollute or deny the slots of an endpoint `ingress`
    itself forwarded from. Using another endpoint's slot would still need
    that endpoint to send a matching InitConf, which requires that
    exchange's private material.
  - A request id would not help: a compromised `pq` echoes the ids it saw.
    This is residual 5 (R6 table).
- **Capacity:** the FIFO is the credit table, `0..=RP_IN_FLIGHT` by
  construction.
  - There is no second table, no timer and no full-table path.
  - A forward refused for room is refused at admission (`RingReserved`),
    spending nothing.
  - Forged InitConfs that `pq` refuses produce `NoReply` records. They
    compete only for InitConf link slots, which the awaited reserve
    partitions (S13).
- **Bound:** `pq`'s relayed replies are at most `ingress`'s forwards. Each
  goes only to the stored `src` of the entry it was assigned to, and only
  as that entry's reply type.

### The `ingress`→`pq` link

- **Hello cap [S14]:** InitHellos in flight are capped at
  `RP_HELLO_IN_FLIGHT` = 2. `pq` handles one message per pass
  (`PASS_MSGS = 1`), at 8.5 s median and 16.1 s max per InitHello
  (MCE-COST).
  - **Before the fix (rev 3, as found):** `pq` returned each buffer as it
    received it, before processing (`ring::Receiver::recv_into`). So the
    InitHello being processed was not in flight, and a cap of 2 allowed
    1 processing + 2 queued. An InitConf could then wait about 3 × 16.1 ≈
    48 s.
  - **After the fix:** the buffer is returned only after the reply (the
    order contract). The InitHello being processed stays an unreturned
    buffer inside the cap, so a cap of 2 means 1 processing + 1 queued. An
    InitConf waits behind at most 2 InitHellos, about 2 × 16.1 ≈ 32 s.
- **Cost of the cap [F1]:** after a reboot, the 6 InitHellos beyond the
  cap are refused (`RingReserved`, no reply) and are resent on upstream's
  backoff (≤ 10 s).
  - Full reconnection of 8 peers stays within the serial bound
    (8 × 16.1 s) plus one 10 s backoff.
  - C6 measures this with a deny/allow pair.
- **InitConf slots:** `RP_CONF_IN_FLIGHT` = 8. InitHellos never take them,
  and InitConfs never take InitHello slots [S-3].
- **Awaited reserve:** `RP_CONF_AWAITED_RESERVED` = 4 of the InitConf
  slots. The conf-global meter holds the same number of tokens back.
- **No cookie on InitConf:** upstream's responder skips the cookie for
  InitConf (L2045-2052), so requiring one would break master clients.
- **The C2 assertion's backlog term:** `RP_IN_FLIGHT` =
  `RP_HELLO_IN_FLIGHT` + `RP_CONF_IN_FLIGHT` stays its backlog term. It
  falls from 16 to 10, so the assertion's margin grows.

### TX tiers [S2]

The `to_driver` ring's free count decides which outbound reply is allowed.
The tiers are by strict comparison:

| Tier | Replies | Allowed while `tx_free >` |
|---|---|---|
| 0 | `hs` and `data` traffic | always (unchanged) |
| 1 | RP answers (RespHello, EmptyData) | `TX_RESERVE` |
| 2 | RP CookieReply, WireGuard cookie reply, ARP reply | `TX_RESERVE + RP_ANSWER_SHARE` |

- **Why this order:** answers to metered, forwarded work are never starved
  by attacker-induced replies.
- **The assertion:** `0 < RP_ANSWER_SHARE < NET_BUFFERS − TX_RESERVE`.
- **What is measured, not assumed:** whether tier-2 replies are suppressed
  under a combined flood. C6 measures it and records suppressions; the
  pass condition is the honest client completing.
- **Not added:** a per-destination CookieReply meter. Spoofing the victim
  would reintroduce S-3.

### Cookie secret and crypto (`ingress`)

- **`RpCookieAdapter`** holds a current and a previous 16-byte secret. Both
  are separate from the WireGuard cookie secret.
  - `rotate` moves the current secret to previous, zeroizing the old
    previous, then fills a new current [F5].
  - A failed fill zeroizes both.
- **Lifecycle:** shared with `Gate` through an extracted `SecretLife`
  (C5).
- **`host_info`** = the IPv4-mapped IPv6 address (16 B) ‖ the port (2 B,
  big-endian). The responder chooses it, so this has no interop effect.
- **`cookie_key`** is derived once at init from `spkm`, as `RpMacKey`
  derives the mac key.
- **CookieReply nonce:** derived from the current secret and a reply
  counter, as the WireGuard adapter does (`cookie.rs:49-57`). It is never
  repeated under one secret.
- **SHAKE256** comes from `sha3 =0.10.9`, already locked as a dependency
  of `classic-mceliece-rust` (`Cargo.lock:1702`, `:211-220`).
  - It becomes a direct, exact-pinned dependency of `rosenpass-core`.
  - The M3a review had suggested `libcrux-sha3`. That would add a crate,
    while `sha3` is already in the graph and the golden vectors adjudicate
    either way [F10].
  - `ingress` gains `sha3` and `keccak` through `rosenpass-core`.

### Law amendments

| Law | Change | Residual |
|---|---|---|
| R6 | Rosenpass DoS by spoofed InitHellos is closed by the cookie gate, and proven peers keep rekeying | (1) Cold start under a non-spoofing attack: a peer with no proven slot, for example after a reboot or an endpoint change, competes for the 4-token unproven share. (2) Tier-2 TX contention under a combined flood, measured in C6. (3) A guessed sidr: 2⁻³² per forwarded InitConf, bounded by the conf meters. (4) Proven peers contending with each other and with the drain may be delayed; priority is proved (I3); completion is not measured under TCG (deviation log, C6 case 3). (5) A compromised `pq` can swap same-kind replies between queued requests. It cannot be detected, but it is bounded to one record per input, sent to the assigned entry's stored source; awaited and proven lookups stay keyed by that stored source, so it cannot post a false proof for another endpoint (R4-F1). (6) The legacy probe (deviation log, trigger 4): under a sustained spoof one uncookied InitHello reaches `pq` per clearance (≤ 16.1 s per 60 s), and once a load has happened 0.2.3 clients are serialised to about one exchange per 60 s. (7) A rotating spoof below the global InitHello rate never engages the gate and reaches `pq` at that rate (the M3a meter sizing) |
| L12 | Verified across all of guest RAM for the OSK (C7) | — |

## Contracts

**C1 — Rosenpass cookie crypto (`rosenpass-core::cookie`,
`rosenpass-wire` CookieReply).**
- **Signatures:**
  - `cookie_key(spkm: &[u8; SPK_LEN]) -> Result<[u8; 32], CryptoError>`
  - `cookie_value(secret: &Secret<16>, host: &[u8; 18]) -> Result<Secret<16>, CryptoError>`
  - `cookie_field(value: &Secret<16>, msg_before_cookie: &[u8]) -> Result<[u8; 16], CryptoError>`
  - `cookie_valid(secrets: [Option<&Secret<16>>; 2], host: &[u8; 18], msg: &[u8]) -> bool`.
    It is constant-time per secret (`ct_eq`), evaluates both secrets with
    no early exit, and returns false on any error [S3].
  - `seal_cookie_reply(key: &[u8; 32], sidi: [u8; 4], nonce: &[u8; 24], value: &Secret<16>, mac: &[u8; 16], out: &mut [u8; COOKIE_REPLY_LEN]) -> Result<(), CryptoError>`
  - **`rosenpass-wire`:**
    - `COOKIE_REPLY_LEN = 1092`, asserted equal to `INIT_HELLO_LEN`;
    - a `CookieReply` encode/decode with the Kani harnesses
      `*_parse_is_total` and `*_round_trips`;
    - the module doc now names CookieReply as the one non-envelope
      message [F7].
- **Removed [F2, S4]:** `Domains::v02()`'s dead `cookie`, `cookie_value`
  and `cookie_key` fields, which sit on the BLAKE2b tree
  (`crypto.rs:91-93`, `:115-118`). Their three cases leave
  `every_hash_domain_matches_upstream` (`tests.rs:183-209`), and
  `tests/vectors/v02.txt:32-34` is regenerated.
- **Invariants:**
  - The SHAKE tree is separate from the V02 tree.
  - Cookie values are `Secret`.
- **Control class:** primitives, not a control. The adjudication
  authority is upstream, through VE11's vectors.
- **Acceptance:**
  - the vectors pass;
  - `cookie_valid` deny/allow: the current secret allows, the previous
    secret allows, a secret two rotations old denies, and a field with one
    flipped bit denies;
  - check-selftest `rp-cookie-domain` changes `b"cookie-value"` and
    requires `unit` to fail.

**C2 — `ingress-core` RpGate v2.**
- **Signatures:**
  - `rp_classify<M: RpMac, K: RpCookieCheck, const N: usize>(gate, mac, cookie, now_ns, tx_free, src, payload) -> RpOutcome`.
    `RpOutcome` gains `CookieReply { dst }`, `CookieSuppressed` and
    `NoCookieSecret`.
  - `RpGate::replied(kind: RpReply, dst, ids: ReplyIds, index: Option<u8>, now_ns)`:
    the endpoint-state feed. It is called only after the reply was handed
    to the driver.
  - `RpGate::tick_if_due` returns the load and secret edges, plus `take_*`
    methods as on `Gate`.
  - **The FIFO and the sync** (pure, in `ingress-core`) [T14, T18, T19]:
    - `RpGate::sent(kind, src)` pushes an `AwaitingRecord` entry after a
      successful send.
    - `RpGate::complete(record: &RpReply) -> Result<Completion, SyncDead>`
      assigns a record to the first `AwaitingRecord` entry.
      - `Completion::Reply { dst, kind, ids, index }` carries `dst`, which
        is always that entry's stored `src`.
      - `Completion::NoReply` is the other case.
      - The PD sends the reply to `dst`, and passes the same `dst` to
        `replied`. There is no other source of a destination.
    - `trait PqSync { fn returned_snapshot(&mut self) -> Result<usize,
      LinkError>; fn next_record(&mut self) -> Option<RecordBytes>;
      fn transmit(&mut self, dst: Endpoint, reply: &[u8]) -> bool; }` is
      the PD's I/O. It mirrors `PassIo`.
      - **No destination choice in the PD [T19]:** `sync_pq` itself calls
        `transmit(c.dst, …)` and then `replied(c.dst, …)`. The PD's
        `transmit` receives neither `index` nor the `Completion`. So the
        PD cannot route by `endpoints[index]` without changing this
        signature, and the destination is decided only in pure code.
    - `sync_pq<T: PqSync, const N: usize>(gate: &mut RpGate<N>, io: &mut T)`
      runs the fixed order:
      1. snapshot;
      2. drain, up to `PASS_FRAMES`;
      3. `complete` and `relay` each record;
      4. check that the oldest `r` entries are Completed;
      5. retire them.

      Any violation sets the sticky `pq_sync_dead`, which `RpGate` holds,
      and while it is set `sync_pq` does nothing. The PD's own `sync_pq`
      is a thin caller, so there is one production order.
  - `rp_tx_allowed(tier, tx_free) -> bool`.
- **Trait:** `RpCookieCheck { valid, seal, rotate, clear }`, implemented
  by the PD over C1.
- **Invariants:** app-enforced, each in the only constructor of its
  outcome, and each proved by Kani with the production constants.
  - **I1:** under load, an InitHello without a valid cookie spends no
    meter and adds nothing in flight.
  - **I2:** off load, `RpCookieCheck::valid` is never called.
  - **I3:** an endpoint that is no live proven slot's endpoint never takes
    the global InitHello meter to `RP_HELLO_PROVEN_RESERVE` or below. A
    proven endpoint never spends beyond its slot's credit.
  - **I4:** InitHellos in flight never exceed `RP_HELLO_IN_FLIGHT`. The
    InitHello and InitConf slots are disjoint.
  - **I5:** only a matched InitConf takes an awaited-reserved slot or
    token, and an entry forwards at most `RP_CONF_SRC_BURST` of them.
  - **I6:** proven slot `[i]` changes only on an EmptyData whose sid
    equals a `conf_seen` entry's sidi for the same endpoint, with `i <
    PEERS`. A live awaited entry is never evicted.
  - **I7:** every `ForwardHello` spent the global InitHello meter (keeps
    the C2 key-bucket assertion).
  - **I8:** a tier-2 reply is never allowed when a tier-1 one would be
    refused.
  - **I9a:** the FIFO length is always in `0..=RP_IN_FLIGHT`. Its entries
    correspond one-to-one, in order, with the successful sends whose
    return `ingress` has not yet observed. An entry is added only on a
    successful send.
  - **I9b:** each entry takes exactly one record, in order. A `Reply`
    record must be that entry's kind's reply type (InitHello → RespHello,
    InitConf → EmptyData), and it goes only to the entry's stored `src`,
    which is also the endpoint passed to `replied`. Records are assigned to
    the first `AwaitingRecord` entry, never to a later one.
  - **I9c:** retirement takes only the oldest `r` snapshotted entries, and
    only if all of them are Completed. Under the order contract, every
    snapshotted return's record is drained first, so an honest `pq` never
    trips the check. Every protocol violation sets `pq_sync_dead`. After
    that, no forward is admitted, no record is relayed, and no awaited or
    proven state changes.
- **Member set (R42):**
  - `rg -n 'RpOutcome::Forward(Hello|Conf) \{' crates/` finds one
    constructor each (`ingress-core/src/lib.rs:750`, `:758`), plus the PD's
    match arms (`pds/ingress/src/main.rs:359-360`) and test matches.
  - The constructor-count test (`tests.rs:1145`) stays.
  - The cookie path adds no constructor.
  - Every TX-reserve user (`rg -n 'TX_RESERVE|rp_reply_allowed'
    crates/ingress-core crates/pds/ingress`) moves to `rp_tx_allowed`'s
    tiers: `arp` (`:156`), `Gate::initiation` (`:488`) and `pq_one`
    (`main.rs:473`).
- **Control class:** **fail-closed verification gate**.
  - A missing or expired secret yields `NoCookieSecret`, a refusal.
  - A full awaited table records nothing.
  - A bad index records nothing.
  - The adjudication authority is `cookie_valid` (C1) for cookies and
    `rosenpass-wire`'s parsers for the session ids.
- **Constants and their compile-time assertions:**
  - `RP_UNDER_LOAD_AFTER_NS ≥ RP_HELLO_SRC_INTERVAL_NS`;
  - `0 < RP_HELLO_PROVEN_RESERVE < RP_HELLO_GLOBAL_BURST`;
  - per-IP cookied burst ≥ `MAX_PEERS`;
  - `PEERS × (120 s / RP_PROVEN_CREDIT_INTERVAL_NS) ≤ 120 s / RP_HELLO_GLOBAL_INTERVAL_NS`
    (refill rates, not bursts);
  - `RP_CONF_AWAITED_RESERVED < RP_CONF_IN_FLIGHT`;
  - the `RP_AWAIT_SLOTS` bound above;
  - `0 < RP_ANSWER_SHARE < NET_BUFFERS − TX_RESERVE`;
  - `RP_IN_FLIGHT ≤ NET_BUFFERS`;
  - `RP_IN_FLIGHT < PASS_FRAMES`, so one drain empties an honest `pq`'s
    replies;
  - `RP_IN_FLIGHT == RP_HELLO_IN_FLIGHT + RP_CONF_IN_FLIGHT`, where each
    cap counts the entry being processed [S14].

  Values unchanged from M3a: `RP_HELLO_GLOBAL_BURST` 8 at one per 10 s,
  `RP_HELLO_SRC_*` one per 20 s, and the `RP_CONF_*` meters. Proposed:
  - hold 60 s;
  - reserve 4;
  - `RP_PROVEN_NS` 300 s;
  - `RP_AWAIT_CONF_NS` 30 s;
  - hello in flight 2;
  - InitConf in flight 8, of which 4 are awaited;
  - `RP_ANSWER_SHARE` 8.

  Phase 2 may tune these with a recorded rationale, but may not weaken the
  assertions.
- **Unit tests, one deny/allow pair per invariant:**
  - **I1:** with the spoof per 20 s, the victim is refused off load and
    admitted with a cookie.
  - **I2:** a counting fake shows no `valid` call off load, and exactly
    one call under load.
  - **I3:** an unproven endpoint is refused at exactly 4 tokens and allowed
    at 5. A proven endpoint is allowed at 1 token and refused past its
    credit.
  - **I4:** an InitHello flood leaves the InitConf slots free; the third
    concurrent InitHello is refused and the second allowed.
  - **I5:** a non-matched InitConf is refused a reserved slot, and the
    matched one is allowed. A matched entry's
    `RP_CONF_SRC_BURST + 1`-th InitConf is refused.
  - **I6:**
    - a captured InitConf replayed from spoofed X leaves X unproven and E
      proven;
    - a suppressed fresh EmptyData followed by a retransmission still
      proves E;
    - an index ≥ PEERS records nothing;
    - peer 1's EmptyData cannot change slot 0.
  - **NAT [F3]:** `MAX_PEERS` endpoints behind one IP are all admitted
    within one rekey interval, and the `MAX_PEERS + 1`-th is refused at the
    cap.
  - **Secrets:** the previous secret is accepted for one epoch, and an
    older one is refused.
  - **I8:** tier boundaries at exactly the threshold and threshold + 1.
  - **I9a–I9c** [T14, T18, T19], through `sync_pq` with a mock `PqSync`
    (as `FakePass` tests `run_passes`) and a model of an honest serial
    `pq`:
    - **Deny cases.** Each sets `pq_sync_dead`, audits once, relays
      nothing and calls `replied` never. They are:
      - an extra record (no `AwaitingRecord` entry);
      - a duplicate;
      - a RespHello for an InitConf entry, and the reverse;
      - a malformed record or a bad `index`;
      - a snapshotted return still `AwaitingRecord` after the drain (a
        premature return);
      - `outstanding > len`;
      - `r > len`;
      - a drain that hits its cap;
      - a snapshot link error.
    - **After dead:** a later honest record and a later forward are both
      refused. WireGuard classification is unaffected.
    - **Allow cases:**
      - several records drained in one sync, with no retirement in between,
        each assigned in order [F16];
      - `pq` refuses j (`NoReply`) and answers j+1 (`Reply`) in one batch.
        j+1's reply goes to j+1's stored `src`, not j's;
      - a TX-refused valid reply leaves the entry `CompletedReply`, and the
        sync continues without dying.
    - **Destination [T19, R4-F1]:**
      - in a fixture where the stored `src` and `endpoints[index]` differ,
        `Completion::Reply.dst` is always the stored `src`;
      - the endpoint handed to `replied` is the same stored value;
      - a swapped same-kind reply (E2's RespHello assigned to E1's entry)
        updates only E1's awaited slot and marks neither E1 nor E2 proven
        without E1's own matching InitConf.
    - **Interleavings:** every order of {`pq` enqueues record j, `pq`
      returns j} against {snapshot, drain, check, retire} completes j with
      no violation.
    - **Failed sends:** a failed send leaves no entry.
    - **Capacity:** the 10th entry is allowed and the 11th is refused at
      admission.
  - **`ring` held receive [F17]:**
    - take, then a second take, which is refused as `Held`; release; take
      again;
    - an error after `pool.accept` yields `Ok(Taken::Unreadable)` with
      the buffer held, and the following `release` returns it;
    - an error before `accept` holds nothing;
    - a failed return makes the link dead;
    - `pdkit::take` tries once and does not loop.
  - **`NoCookieSecret`** [T17]: under a missing or expired secret,
    classification yields `NoCookieSecret` (deny). Under a usable secret it
    yields `CookieReply` (allow).
- **Kani:** I1–I9c with the production constants and a symbolic order of
  return and reply events, at small bounds.
- **Red-proofs:** each Kani harness and each pair is red-proved by its own
  mutation on a scratch copy. For the FIFO these are at least the
  following. "Unit" means reachable by `cargo test` through `sync_pq` or
  `ring`; "integration" means only the C6 suite reaches the code [T18].
  1. `pq` releases the input before enqueueing its record. *Integration*:
     the zero-`RpPqSyncDead` allow side must fail.
  2. An extra record is accepted instead of killing the sync. *Unit.*
  3. `sync_pq` passes a destination other than `c.dst` to `transmit` or
     `replied`, for example the `endpoints[index]` the fixture supplies to
     the mock. *Unit*: the differing-fixture destination test must fail.
     The PD half is closed structurally, not by a test, because
     `transmit` has no `index` [T19].
  4. Two records are accepted for one entry. *Unit.*
  5. The reply types are swapped (RespHello accepted for an InitConf).
     *Unit.*
  6. A record is assigned to any matching entry instead of the first
     `AwaitingRecord`. *Unit*: the refused-j / answered-j+1 batch test must
     fail.
  7. The processing entry is excluded from the cap (`pq` returns at
     receive). *Unit*: the I4 test with one processing and one queued.
  8. The length bound in `sent` is removed. *Unit*: the 11th-entry test
     must fail [T20].
  9. The checked `r = len − outstanding` is replaced by a saturating
     subtraction. *Unit*: the `outstanding > len` test must fail [T20].
  10. `sync_pq` retires before draining. *Unit*: the interleaving test must
      fail.
  11. `pq_sync_dead` is cleared on the next sync (made transient).
      *Unit*: the after-dead test must fail [R4-F2].
  12. `take_into` returns `Err` on a failure after `accept`, either still
      holding the buffer or returning it with no record. *Unit*: the `ring`
      `Unreadable` test must fail [F17].

**C3 — `ingress` PD cookie path, and `pq`'s reply record.**
- **`RpCookieAdapter`:** host-buildable, like `cookie.rs`, with the
  rotation of §"Cookie secret".
- **The `RpReply` completion record** (new, `msgs`): either
  `Reply { index: u8, msg }` or `NoReply`. Exactly one is sent per input.
  It replaces `RpDatagram` on the `pq`→`ingress` link only.
  - **No endpoint field:** the destination is the assigned entry's stored
    `src`, so `pq` cannot name one [S13].
  - `index` is the configured peer for an EmptyData, and `0xFF` otherwise.
  - The `ingress`→`pq` direction keeps `RpDatagram`. `pq` reads `src`
    from it only for its own bookkeeping.
- **Consumer walkthrough (R40):** `sync_pq` (through `PqSync::next_record`)
  reads each record.
  - **`Reply`:** it uses `msg`'s length and type to match the entry's kind,
    the session ids from `rosenpass-wire`'s parser for `ReplyIds`, and
    `index` for the proven slot. The destination comes from the entry,
    never from the record.
  - **`NoReply`:** it marks the entry `CompletedNoReply`.
  - **Strictness:** the decoder is strict. It accepts the `NoReply` tag, or
    the `Reply` tag with a RespHello or EmptyData length and `index < MAX_PEERS`
    or `0xFF`. Anything else is a protocol violation (`pq_sync_dead`).
  - `pq` builds the record in `send_rp` (`main.rs:126`, `:279`, `:323`),
    taking the index from `Conf::Fresh`'s `PendingExport::peer` or
    `Conf::Retransmission { peer }`.
  - `msgs` tests and proofs cover the totality and round trip of the new
    record.
- **The order contract** (§Reply ownership) is a C3 obligation on both
  PDs:
  - **`ring`:** a held receive, `Receiver::take_into(out) -> Result<Option<len>, LinkError>`
    then `Receiver::release() -> Result<(), LinkError>` [F17].
    - `take_into` copies the payload and keeps the buffer.
    - **Failure before ownership** (popping or validating the
      descriptor): no buffer is held, and there is nothing to return.
    - **Failure after `pool.accept`** (copying) [F17 note]: `take_into`
      keeps the buffer held and returns `Ok(Taken::Unreadable)`, not `Err`.
      `pq` then enqueues `NoReply` and releases as usual, so the record
      count stays aligned with the returns.
      - **Why not return the buffer internally:** that would be a return
        with no record. The next record would then be assigned to the
        wrong entry and relayed before the check caught the gap.
      - **The property kept:** `take_into` never returns `Err` while a
        buffer is held.
    - **A failed return** (in `release`, or in that internal return) makes
      the link dead for good, as every `ring` failure does.
    - **A second `take_into`** while a buffer is legitimately held fails
      with a new `LinkError::Held`. That is the only way `Held` arises.
    - `recv_into` stays for every other link.
    - **`pdkit::take`** is a new helper that tries once. It does not use
      `pdkit::recv`'s retry loop.
  - **`pq` `one()`:** `take` → decode → handle → enqueue exactly one record
    (`Reply` or `NoReply`) → `release`, with `PASS_MSGS = 1`.
    - Every refusal, decode-failure and error path enqueues `NoReply`
      before its single release point.
    - If the enqueue fails, `pq` keeps the input held and stops its
      Rosenpass path for good: it neither releases nor takes again, and
      audits the stop.
    - The `pq`→`ingress` link has `≥ RP_IN_FLIGHT` buffers (asserted), so
      an honest `pq` never hits this.
    - A comment in `pq` states the contract and the cross-ring ordering:
      the completion ring's Release comes before the return ring's
      Release, which `ingress`'s snapshot Acquire reads.
  - **`ingress`:** the PD's `sync_pq()` is a thin caller of the pure
    `ingress_core::sync_pq` (C2). It runs in `serve_pq` and before every
    Rosenpass admission, and replaces today's lazy reclaim in the outside
    path (`main.rs:348-357`).
- **Further PD changes:**
  - The PD's `PqSync::transmit(dst, reply)` applies the TX tier check and
    calls `send_to_peer(CONFIG.rp_port, dst, reply)`. It returns that
    call's result, which is ignored today (`main.rs:477`). `sync_pq` calls
    `replied` only when it returns true.
  - The forward path calls `RpGate::sent` only after the
    `ingress`→`pq` send succeeded.
  - The tick calls `tick_if_due`.
  - Every outbound reply goes through `rp_tx_allowed`.
- **Control class:** the secret custody is an **enforceable boundary**.
  The secret is a field of a PD-local struct, and `ingress-core` sees only
  the trait.
- **Acceptance:**
  - the adapter is tested against C1's vectors;
  - a reply suppressed at TX records nothing in `replied`, but its credit
    is spent (unit test of the PD helper);
  - the `ring` held-receive tests;
  - the WireGuard `Gate`'s tests and Kani proofs pass unchanged (C5).

**C4 — Audit events (`src=ingress`, codes after `0x0048`).**
- **Never coalesced:**
  - `RpUnderLoad` and `RpLoadCleared`, which alternate as `WgUnderLoad`
    and `WgLoadCleared` do;
  - `RpCookieSecretExpired`;
  - `RpCookieSecretUnavailable`.
- **Coalesced:**
  - `RpCookieReplySent`;
  - `RpCookieAccepted`;
  - `RpCookieSuppressed`, as `WgCookieSuppressed` is [F3];
  - (`RpReplyBadIndex` and `RpReplyUncredited` from rev 3 are withdrawn.
    Each is now a protocol violation, reported as `RpPqSyncDead`.)
- **Never coalesced (rev 4):** `RpPqSyncDead`, audited once when the sync
  dies; and `pq`'s `RpPqRecordStuck`, when `pq` stops because a record
  could not be enqueued.
- **Member set (R12):** every `Event` list in `audit-event` (code map,
  `ALL`, names, `is_coalesced`), `crates/pds/audit`, and the audit-event
  tests.
- **Consumer walkthrough:** run.py (C6) reads
  `audit: src=ingress <Name> total=<n>` lines, always as a **delta since a
  mark** (`con.count(..., since=mark)`, as `cookie_totals` does at
  `run.py:1629-1638`). It never reads a literal `total=1` [T1]. Every field
  it reads (src, name, total) is in the existing line format.

**C5 — `SecretLife` extraction (R1).**
- **What moves** out of `Gate` into one struct used by both gates: born
  time, rotation due, the expiry backstop, retry spacing, and the
  unavailable and expired edges.
- **What stays per gate:** holding the previous secret is the RP
  adapter's, and `SecretLife` only says when to rotate.
- **Control class:** a refactor of a fail-closed gate.
- **Acceptance:** the existing `Gate` unit tests and Kani proofs pass with
  no edits to their assertions.

**C6 — Integration: flood, latency and attribution** [S-3, F3, S2, F1,
M3a T8].
- **Harness:**
  - **Python twin:** `tests/integration/rp_cookie.py` is a twin of C1. It
    is checked against VE11's vectors in `tests/tools` (RT9).
  - **Attribution sniffer:** it accepts, in order:
    1. a CookieReply to the client's port that opens with the public
       cookie key and the mac of one of its sniffed InitHellos;
    2. a later InitHello from that port whose cookie field is valid for
       the opened value;
    3. a positive `RpCookieAccepted` delta after it, and then a fresh
       `key_out` that opens a WireGuard handshake.
  - **Budgets** are derived in run.py from existing constants [T2]:
    - one exchange: `RP_EXCHANGE_S` (MCE-COST-derived, `run.py:728-737`);
    - under load: `RP_EXCHANGE_S` plus one upstream backoff cap (10 s);
    - the reboot case: the case 6 formula, from the MCE-COST maximum
      [T12];
    - a WireGuard handshake under a Rosenpass flood: the M2.5 flood case's
      `hs_deadline` derivation;
    - `RP_SLACK_S` = 10 s, new and named once in run.py [T15]. It is the
      MCE-COST spread between the maximum and the median handshake
      (16.1 − 8.5 = 7.6 s), plus `pq`'s and `hs`'s 1 Hz ticks, rounded up.
- **The FIFO at the integration level** [T14]: every case asserts a zero
  `RpPqSyncDead` line and no `RpPqRecordStuck` across its honest exchanges. That is the allow
  side of I9c on the real PDs; the deny side is the unit and Kani level.
- **Cases** (tap boot; each deny with its allow in the same boot):
  1. **Spoof (S-3) [T3, T10]:**
     - **Setup:** the victim's client starts, and the case polls the
       sniffer until its first InitHello is captured (the
       `attribute_wireguard_go` pattern).
     - **The spoof:** from then on it replays those bytes with the
       victim's source IP **once per second**. That keeps the victim's
       per-IP token at zero deterministically, so no phase-locking is
       needed. The exact 20 s economics is the I1 unit test.
     - **Allow:** the victim's next exchange completes, with attribution.
     - **Deny:** check-selftest `rp-cookie-gate` mutates the gate so that
       load never holds. The case's own new call site then fails with
       `Fail("rp spoof: the victim's exchange did not complete under the
       spoof")`, which is the needle, within `RP_EXCHANGE_S`.
     - **Red-proof:** this layer is red-proved by its mutation. The M2.5
       `flood_case` string at `run.py:2204` tests an unrelated path and is
       not used [T6].
  2. **Global drain:**
     - Mac-valid InitHellos come from rotating spoofed IPs at 0.2 pkt/s.
     - Each gets a CookieReply to its spoofed address (sniffed).
     - `RpInitHello` rises only by the client's exchanges.
     - The client completes.
  3. **Proven reserve:**
     - Client A completes first, and is now proven.
     - After at least one `RP_HELLO_GLOBAL_INTERVAL_NS` (the meter is full
       again), a non-spoofing Python initiator on the host completes
       cookies from 5 ports.
       - It replays **one** sniffed mac-valid InitHello unchanged from
         each port.
       - Each port opens its own CookieReply with the public cookie key,
         then resends with that port's cookie field. The cookie covers
         `msg[..cookie]`, which is unchanged, so this works.
       - No envelope mac is computed in Python.
       - A duplicate sidi from 5 endpoints is harmless: `pq` draws a fresh
         sidr per RespHello, and the awaited table is keyed `(E, sidr)`
         [T9]. The first 4 are admitted, and the 5th is
       refused at the reserve, observed as no RespHello.
     - A rekeys within budget.
     - A cache replay of A's sniffed InitConf from a spoofed endpoint X
       gets EmptyData at X. Then X's cookied InitHello is still refused at
       the reserve (the I6 path in the PD).
  4. **InitConf share:** a spoofed InitConf flood at the conf-global rate,
     plus an InitHello flood, during the client's exchange. The client's
     InitConf is accepted (fresh `key_out` opens a handshake).
  5. **NAT (F3):** two master clients on one host IP, on different
     ports, start together. Both export, the second with attribution.
  6. **Reboot fan-in [F1, T8]:**
     - `--peers 3` clients start together after the prelude, so one
       InitHello exceeds the cap of 2. All three complete within
       3 × the MCE-COST maximum (16.1 s), plus one 10 s backoff, plus the
       named `RP_SLACK_S`.
     - **What is measured:** the cap's refusal-and-retry path end to end.
     - **What is derived, not measured:** the 8-peer bound (8 × 16.1 s +
       10 s). It would need its own 8-peer image, and its arithmetic is
       I4's.
  7. **Combined flood [S2]:**
     - Spoofed InitHellos at `ingress`'s classification capacity come in
       under load, with the WireGuard band flood.
     - The master client completes within the under-load budget.
     - The tier-2 suppression count is recorded in the deviation log.
  8. **0.2.3 after load [T11]:**
     - **Quiescence first:** every earlier case's floods and spoofers are
       closed and joined, and every client except the 0.2.3 one is
       stopped.
     - **Engage load:** the case spoofs once to engage load and marks the
       console.
     - **Deny:** the 0.2.3 client gets no RespHello while load holds.
     - **Allow:** after an `RpLoadCleared` delta since the mark (budget:
       the hold plus `RP_SLACK_S`), the client completes.
  9. **Latency, both directions:**
     - a WireGuard handshake under a Rosenpass flood;
     - a Rosenpass exchange under the WireGuard band flood.
- **check-selftest** (failure-only needles):
  - `rp-cookie-gate`: integration, as in case 1;
  - unit cases, each with the cargo `---- tests::<name> stdout ----` line
    of its deny test as the needle:
    - `rp-conf-share` (I4);
    - `rp-awaited` (I5);
    - `rp-proven-reserve` (I3);
    - `rp-sid-binding` (I6, the sidr match removed);
    - `rp-nat` (the cookied lane keyed by IP);
    - `rp-cookie-offload` (I2);
    - `rp-tx-tier` (I8);
    - `rp-reply-fifo` (I9b, a record assigned past the first `AwaitingRecord`);
    - `rp-reply-order` (I9c, retire before drain in `sync_pq`);
    - `rp-reply-dst` (I9b, `endpoints[index]` used as the destination) [T19];
    - `rp-sync-sticky` (I9c, `pq_sync_dead` made transient) [R4-F2].
- **Time:**
  - `rp-cookie-gate` stops the suite at case 1. A case's own failure path
    is shorter than a full run, so the layer costs less than one suite run
    (about 900 s with the added cases).
  - The added cases are estimated at about 600 s of suite time.
  - The full selftest is then estimated well under 2 × the 4179 s
    baseline (`e581e79`), which is recorded.
- **Manifest:** the following are recounted [T13]:
  - `INTEGRATION-CASES`;
  - the unit counts;
  - `CHECK-SELFTEST-FIXTURES`, for 13 new case names [T16]: the 12 listed
    above plus C1's `rp-cookie-domain`. The count is derived from the
    list, not stated by hand.

**C7 — Guest-RAM OSK residue scan** [M3a T10].
- **`Monitor.pmem` fix [T4]:**
  - The unlink moves into a `try/finally` that covers `sendall` and the
    monitor read.
  - A new `scan_absent(needle, control)` takes one 2 GiB snapshot, with one
    retry after the 1 Hz tick.
  - The existing 32 MiB `wait_absent` is unchanged.
- **Cases:**
  - **Expiry:** after the expiry case's `HandshakePskStale`, peer 1's OSK
    (its `key_out`) occurs nowhere in the 2 GiB. The control, in the same
    snapshot, is peer 0's live OSK.
  - **Supersession:** after the rotation case, the superseded OSK occurs
    nowhere. The control is the new OSK.
- **Recorded:** the live OSK's occurrence count, in the deviation log. Any
  copy outside `hs`'s table is a finding to fix, by zeroizing the owner's
  scratch or scrubbing a stack. It is not waived [T7].
- **Control class:** detection, with a positive control, so a scan of the
  wrong window fails.
- **Red-proof:** remove the zeroization in `hs`'s expiry tick; the expiry
  scan must fail.

**Forbidden patterns** (check-pins rules, with fixtures, red-proved):
- `pattern: getrandom|thread_rng|OsRng` in `crates/` — reason: unchanged;
  the CookieReply nonce is derived.
- `pattern: derive\([^)]*\b(Clone|Copy|Debug)\b` on a struct whose body
  names `Secret<`, `Zeroizing<`, `CookieSecret` or `RpCookieAdapter`'s
  secret type — reason: L12 [A1].
  - `pds/ingress` joins the rule's crate list.
  - The matcher learns the named secret types; it previously matched only
    `Secret<`/`Zeroizing<` (`tools/check-pins:252-264`).
  - A fixture uses a named-type wrapper.
- `pattern: == | !=` on a value named `cookie` in
  `pds/ingress/src/rp_cookie.rs` and `rosenpass-core/src/cookie.rs` —
  reason: RS1; compares go through `ct_eq` [S3]. This is a tripwire.

## Files to update

- **rosenpass:**
  - `crates/rosenpass-core/{lib.rs, cookie.rs (new), crypto.rs, tests.rs, Cargo.toml}`
    and `tests/vectors/`;
  - `crates/rosenpass-wire/{lib.rs, proofs.rs, tests.rs}`.
- **ingress:**
  - `crates/ingress-core/{lib.rs, proofs.rs, tests.rs}`;
  - `crates/pds/ingress/src/{main.rs, rp_cookie.rs (new)}` and its
    Cargo.toml.
- **Messages and links:**
  - `crates/msgs/{lib.rs, tests.rs, proofs.rs}` (`RpReply`);
  - `crates/ring/src/{link.rs, tests}` (held receive);
  - `crates/pdkit` (a held-receive helper, if `pdkit::recv` is the
    caller);
  - `crates/pds/pq/src/main.rs` (`one()`'s order, `send_rp`, the index).
- **Audit:** `crates/audit-event/src/{lib.rs, tests.rs}` and
  `crates/pds/audit`.
- **Tools:**
  - `tools/rp-vectors` and the committed vectors;
  - `tools/check-pins` and `tests/tools/test_check_pins.py`;
  - `tools/check-selftest`.
- **Tests:**
  - `tests/integration/{run.py, rp_cookie.py (new)}`;
  - `tests/tools` (twin vectors);
  - `tests/manifest.txt`.
- **Locks and policy:**
  - `Cargo.lock`, refreshed with `cargo metadata --offline`;
  - `policy/waivers.toml`: SC26 `closed` once C6 and C7 pass.
- **Docker:** `docker/Dockerfile`, only if the vector stage needs a
  feature flag.

## Testing strategy

- **Oracles:**
  - upstream functions for the vectors;
  - upstream master as the initiator under load;
  - the Python twin, checked against the same vectors.
- **Kani** proves I1–I9c with the production constants. Runs are
  serialized (`tools/kani-gate.sh`).
- **Gates:** every new gate, assertion, invariant and integration case is
  red-proved on a scratch copy, one mutation per clause.

## Considerations & constraints

- **Residuals:**
  - **The R6 table's three entries.**
  - **On-path attackers** can read cookies and session ids, and can drop
    traffic. They are out of scope, as for WireGuard.
  - **0.2.3 clients** cannot complete while load holds (VE13).
    Production already requires master clients.
  - **InitConf latency:** an InitConf waits behind at most 2 InitHellos,
    about 32 s at TCG worst case. Meanwhile the client already uses its
    new `key_out`.
  - **Reflection:** the gateway reflects 1092-byte CookieReplies 1:1 to
    spoofed sources, at up to `ingress`'s classification rate. The rate is
    measured in C6.
- **Scope contract:**

| ID | Deferred | Owner |
|----|----------|-------|
| SC20 | Release-kernel proof | M4 |
| SC23 | cmr replacement and constant-time verification | M4 |
| SC24 | Protocol V03 | M4 |
| SC27 | Closed in M3b: replies are owned by the `InFlight` FIFO (I9a–I9c) and sent only to the stored source | M3b |
| SC28 | A dedicated InitConf ring, if the 32 s worst-case InitConf latency proves too long on hardware | M4 measurement |

## User operation scenarios

1. **Spoofed starvation.** Someone spoofs a laptop's IP once every 20 s.
   The laptop's next rekey is refused once, which engages the gate. Its
   retransmission gets a CookieReply, it retries at once with the cookie,
   and it completes.
2. **Office NAT.** Eight laptops behind one public IP all start at 09:00.
   The first is admitted per IP. The others are refused once, which
   engages the gate, and after one backoff (≤ 10 s) they complete through
   cookies.
3. **A botnet with real addresses.** Peers that completed an exchange in
   the last 300 s keep rekeying through their own proven slots. A newly
   arriving peer may wait.
4. **An old client.** A 0.2.3 client reconnects once the gate clears
   (`RpLoadCleared`).

## Go/No-Go Gate

Plan review closed after Round 4 by the stopping rule: no open Critical or Major, every one re-checked by the expert who raised it.

| ID | Subject | Status |
|----|---------|--------|
| C1 | Rosenpass cookie crypto and CookieReply wire | locked |
| C2 | ingress-core RpGate v2 | locked |
| C3 | ingress PD cookie path and `RpReply` | locked |
| C4 | Audit events | locked |
| C5 | SecretLife extraction | locked |
| C6 | Integration: flood, latency, attribution | locked |
| C7 | Guest-RAM OSK residue scan | locked |

## Implementation Checklist

Derived in Phase 2 Step 2-1 with `rg` over `crates/`. Slices are in the
order of the memory note risk-tiered-review; each closes with its own fast
gate.

1. **`ring` held receive:** `crates/ring/src/{link.rs, tests.rs, proofs.rs}`.
   - `LinkError::Held` is a new variant. Its exhaustive matches are
     `crates/pdkit/src/lib.rs:97` and `crates/netdrv/src/lib.rs:161`, and
     each gets an arm.
   - `pdkit::take` is new. `pdkit::recv` (`lib.rs:131`) stays for the 13
     other call sites; `rg -n 'pdkit::recv'` lists them.
2. **`pq` completion record:**
   - `crates/msgs/{lib.rs, tests.rs, proofs.rs}` get `RpReply`. The
     `RpDatagram` users are `pds/pq/src/main.rs:126/254/279/323` and
     `pds/ingress/src/main.rs:61/359/360/455`.
   - `pds/pq/src/main.rs` `one()` moves to `take` → one record → `release`.
3. **The `InFlight` state machine:** `crates/ingress-core/src/lib.rs`.
   - `InFlight`, `RpGate::admit/reclaimed/unsent` (`:643-805`).
   - The PD call sites of `reclaimed`/`unsent`: `pds/ingress/src/main.rs:357/377/435`.
4. **Pure `sync_pq` and `PqSync`:** `crates/ingress-core/src/lib.rs`, next
   to `PassIo` (`:808-845`), with tests and Kani in
   `crates/ingress-core/src/{tests.rs, proofs.rs}`.
5. **PD wiring:** `pds/ingress/src/main.rs`.
   - `pq_one` (`:451-479`) becomes `PqSync`.
   - The outside path's lazy reclaim (`:348-357`) is replaced.
   - Every TX-reserve user moves to `rp_tx_allowed`: `ingress-core/src/lib.rs:156/488/742` and `pds/ingress/src/main.rs:473`.
6. **Cookie gate, lanes, binding (C1–C5):**
   - `crates/rosenpass-core` (cookie module; remove `Domains` cookie fields, `crypto.rs:91-93/115-118`);
   - `crates/rosenpass-wire`;
   - `crates/ingress-core`;
   - `pds/ingress` (`rp_cookie.rs`);
   - `crates/audit-event` and `crates/pds/audit`.
7. **Kani and mutations, then C6/C7 integration,** check-selftest cases,
   and `tests/manifest.txt`.

**Reuse, not reimplement (R1):**
- `ring::pass::{drain, any_full}`;
- `pdkit::{send, Audit}`;
- `Meter`, `SourceMeters` (made generic over the key);
- `Gate`'s secret lifecycle, extracted to `SecretLife` (C5);
- `wg-core`'s nonce derivation pattern for the CookieReply;
- `rosenpass_core::crypto::ct_eq`;
- `run.py`'s `Sniffer`, `wait_absent`, `cookie_totals` and `exported`.

**CI parity:** there is no CI config. `make check` is the single gate, run
once at the end (memory: risk-tiered-review).
