# Plan: secureos-m2-5-cookies-keepalive (rev 6)

Iteration 2.5 (M2.5): WireGuard cookies (mac2 / cookie reply) in `ingress`, so
that a spoofed-source initiation flood can no longer drain `key`'s shared
budget or starve `hs` (closes SC13 / architecture R6 down to a narrower
residual), and passive keepalives in `data` (SC14). Base: M2 at `3750758`
(`feature/m2-wireguard`). Everything not restated here follows
`secureos-m2-wireguard-plan.md` rev 4 and its deviation log. Bracketed IDs
(M1–M19, and R2-<expert>-<id> for Round 2) cite findings in the review
artifact; R3-<expert>-<id> for Round 3.

## Project context

- Type: `mixed`. Test infra: unit + Kani + bolero + QEMU integration behind
  `make check` with check-selftest; no CI (M2 SC9).
- Verification environment: M2 VE1–VE7 unchanged; VE6 (QEMU `neoverse-n2`,
  RNDR) now also backs `ingress`'s cookie secret.
  - VE8 (new): the cookie and keepalive integration cases need a `tap`
    device and AF_PACKET inside `unshare -rn`. Both were probed in the dev
    container (`ip tuntap add … mode tap`, `socket(AF_PACKET, SOCK_RAW)`)
    and work. `preflight()` raises `Fail` when either is missing; it never
    skips.
- Every acceptance path below is `verifiable-local`.

## Objective

1. Under load, `ingress` forwards an initiation to `hs` only if its mac2 is
   valid for the datagram's source (ip, port). Otherwise it answers with a
   cookie reply (whitepaper §5.4.7) and drops the initiation.
2. `ingress` can never forward enough initiations for `key`'s bucket to run
   dry through `hs`. That holds from any number of sources, and even with
   `hs` stalled while its input ring is full.
3. `data` sends a passive keepalive (an empty transport message) when a peer
   sent data and nothing went back within KEEPALIVE_TIMEOUT (10 s).

## Design

### Cookies in `ingress`

`ingress` does cookies without `key`: the cookie reply key
`HASH("cookie--" ‖ S_pub)` is public, as the mac1 key already is, and the
cookie secret is `ingress`-local. That matches the architecture plan's
secrets table and the L13 wording. `hs` is unchanged.

**Construction (C1).**
- `cookie = MAC(secret, src_ip ‖ src_port)`, 16 bytes. The byte order of the
  port is local and opaque to the initiator. The Linux module uses
  big-endian, wireguard-go little-endian; we use big-endian [M16].
- mac2 is valid iff `mac2 == MAC(cookie, msg[..132])`. MAC is keyed
  BLAKE2s-128 with a **16-byte key**: BLAKE2s puts the key length in its
  parameter block, so zero-padding the cookie to 32 bytes would compute a
  different MAC [M18]. The comparison uses `ct_eq`.
- **Cookie reply** (type 3, 64 bytes): the receiver index, then a 24-byte
  nonce, then `XChaCha20Poly1305(cookie_key, nonce, cookie, aad = initiation
  mac1)`. The AEAD comes from the pinned
  `libcrux-chacha20poly1305 = 0.0.10` (its `xchacha20_poly1305` module).
- **Nonce:** `HASH(secret ‖ counter)[..24]`, where the counter counts within
  the current secret's lifetime. A nonce only has to be unique under a
  fixed key, and a fresh random secret per rotation makes collisions across
  boots negligible. RNDR is therefore read only to make a secret, never at
  attacker-driven rate, so a flood cannot strain the RNG that `hs` uses
  fail-closed [M14].
- **Visibility to on-path observers:** they can open cookie replies, because
  the key derives from the public S_pub. The whitepaper accepts this. A
  cookie is a bearer token for its (ip, port) for at most 120 s.

**The secret is owned by the PD's crypto adapter, not by ingress-core [M7].**
- The adapter is the PD's implementation of `CookieCrypto`. It holds
  `wg_core::cookie::CookieSecret`: zeroized on drop and on clear, and not
  `Copy`, `Clone` or `Debug`.
- It fills the secret in place from RNDR (`cpu::fill_random` into the
  secret's own storage). No secret ever travels by value.
- ingress-core keeps only `born_ns: Option<u64>` and decides *when* crypto
  may run. It therefore still depends only on `wire` and `wg-wire`, so Kani
  still applies.

**Rotation [M9, R2-S-N2].**
- The secret rotates once its age reaches ROTATE_AT (118 s = MAX_AGE − 2
  ticks). The check `tick_if_due(now)` runs on every pass of the handler
  loop (see "Handler loop") as well as on the timer notification, so a
  flood cannot postpone it.
- While no secret is held, it retries at most once per RETRY_INTERVAL
  (100 ms, tracked in the Gate). RNDR is therefore never read at
  attacker-driven rate, even while it is failing [R3-F-F5].
- Rotation is the only clearing. Each rotation zeroizes the old value, so
  no secret lives longer than about 118 s, idle or not (L12) [R2-F-F5].
- `classify` never calls crypto with a secret aged at or past MAX_AGE
  (120 s). That refusal is a backstop only: it is audited as
  `CookieSecretExpired`, separately from RNDR failure
  (`CookieSecretUnavailable`).
- RNDR failing at boot halts `ingress`, as CNTFRQ = 0 does in `data`/`hs`.

### Load, caps and the key budget

Every check below runs after length and mac1. Nothing costs a MAC or AEAD
before mac1 has passed. A mac2 of all zeros skips the mac2 MAC: it is
invalid by definition [R2-S-N3].

**Inputs, all read fresh on each pass [R2-F-F2].**
- **Forward bucket** (`FORWARD_BURST` 16, `FORWARD_INTERVAL_NS` 5 ms). A
  hard cap on initiations handed to `hs`, under load or not.
- **Arrival meter** (`ARRIVAL_BURST` 16, `ARRIVAL_INTERVAL_NS` 5 ms). Every
  mac1-valid initiation spends it, before any other gate. It measures
  offered load, so gating cannot switch load off while a flood
  continues [M2].
- **Backlog.** The number of `to_hs` buffers `hs` has not returned.
  `Sender::in_flight()` calls `reclaim()` first, so the count is never
  stale [M6, R2-F-F2].
- **TX free.** Free `to_driver` buffers, read the same way.

**Under load** [R2-F-F3, R2-S-N1] is computed afresh on each call from
the current inputs plus the stored `under_load_until_ns`. Invariant (f)
therefore holds by definition, and Kani proves that definition against the
code [R3-T-P5]:
- **When:** while any of these holds, and for UNDER_LOAD_AFTER (1 s) after
  the last one held:
  - the forward bucket is below half;
  - the arrival meter is below half;
  - backlog ≥ `BACKLOG_LOAD` (`NET_BUFFERS / 8`).
- **Why the forward trigger:** it means the forward bucket can never run
  dry outside load, whatever the arrival constants are. Kani pins this as
  "forward bucket empty ⇒ under load".
- **Under load:**
  - mac2 valid → the per-source bucket (M2), then the forward bucket.
  - Otherwise → a cookie reply.
- **Outside load:** mac2 is ignored, as in the whitepaper.
- **Ordering of the arrival constants:** `ARRIVAL_INTERVAL_NS ≥
  FORWARD_INTERVAL_NS` and `ARRIVAL_BURST ≤ FORWARD_BURST` are asserted at
  compile time in ingress-core. With them, load begins on arrivals no later
  than on forwards.
- **Accepted cost:** an attacker sending more than `1 / ARRIVAL_INTERVAL_NS`
  mac1-valid initiations/s (public key only; 200/s at the initial values)
  keeps the gateway under load. Batch 4 measured C at 740–1 650/s under
  TCG, at least 2 × the refill (CF), so the arrival constants stand and
  this figure is the one in R6 and the deviation log [R5-S-1]. Every
  handshake then pays one cookie round trip plus up to one retransmit
  (5 s + jitter). This is inherent to WireGuard cookies and is stated in
  R6.

**Cookie replies: no rate cap [M4].**
- **Why no cap:** a 64-byte reply answers a 148-byte initiation, so there is
  no amplification.
- **CPU:** cookie work is bounded by `ingress`'s L13 budget. Above that
  budget, frames are shed at the driver ring, legitimate ones in proportion
  to the flood, as on any responder. The work comes out of the same PD's
  transport capacity.
- **TX reserve:** a reply is sent only while TX free > `NET_BUFFERS / 2`;
  otherwise it is `CookieSuppressed`. Half the TX ring therefore always
  stays for `data` and `hs` [R2-F-F4].
- **Phase 2 checks that the reserve does not bind before CPU:** it measures
  `eth_out`'s drain rate against `ingress`'s maximum reply rate under TCG,
  and C6 requires no `WgCookieSuppressed` during the flood.
- **If it does bind:** a handshake-class TX reservation is added before
  Phase 3 [R2-S-N3, R2-T-N2].

**Handler loop [R2-S-N2, R3-F-F1, R3-S-P1, R3-S-P2].** In M2, `notified()`
drains each input in an unbounded `while` and notifies peers and flushes
audit only at the end. Under a flood it never returns, which starves
handshake responses, transport output, timer work and every notification.
M2.5 restructures it:

```
loop {
  a = from_hs(at most K)
  b = from_data(at most K)
  tick_if_due(now)
  c = from_outside(at most K)
  notify peers with work; audit.flush()
  if a, b and c are all < K: break
}
```

- K = `NET_BUFFERS`.
- Notifications and the flush happen at the end of *every* pass, so `hs`,
  `eth_out`, `data` and `audit` keep running during a flood.
- The pure part lives in ingress-core so it can be unit-tested: the pass
  order, the K bounds, the per-pass flush and the break rule.
- Neither an outside flood nor an inside-originated one can postpone
  `tick_if_due` by more than one pass.

**Key budget invariant [M5, R2-S-N4].**
- **Where key calls are spent:** `hs` spends key calls when it drains `ih`,
  not when `ingress` forwards.
- **Worst case:** up to `NET_BUFFERS` initiations wait in `ih`, plus one
  that `hs` has already dequeued (it frees the slot before its key calls),
  while the forward bucket refills. `hs` also spends one token on its boot
  seed.
- **The bound:**
  - `(FORWARD_BURST + NET_BUFFERS + 1) × KEY_CALLS_PER_HANDSHAKE ≤ KEY_BURST − KEY_BOOT_CALLS`,
    which is (16 + 64 + 1) × 3 = 243 ≤ 255.
  - `KEY_CALLS_PER_HANDSHAKE × KEY_INTERVAL_NS ≤ FORWARD_INTERVAL_NS`,
    which is 1.5 ms ≤ 5 ms.
  - The first inequality covers any burst. The second makes `key` refill
    faster than `hs` can spend it.
- **Per path:** `KEY_CALLS_PER_HANDSHAKE` is the maximum over every exit of
  hs-core's initiation path: unknown peer 1; decrypt, replay or flood 2;
  accept 3 [M12].
- `HandshakeKeyRateLimited` remains as the audited backstop.

**Responder only.** The gateway never initiates. Incoming cookie replies
stay `BadMessage`, and responses keep mac2 = 0 (SC19).

**Timer.** `timer` gains `ingress` as a third notification peer at 1 Hz,
with `notify` false at `ingress`'s end. The notification is one of the two
triggers of `tick_if_due`; the handler loop is the other.

**Audit visibility [R2-F-F1, R2-T-N1].**
- **Records carry no endpoint** (L10), and events are coalesced (logged at
  totals 1, 65, 129, …).
- **Never coalesced, emitted only on state edges** [R3-F-F2, R3-S-P3]:
  - `WgUnderLoad` and `WgLoadCleared`: load entered or left;
  - `CookieSecretUnavailable`: the secret became unavailable;
  - `CookieSecretExpired`: the backstop fired for the first time since a
    valid secret.

  Edges come only from the Gate's state, never from per-initiation
  outcomes, so they arrive at most about once per second each.
  audit-event gains a never-coalesced class, with tests for both classes.
- **Per-initiation refusals** (`NoCookieSecret`, `CookieSecretExpired`
  outcomes) map to the coalesced `WgCookieDropped`.
- **Coalesced:** `WgMac2Accepted`, `WgCookieSent` and `WgCookieSuppressed`
  stay coalesced, because they are attacker-rate. Tests rely only on their
  first occurrence in a fresh boot.

### Passive keepalive (C7)

Each peer in `data` keeps `unacked_since: Option<u64>`.
- **Set** to `now` when an authenticated `Forward` (data) arrives on any
  slot and the field is `None`.
- **Cleared** in these cases:
  - anything is sealed for the peer (an outbound datagram or a keepalive);
  - the peer's `current` session is dropped;
  - `current` cannot seal at fire time. Then nothing is sent and the next
    peer is still served [M19].
- **Sent:** on a tick with `now ≥ unacked_since + KEEPALIVE_TIMEOUT`, `data`
  seals an empty payload on `current`.
- **Call order:** the PD calls `keepalive()` after `inner`'s queue has been
  drained, so a reply already queued clears the state first.

At the 1 Hz tick a keepalive leaves within [10 s, 11 s + tick jitter).

Deliberate deviations from wireguard-go `timers.go`, recorded in the
deviation log [M16]:
- **Arming:** only on `Forward`. wireguard-go also arms on any non-empty
  authenticated packet, including ones that fail the allowed-IPs check.
- **Clearing:** `data` cannot see a handshake response going out, so
  sending one does not clear the state.
- **`needAnotherKeepalive` is not needed:** a keepalive covers all data
  received before it. Data received later starts a new cycle.

The keepalive's real purpose is to stop the peer's new-handshake timer,
which fires at KEEPALIVE + REKEY_TIMEOUT = 15 s, during one-way traffic.

### `make package` stays debug-only

The M2 plan tied lifting the refusal to SC13. M2.5 keeps it, because no
release-kernel image has ever been booted or tested here (R32/R41). The
refusal's comments and messages move from SC13 to SC20 (M7).

## Contracts

**C1 — wg-core cookie primitives** (`wg_core::cookie`, `wg_core::crypto`)
- **Signatures:**
  - `cookie_key(gw_public: &[u8; 32]) -> Key32`
  - `CookieSecret::fill(&mut self, fill: impl FnOnce(&mut [u8; 32]) -> bool) -> bool`
  - `CookieSecret::clear(&mut self)`
  - `make_cookie(&CookieSecret, ip, port) -> Option<Cookie>`
  - `mac2_valid(&Cookie, &[u8; INITIATION_LEN]) -> bool`
  - `reply_nonce(&CookieSecret, counter: u64) -> Option<[u8; 24]>`
  - `seal_cookie_reply(key, receiver, nonce, &Cookie, mac1) -> Result<[u8; COOKIE_REPLY_LEN], CryptoError>`
  - `crypto::mac16(key: &[u8; 16], parts) -> [u8; 16]`
- **Types:** `CookieSecret` and `Cookie` are zeroized on drop and are not
  `Copy`, `Clone` or `Debug` (L12, type-enforced).
- **Validity [R4-S-Q1]:** `CookieSecret` carries a validity flag, set
  only by a successful `fill` and cleared by `clear` or a failed `fill`.
  - `make_cookie` and `reply_nonce` return `None` without a valid secret.
  - The adapter's `mac2_valid` and `seal_reply` therefore fail closed on
    their own, even if the Gate's `born_ns` disagrees.
  - Without the flag, a zeroed secret would make anyone able to compute
    the cookie.
- **Control class:** fail-closed verification gate. The adjudication
  authority is the MAC recomputation; an error or a mismatch counts as
  invalid.
- **Acceptance [M10]:**
  - **MAC chain:** golden vectors from Python `hashlib.blake2s` for
    `cookie_key`, `make_cookie`, `mac16` (16-byte key) and `mac2_valid`.
    A one-bit flip is rejected, and so is a different port.
  - **XChaCha:**
    - a libcrux known-answer test from draft-irtf-cfrg-xchacha §A.3.1;
    - a golden `seal_cookie_reply` vector from an independent Python
      implementation: `cryptography`'s ChaCha20Poly1305 plus a pure-Python
      HChaCha20, itself checked against the draft's §2.2.1 vector.
  - **Deny:** after `fill` returns false (and after `clear`):
    - `make_cookie` / `reply_nonce` return `None`;
    - the adapter rejects a mac2 computed under the all-zero-key cookie
      for that source;
    - `seal_reply` refuses.
  - **Allow:** after a successful `fill`, the correct mac2 is accepted.
  - **Gate:** `rotate` returning false leaves `born_ns == None`.

**C2 — wg-wire cookie reply**
- **Signatures:**
  - `MSG_COOKIE = 3`
  - `COOKIE_REPLY_LEN = 64`
  - `CookieReply { receiver, nonce, encrypted_cookie }`, with total
    encode/decode
- **Acceptance:**
  - a round-trip unit test;
  - a Kani `cookie_reply_parse_is_total` harness, like the other parsers;
  - the bolero target gains the type, with a committed `seed-cookie-reply`.

**C3 — ingress-core gate**
- **Signatures:**
  - `trait CookieCrypto`:
    - `rotate(&mut self) -> bool`
    - `clear(&mut self)`
    - `mac2_valid(&self, src, msg) -> bool`
    - `seal_reply(&mut self, src, msg, out: &mut [u8; COOKIE_REPLY_LEN]) -> bool`
  - The PD plugs in C1, with the nonce derived inside `seal_reply`. The
    proofs plug in a recording stub.
  - `Gate { arrivals, forward, under_load_until_ns, born_ns: Option<u64>, entered_load: bool, last_retry_ns: Option<u64>, expired_reported: bool, unavailable_reported: bool }`
    [R4-T-Q4]
  - `classify(gate, crypto, mac1, buckets, now_ns, backlog, tx_free, src, payload, out)`
  - `Gate::tick_if_due(&mut self, crypto, now_ns, backlog) -> TickReport { rotated, secret_unavailable, left_load }`
  - `Gate::take_load_entered() -> bool`
  - `fn pass_plan(n_hs, n_data, n_outside) -> PassActions { flush: bool, continue_: bool }`
    (the handler-loop bound)
- **Constants**, all `pub`:
  - `ARRIVAL_BURST`, `ARRIVAL_INTERVAL_NS`
  - `FORWARD_BURST`, `FORWARD_INTERVAL_NS`
  - `UNDER_LOAD_AFTER_NS`, `BACKLOG_LOAD`
  - `ROTATE_AT_NS`, `COOKIE_SECRET_MAX_AGE_NS`
  - `PASS_FRAMES`, `RETRY_INTERVAL_NS`
- **Outcomes:**
  - `CookieReply { dst, len }`
  - `CookieSuppressed`, when the TX reserve is reached or `seal_reply`
    fails
  - `CookieSecretExpired`
  - `NoCookieSecret`
  - `Initiation { mac2_checked: bool, .. }`
- **Invariants** (app-enforced in `classify`, the single function every
  initiation passes):
  - (a) Under load, no initiation without a valid mac2 becomes `Initiation`.
  - (b) The `Initiation` count never exceeds the forward bucket's allowance.
  - (c) No `mac2_valid` / `seal_reply` call when `born_ns` is `None` or
    `now − born ≥ MAX_AGE`.
  - (d) No crypto call when mac1 failed. No `mac2_valid` call when mac2
    is all zero. A zero mac2 under load still gets `seal_reply` [R3-S-P4].
  - (e) No reply unless `tx_free > NET_BUFFERS / 2`.
  - (f) Forward bucket below half ⇒ under load (so empty ⇒ under load).
    It is definitional, since under-load is computed.
  - (g) At most one `rotate` call per RETRY_INTERVAL while no secret is
    held.
- **Member set (R42):**
  - `rg -n 'Outcome::Initiation \{' crates/ingress-core/src/lib.rs`: the
    single constructor.
  - `rg -n 'self\.to_hs' crates/pds/ingress/src`: the single send, fed
    only by the `Initiation` arm.
  - Both are pinned by a review checklist entry and a unit test.
- **Control class:** enforceable boundary for (a)–(f) with respect to
  `hs`'s input. `hs` has no other input channel, which L4's channel
  default-deny enforces.
- **Acceptance:**
  - **Kani harnesses** start from a symbolic `Gate`: any levels, any
    `under_load_until_ns`, `born_ns` none / fresh / aged,
    `last_retry_ns`, both edge flags, any backlog and `tx_free`. (g) is
    proved by a two-call harness at symbolic times.
    - Proved with the recording stub: (a), (c), (d), (e), (f), (g).
    - A cover for `CookieReply` with a zero mac2.
    - (b) is proved on the bucket type, plus a one-step harness.
    - The stub's `seal_reply` returns `true` with exactly
      `COOKIE_REPLY_LEN` bytes, or `false`.
    - Covers:
      - `CookieReply`, `CookieSuppressed`, `CookieSecretExpired`,
        `NoCookieSecret`;
      - `Initiation` under and outside load;
      - forward `RateLimited` under load;
      - `tick_if_due` with `rotate` both true and false.
  - **Compile-time assertions** for the arrival/forward ordering, each with
    a check-selftest case that loosens one constant.
  - **Unit tests** (each paired with its no-transition case):
    - load from each of the three triggers;
    - the 1 s hysteresis at its boundary;
    - a flood keeping load on while gated;
    - after `hs` drains with no further sends, load clears 1 s later; with
      the ring still full, it does not;
    - `in_flight` is exact after buffers return and before the next send;
    - rotation by the loop during a flood with no timer notification;
    - continuous passes never give `NoCookieSecret`;
    - a late pass past 120 s gives `CookieSecretExpired`;
    - RNDR failure gives `NoCookieSecret`. A pass before RETRY_INTERVAL
      still gives `NoCookieSecret`, and the first pass at or after it
      recovers [R4-F-F3];
    - mac2 ignored outside load;
    - mac2 all zero makes no crypto call;
    - the TX reserve: exactly half is refused, half + 1 is sent;
    - `pass_plan`:
      - K on any one input gives continue, and all below K gives break;
      - every pass with work flushes, and a pass with no wake flags does
        not notify;
      - K from `data` still runs `from_outside` and the tick in the same
        pass.
    - 1,000 `NoCookieSecret` outcomes give exactly 1 never-coalesced
      record and ⌈1000/64⌉ coalesced ones.
    - Recovery followed by a new failure gives a second never-coalesced
      record.
    - Many passes within RETRY_INTERVAL give one `rotate`; a pass after it
      retries.

**C4 — `ingress` PD and system wiring**
- **Changes:**
  - timer → `ingress` channel: layout `CH_INGRESS` / `CH_TIMER`, the timer
    `PEERS`, `.system`, `policy/laws.toml`;
  - `ring::link::Sender::in_flight()` / `free()`, each reclaiming first;
  - the bounded handler loop;
  - a separate cookie buffer;
  - a doc fix ("Holds no secret").
- **Outcome → audit event:**

| Outcome / report | Event | Coalesced |
|---|---|---|
| `take_load_entered()` | `WgUnderLoad` | no |
| `TickReport.left_load` | `WgLoadCleared` | no |
| `CookieReply` sent | `WgCookieSent` | yes |
| `CookieSuppressed` | `WgCookieSuppressed` | yes |
| `Initiation { mac2_checked: true }` | `WgMac2Accepted` | yes |
| `NoCookieSecret` / `CookieSecretExpired` outcome | `WgCookieDropped` | yes |
| Gate edge: backstop first fired | `CookieSecretExpired` | no |
| Gate edge: secret became unavailable | `CookieSecretUnavailable` | no |

- **Acceptance:**
  - laws pass.
  - **check-selftest `laws-timer-ingress` [M17, R2-F-F6, R2-T-N5]:** flips
    `notify` for `ingress` to true in both `system/secureos.system` and
    `policy/laws.toml`. It needs the exact needle
    `timer pd 'timer' is tainted`. The committed configuration is the
    allow side.
  - **check-selftest `ingress-unbounded-loop`:** restores the unbounded
    `from_outside` loop. It requires the C6 flood case to fail on its
    over-capacity data-path assertion.
  - **check-selftest `ingress-late-notify`:** moves notifications and the
    flush back after the loop. It requires the same assertion to fail.
  - **Unit tests** for `in_flight` / `free`: send, receiver return,
    reclaim, and a dead link.

**C5 — key budget invariant [M5, M12]**
- **Constants:**
  - `KEY_BURST`, `KEY_INTERVAL_NS` and `KEY_BOOT_CALLS` move from
    `crates/pds/key/src/main.rs` (today `BUCKET_BURST` /
    `BUCKET_INTERVAL_NS`) into `key-core`.
  - `KEY_CALLS_PER_HANDSHAKE` moves into hs-core.
- **Assertions:** both Design inequalities are compile-time assertions in
  hs-core's tests, with ingress-core and `layout` as dev-dependencies (no
  cycle: ingress-core depends only on `wire` and `wg-wire`).
- **Per-path test:** a counting key client asserts calls ≤
  `KEY_CALLS_PER_HANDSHAKE` on every exit path, and equality on accept.
- **Control class:** fail-closed verification gate. The adjudication
  authority is the compiler, plus the per-path test.
- **Acceptance:** separate check-selftest cases (gate `unit`), each with its
  own needle, injecting into the assertion's own operands in the test,
  never into `layout` [R2-F-A2, R2-T-N6]:
  - `FORWARD_BURST` raised;
  - the backlog operand raised;
  - the interval clause violated;
  - a fourth key call added in hs-core.

**C6 — integration (tests/integration/run.py)**
- **Topology [M1]:** the outside NIC is on a `tap` inside the netns
  (10.0.2.2/24, MAC = `outside_router_mac`).
  - wireguard-go (peer 0) talks to the gateway directly.
  - The harness injects spoofed frames, and sniffs, with AF_PACKET on the
    tap.
  - **Two fresh boots**, so each audit counter starts at zero
    [R2-F-F1, R2-T-N1]:
    - Boot "cookie-a": the keepalive case, then the paired case.
    - Boot "cookie-b": the flood case.
- **Case "passive keepalive"** (boot a, first):
  - **Allow:** the Python peer sends one datagram to an inside address that
    never answers.
    - Exactly one gateway transport message arrives between 10 s and 13 s
      after the send.
    - Decrypted with the session key, it is an empty plaintext with the
      next counter.
    - No second one arrives within a further 10 s.
  - **Deny:** an inside reply is seen to arrive first, then 13 s pass with
    no keepalive.
- **Case "cookie path, paired"** (boot a) [M10, R2-T-N7]:
  - **Load** comes from a spoofed flood between 1.2 × the arrival refill
    and 0.8·C [R4-F-F1].
    - It runs from `WgUnderLoad total=1` until the allow step's handshake
      response arrives.
    - No `WgLoadCleared` may appear in that window; if one does, the case
      aborts with its own message.
    - `WgLoadCleared` must appear in [UNDER_LOAD_AFTER, UNDER_LOAD_AFTER
      + 2 ticks + 0.5 s] = [1 s, 3.5 s] after the harness's last flood
      send. Both ends are derived from named constants in one place in
      run.py. This is the allow side of the hysteresis. The lower end is
      only a coarse integration cross-check; the C3 boundary unit test is
      what pins the 1 s length [R3-F-F4, R3-T-P4, R4-T-Q1, R5-F-F1].
  - **Learning a cookie:** from port A, the Python peer's first initiation
    draws a cookie reply. wg.py opens it.
  - **Deny:** from port B, a *fresh* initiation (new ephemeral key, newer
    timestamp) carries the mac2 made from port A's cookie.
    - Positive signal: a cookie reply arrives at port B.
    - No handshake response arrives at B.
    - No `WgMac2Accepted` line appears.
  - **Allow:** from port A, a fresh initiation with mac2.
    - `WgMac2Accepted total=1` appears, and then a handshake response at A.
    - If the deny step had been accepted, total=1 would already have
      appeared before this step, and the case fails.
- **Case "cookie under flood"** (boot b) [M1, M2, R2-S-N2, R3-F-F3, R3-T-P1]:
  - **Sources:** mac1-valid initiations from more than 64 distinct spoofed
    sources.
  - **Implementation Phase 2 measures,** under TCG, `ingress`'s
    processing rate C.
    - **Feasibility precondition (CF, settled in batch 4):** C must be
      at least 2 × the arrival refill (400/s).
      - A cookie-gated flood holds load only through the arrival meter,
        which needs `ingress` to process more than the refill.
      - Measured C: 740–1 650/s per run under TCG (deviation log, batch
        4), so `ARRIVAL_*` was not retuned.
      - At run time, the harness aborts with a distinct message if the
        measured C falls below it [R4-T-Q3, R4-F-F1].
  - **Per-run C [R5-T-S1]:**
    - Every run measures C itself, with a short over-capacity probe
      before the precondition flood: the rate of `WgCookieSent` coalesced
      totals, each line standing for 64 replies.
    - All bands derive from that per-run C, the harness prints the value
      it used, and C < 2 × refill aborts.
    - The implementation-Phase-2 figure is only the reference for the
      deviation log.
  - **Band check:** the harness asserts its own send rate against both
    bounds of each flood step, and aborts with a distinct message outside a
    band.
  - **Retry budgets** (ping tries, wireguard-go's handshake deadline) are
    sized from the measured survival ratio so a run fails by chance with
    probability below 1e-3. The calculation is recorded in the deviation
    log. The same budgets must also succeed with no flood running (allow
    side).
  - **Preconditions**, each aborting with a distinct message:
    - `WgUnderLoad total=1` appears before any peer traffic;
    - the Python-peer session is established right before Flood step 2.
      It is made under load through the cookie path, which also exercises
      wg.py's mac2 on the allow side a second time [R5-F-F1, R5-T-S2].
  - **Flood step 1, below capacity** (between 1.2 × the arrival refill and
    0.8·C; the precondition flood uses the same band). Only Flood step 2
    goes above C. Under both loop mutations step 1 still passes, so step
    2's assertion is their first failure [R4-F-F2]:
    - wireguard-go is restarted, with a fixed `ListenPort`.
    - It completes a handshake and a ping. That shows `from_hs` is not
      starved and the cookie interop works.
    - **Attribution, evaluated before the ping:**
      - the sniffer sees a type-3 datagram to wireguard-go's port, whose
        receiver index is one of the sniffed sender indices of its
        initiations, and wg.py opens it with the public cookie key;
      - then a wireguard-go initiation with non-zero mac2 is sniffed;
      - then `WgMac2Accepted total=1` appears;
      - by exclusion it is wireguard-go's;
      - `latest_handshake` changes.
    - **Continuity:**
      - no `WgLoadCleared` between `WgUnderLoad` and the handshake;
      - no `WgCookieSuppressed total=1`.
  - **Flood step 2, over capacity** (about 3·C):
    - The flood runs until the ping assertion concludes, by success or by
      exhausting its budget. The harness asserts it was still running at
      that moment, so a mutant cannot recover after the flood ends
      [R4-T-Q2].
    - The session's age stays below REJECT_AFTER_TIME minus step 2's
      budget, checked with its own abort message [R4-T-Q3].
    - the established session's ping still succeeds, within its sized
      budget. That shows `from_data` and notifications are not starved.
    - This is the assertion `ingress-unbounded-loop` and
      `ingress-late-notify` red-prove.
  - **Sniffer** [R3-T-P3]:
    - a classic BPF filter keeps only UDP to and from wireguard-go's port;
    - `SO_RCVBUF` is enlarged;
    - `PACKET_STATISTICS` with `tp_drops > 0` aborts with a distinct
      message, so a drop never reads as an attribution failure.
- **Key-exhaustion positive control [M3, R2-T-N3]: decided in batch 4,
  branch 2.**
  - **Measurement run** [R3-T-P2]:
    - The mutation disables the forward bucket, the mac2 requirement
      [R2-F-A1] *and* the per-source bucket.
    - The harness floods 60 s of initiations built with peer 1's real key
      and increasing timestamps, which take the 2–3-call path.
    - The harness records the rate `hs` actually handled, from coalesced
      `HandshakeOk` and reject totals over time.
  - **Branch 1 (rule: `HandshakeKeyRateLimited total=1` appears in the
    run):**
    - the flood case also runs a peer-keyed phase with the same
      composition, and asserts that it never appears;
    - check-selftest `integration-key-exhaustion` is the measurement
      mutation.
  - **Branch 2 (it does not appear) — taken:**
    - the clause is dropped;
    - the measured `hs` rate is recorded in the deviation log: about
      100–120 initiations/s, under 300 key calls/s against `key`'s
      2 000/s refill, with no `HandshakeKeyRateLimited`;
    - "`key` unreachable" rests on C5 and Kani (b) alone.
  - **Settled in batch 4:** the branch is recorded in the deviation log
    and the Go/No-Go row "M3" is `locked`.
- **Manifest:** `INTEGRATION-CASES` increases by 3.
- **check-selftest:**
  - `integration-cookie` removes the mac2 requirement under load. Its
    needle is the attribution assertion's message.
  - The integration-count needle becomes `10 < manifest 11`.
  - `ingress-unbounded-loop` and `ingress-late-notify` (C4). Each also
    checks that Flood step 1's PASS line printed before its needle.
  - `integration-key-exhaustion` in branch 1 only (not taken).

**C7 — data-core passive keepalive**
- **Signature:** `Data::keepalive(&mut self, now_ns, out) -> Option<(u16, usize)>`.
  It skips and clears peers that cannot seal, and returns the next one it
  sealed. The PD loops until `None`.
- **Invariants:**
  - A keepalive is sealed only on `current`.
  - At most one keepalive per unacked cycle.
  - Any sealed message clears the state.
- **Acceptance:** unit tests for:
  - data received, then a send → none;
  - data received, then 10 s → exactly one, which a receiving session opens
    as `Payload::Keepalive`;
  - keepalives only → none;
  - `current` expired → none, the state cleared, and a later peer still
    served;
  - data on `previous` → a keepalive on `current`;
  - a second data packet does not move `unacked_since`;
  - a rejected packet does not arm it;
  - a backwards clock does not fire it;
  - the 10 s boundary: exactly 10 s fires, and 10 s − 1 ns does not.

**Forbidden patterns**

- `pattern: derive\([^)]*(Clone|Copy|Debug)[^)]*\)\s*(pub )?struct (CookieSecret|Cookie)\b` — reason: L12.
- `pattern: mac2 ==|== [a-z_.]*mac2` — reason: `ct_eq` only.
- `pattern: getrandom|rand::` in `crates/` — reason: randomness comes only from RNDR through `cpu`.
- `pattern: wg-core` in `crates/ingress-core/Cargo.toml` — reason: Kani feasibility, and the secret stays outside the core [M7].

## Files to update [M13]

- **wg-core:**
  - `cookie.rs` (new);
  - `crypto.rs`: `mac16`, XChaCha seal;
  - `lib.rs`: `KEEPALIVE_TIMEOUT_NS`;
  - tests and Python vectors.
- **wg-wire:** `lib.rs`, `tests.rs`, `proofs.rs`, the bolero corpus seed.
- **ingress-core:** `lib.rs` (Outcome, `respond` / `udp` / `classify`
  parameters, SC13/R6 doc comments), `proofs.rs`, `tests.rs`.
- **ring:** `src/link.rs` (`in_flight`) and tests.
- **PDs:**
  - `pds/ingress/src/main.rs`: arms, timer, adapter, buffers, doc;
  - `pds/timer/src/main.rs`: `PEERS`, doc;
  - `pds/data/src/main.rs`: the keepalive loop;
  - `pds/key/src/main.rs`: constants moved out.
- **Other crates:**
  - `key-core`: constants;
  - `hs-core`: constant, per-path test, dev-dependencies;
  - `data-core`: `lib.rs`, `tests.rs`;
  - `audit-event`: enum, `code`, `FIXED`, `name`, `slot`, `FIXED_SLOTS`,
    the `FIXED.len()` test, and the never-coalesced class with its tests;
  - `layout`: `lib.rs`, `tests.rs`.
- **System:**
  - `system/secureos.system`;
  - `policy/laws.toml`: the channel and the "Current system" comment.
- **Tests and tools:**
  - `tests/integration/run.py`, `wg.py`;
  - `tests/manifest.txt`: `UNIT-TESTS`, every touched `UNIT-*`,
    `KANI-HARNESSES`, `KANI-INGRESS-CORE`, `KANI-WG-WIRE`,
    `INTEGRATION-CASES`, `CHECK-SELFTEST-FIXTURES` if counted;
  - `tools/check-selftest`: the new cases in `CASES` and `CASES_FOR_GATE`,
    the integration-count needle, SC13 → SC20 comments;
  - `tools/package` and `Makefile`: SC13 → SC20 text, plus any
    `test_package.py` fixture matching that text.
- **Docs:** the architecture plan's R6, the M2.5 deviation log.

## Testing strategy

- **Per contract:** unit tests and Kani as listed in each contract.
- **Independent oracles:**
  - Python for the MAC chain and the XChaCha reply;
  - wireguard-go for end-to-end cookie interop;
  - session-key decryption for the keepalive.
- **check-selftest cases:**
  - C5: four;
  - C4: `laws-timer-ingress`;
  - C6: `integration-cookie` (`integration-key-exhaustion` was for branch 1,
    not taken);
  - C4: `ingress-unbounded-loop`, `ingress-late-notify`;
  - C3: one case per arrival/forward ordering assertion.

## Considerations & constraints

- **Residual R6, narrowed:**
  - An attacker controlling many *real* source addresses, so it receives
    replies, can fill the forward bucket. Legitimate handshakes then
    compete, as in wireguard-go.
  - `key` cannot be exhausted through `hs` (C5), and `hs`'s queue cannot
    fill unseen (the backlog signal).
  - Anyone with the public key can keep the gateway under load at
    `1 / ARRIVAL_INTERVAL_NS` initiations/s (200/s initially). Every handshake then pays a cookie round trip and up
    to one retransmit.
  - A flood above `ingress`'s processing rate sheds legitimate frames at
    the driver ring in proportion to the flood, as on any responder.
  - The architecture R6 text is updated to this.
- **Compromise of `ingress`:** it yields the cookie secret, which only
  weakens DoS protection.
- **Scope contract** (IDs continue M2's sequence):

| ID | Deferred | Owner |
|----|----------|-------|
| SC19 | Responder receiving cookie replies / adding mac2 to responses | not planned (gateway never initiates) |
| SC20 | Release-kernel images: lift `make package`'s debug-only refusal, boot-test release, L10 on release (arch R4) | M7 |
| SC21 | Per-peer handshake prioritisation under a real-address flood | unscheduled |
| SC13, SC14 | Closed by this plan | M2.5 |

## User operation scenarios

1. **Flood during a handshake.** A client on a hostile network meets a
   spoofed flood. Its first initiation draws a cookie reply, and its
   retransmit (REKEY_TIMEOUT 5 s plus up to 333 ms of jitter) carries mac2
   and succeeds.
2. **NAT rebinding.** A client behind NAT is rebound to a new port while the
   gateway is under load. Its cookie no longer matches, so it gets a new
   reply and one more retransmit.
3. **Idle period.** The link sits idle for 10 minutes. The secret keeps
   rotating every 118 s, and each old value is zeroized.
4. **One-way traffic.** A client streams one-way to an inside collector.
   The gateway's keepalives (one per 10–11 s) keep the client from
   starting a new handshake every 15 s.

## Carried-Forward Plan Findings

Plan review closed at Round 5 by saturation; every Round-5 finding is
resolved in rev 6. Two decisions were carried into Phase 2 by design,
because they depend on measurements under TCG; batch 4 settled both.

### M3 [Major, Round 1] Key-exhaustion positive control — Decided in batch 4 (branch 2)
- **Anti-Deferral check:** this is a measurement-dependent branch, not a
  deferred fix. Both branches are specified in C6.
- **Cost of not deciding now:** none to correctness. C5 and Kani (b)
  carry "`key` unreachable" in either branch.
- **What would settle it:** the C6 measurement run (forward bucket, mac2
  gating and per-source bucket disabled; peer-keyed flood for 60 s)
  either shows `HandshakeKeyRateLimited total=1`, giving branch 1, or does
  not, giving branch 2.
- **Outcome:** no `HandshakeKeyRateLimited` in the measurement run;
  branch 2 (deviation log, batch 4). Go/No-Go row M3 is `locked`.

### CF [Minor, Round 4] Flood-case feasibility — Decided in batch 4 (feasible)
- **Anti-Deferral check:** a measurement precondition, not a deferred fix.
- **Cost:** if it fails, the arrival constants are retuned within the
  compile-time ordering assertion, and R6's accepted-cost figure is
  updated to match.
- **What would settle it:** the measured C ≥ 2 × the arrival refill.
- **Outcome:** C measured at 740–1 650/s per run, at least 2 × the
  200/s refill; no retune (deviation log, batch 4). Go/No-Go row CF is
  `locked`.

## Go/No-Go Gate

| ID | Subject | Status |
|----|---------|--------|
| C1 | wg-core cookie primitives, secret types, 16-byte MAC | locked |
| C2 | wg-wire cookie reply | locked |
| C3 | ingress-core gate: load (forward, arrivals, backlog), mac2, caps, rotation, pass plan | locked |
| C4 | ingress PD, timer channel, `in_flight`/`free`, bounded loop, audit classes | locked |
| C5 | key budget invariant incl. ring backlog | locked |
| C6 | integration: tap, two boots, keepalive, cookie paired, flood; M3 branch 2 | locked |
| C7 | data-core passive keepalive | locked |
| M3 | Key-exhaustion branch decision (batch 4 measurement: branch 2) | locked |
| CF | Flood-case feasibility C ≥ 2 × arrival refill (batch 4: C 740–1 650/s) | locked |

## Implementation Checklist

Base ref for every diff: `feature/m2-wireguard` (`3750758`). M2 is not on
`main` yet.

**Carried-forward items** (from the section above):
- M3: decided in batch 4 by measurement.
- CF: decided in batch 4 by measurement.

Each gets a deviation-log entry when decided.

**Batches** (files are disjoint within a batch):
1. **Batch 1a — C1, C2:**
   - `crates/wg-core/{src/cookie.rs (new), src/crypto.rs, src/lib.rs (pub mod cookie, KEEPALIVE_TIMEOUT_NS), src/tests*.rs, Cargo.toml if a feature is needed}`
   - `crates/wg-wire/{src/lib.rs, src/tests.rs, src/proofs.rs, src/__fuzz__/…/corpus/seed-cookie-reply}`
   - Python vector generator under `tests/tools/` (checked-in script, with
     its output pinned in the Rust tests)
2. **Batch 1b — ring, audit-event, C5:**
   - `crates/ring/src/link.rs` (`in_flight`, `free`, both reclaiming
     first) plus tests (and proofs if the existing harnesses touch
     `Pool`);
   - `crates/audit-event` (new events, never-coalesced class, `FIXED`,
     `FIXED_SLOTS`, tests);
   - `crates/key-core` (`KEY_BURST`, `KEY_INTERVAL_NS`, `KEY_BOOT_CALLS`);
   - `crates/pds/key/src/main.rs` (uses them);
   - `crates/hs-core` (`KEY_CALLS_PER_HANDSHAKE`, per-path counting test,
     const asserts; dev-dependencies on `ingress-core` and `layout`). The
     asserts reference ingress-core constants that land in batch 2, so 1b
     adds the asserts against placeholder-free names only after batch 2,
     or batch 2 adds them.
3. **Batch 2a — C7:** `crates/data-core`, `crates/pds/data/src/main.rs`.
4. **Batch 2b — C3:** `crates/ingress-core/{lib.rs, proofs.rs, tests.rs}`,
   plus the hs-core C5 const asserts that need its constants.
5. **Batch 3 — C4:**
   - `crates/pds/ingress/src/main.rs`;
   - `crates/pds/timer/src/main.rs`;
   - `crates/layout/{lib.rs, tests.rs}`;
   - `system/secureos.system`;
   - `policy/laws.toml`.
6. **Batch 4 — C6, gates, M3/CF:**
   - `tests/integration/{run.py, wg.py}`;
   - `tools/check-selftest` (new cases);
   - `tests/manifest.txt`;
   - SC13 → SC20 text in `tools/package`, `Makefile`,
     `tests/tools/test_package.py`;
   - the architecture plan's R6;
   - the deviation log.

**Shared code that must be reused, not reimplemented:**
- `wg_core::crypto::{hash, mac, ct_eq}` (add `mac16` beside `mac`);
- the `libcrux-chacha20poly1305` `xchacha20_poly1305` module;
- `cpu::fill_random` (zeroes on failure);
- the token-bucket shape of `ingress_core::Buckets` and `key_core::Bucket`;
- `pdkit::{send, recv, Audit}`;
- `ingress_core::emit_udp`;
- `msgs::ToIngress::Outbound` (keepalives);
- `audit_event` coalescing (`COALESCE_EVERY`).

**Patterns to follow at every site:**
- `#![deny(clippy::indexing_slicing, unwrap_used, expect_used, panic, arithmetic_side_effects)]`
  in core crates;
- secret types are not `Copy`, `Clone` or `Debug`, and are zeroized on
  drop;
- totals and decoders are total;
- every new gate gets a check-selftest case.

**Not applicable:**
- No CI (SC9). `make check` is the full local gate, and no parity diff
  exists.
- The fingerprint hook does not support Rust; the inventory above is
  manual.
- No `feedback_*` memories.
