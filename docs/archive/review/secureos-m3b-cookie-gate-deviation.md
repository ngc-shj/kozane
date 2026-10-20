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
