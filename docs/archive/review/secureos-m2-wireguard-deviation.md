# Deviation log: secureos-m2-wireguard

Implementation decisions not spelled out by plan revision 4, or departing
from it. Each entry: what changed, why, and what it costs.

## Structure

- **Decision logic in `*-core` crates.** `key-core`, `hs-core`, `data-core`,
  `inner-core` and `ingress-core` v2 hold all logic as pure, host-testable
  code; the PD binaries only move bytes. `hs-core`'s tests drive a full
  handshake through the real `key-core` oracle (the PPC replaced by a direct
  call), so the key/hs contract is tested without QEMU.
- **`msgs` crate** defines every inter-PD message layout with total decoders
  (Kani: round trip of the small decoders). Not named in the plan; C11/C12/C14
  needed one shared contract.
- **`pdkit` crate** (links, audit producer) and **`cpu` crate** (CNTPCT,
  CNTFRQ, RNDR with bounded retries) remove per-PD boilerplate; `cpu` is the
  only new `unsafe` (inline `mrs`).
- **Every inter-PD channel is a `ring::link`** (used ring, free ring, data
  region of 64 × 2 KiB), including the small hs links. Simpler than typed
  rings, and reuses the Kani-proved code.

## Behaviour

- **Install residue (S6).** The plan had `data` zero the install slot after
  copy-in, but the consumer maps link data regions read-only (L3 `data`
  kind). Instead `ring::link::Sender::new_scrubbing` zeroes each buffer when
  it returns to `hs`, and both PDs zero their private copies.
- **`data` holds at most 8 peers** (`MAX_PEERS` in the PD) and halts at boot
  if the configuration has more. A `ReplayWindow<2048>` stores one bool per
  slot (~2.1 KiB per session, ~6.3 KiB per peer); the config format still
  allows 61. Revisit with a bit-packed window.
- **`hs` makes three `key` calls per handshake** (StaticDh for es and ss,
  PskMix). An unknown peer is still rejected after the first (before ss), as
  planned. `key`'s bucket: burst 256, refill 2000/s.
- **Inside forwarding is verbatim.** `wire::parse_frame_ip` returns
  `Body::Ipv4` with the datagram exactly as received; re-encoding would
  rewrite ID/TTL/flags. The outside parser is unchanged (UDP only). TTL is
  not decremented.
- **Endpoints.** `ingress` learns a peer's endpoint only from `data`'s
  `EndpointUpdate` (first authenticated transport packet with a new highest
  counter); outbound traffic before that is dropped and audited
  `NoSession`. Responder-only clients always send first, so this is
  invisible in practice.
- **Audit codes.** Handshake rejections are fixed events
  (`HandshakeUnknownPeer`, `HandshakeDecrypt`, …) rather than a
  parameterised `HandshakeRejected{reason}`, so `audit` names them without a
  second decode table.
- **Timer role in C7.** New `timer` role: may own device mrs and IRQs; its
  device does not seed taint; exemption as amended in L1 (S14); additionally
  a tainted timer is itself an L1 finding, so a shared mr cannot silently
  revoke the exemption.
- **Package diff.** Verified empirically that prefill bytes land verbatim and
  contiguously in the loader image, so `tools/package` requires every
  differing byte to lie inside the single occurrence of the blob, over zeros
  in the placeholder build.
- **Seccomp drift check** compares a canonical hash of the profile minus our
  entry with the pinned Docker default (offline), instead of vendoring the
  default profile.

## Test environment

- wireguard-go needs `/var/run/wireguard` for its UAPI socket; the image now
  creates it owned by `dev`. The socket directory is shared by every netns in
  the container, so the harness names the interface per run.
- PD console output interleaves at character level during boot (several PDs
  print concurrently), so readiness is functional (ARP reply, completed
  handshake), not matched on "ready" lines.

## Known gaps (carried to Phase 3)

- No Kani harnesses for `data-core`, `hs-core`, `key-core` (they compile
  libcrux); covered by unit tests and mutation runs instead.
- Transient key copies on the stack (`Key32::from_bytes(*array)`) and
  libcrux's internal state are not zeroized.
- The send-counter-exhausted path in `data` is tested only in wg-core.
