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
  kind). Instead `ring::link::Sender::new_scrubbing` zeroes the entire region
  at construction (shared pages have no assumed initial contents), then each
  returned buffer in `reclaim()`, which `hs` runs on every notification;
  `data` notifies right after copying an install out, and the 1 Hz timer
  retries. Both PDs zero their private copies. The integration test reads
  `hd_data` through the QEMU monitor after each handshake and requires it to
  be all zero.
- **`key`'s own IPC buffer** keeps its last reply until the next call. Only
  `key` can read it and it holds the static secrets anyway; registers beyond
  each reply are zeroed so no earlier, longer reply reaches `hs`.
- **At most 8 peers and 64 inside neighbors per image.** One constant
  (`config::MAX_PEERS`, from `validate.rs`) bounds the validator, mksecrets
  and every PD table; build.rs asserts it fits the secrets region, and each
  PD asserts at compile time that the configuration fits. A configuration
  that builds therefore boots. The bound comes from `data`: a
  `ReplayWindow<2048>` stores one bool per slot (~2.1 KiB per session); the
  state size is asserted against the stack. Revisit with a bit-packed window.
- **`hs` makes three `key` calls per handshake** (StaticDh for es and ss,
  PskMix). An unknown peer is still rejected after the first (before ss), as
  planned. `key`'s bucket: burst 256, refill 2000/s; exhaustion is audited as
  `HandshakeKeyRateLimited`. mac1 needs only the published gateway key, so
  anyone holding the image can drain that shared budget with spoofed
  sources until cookies land (architecture R6, SC13).
- **Receiver indices are issued only after authentication** (wg-core asks
  for one once the replay and flood checks pass), so rejected initiations
  cannot use up the 2^32 index space.
- **Session clocks start in `data`.** `msgs::Install` carries no timestamp:
  `data` stamps its own CNTPCT at install, so a compromised `hs` cannot keep
  a session past REJECT_AFTER_TIME.
- **Endpoint updates only on change.** `data` sends `EndpointUpdate` when an
  authenticated new highest counter comes from a source other than the one
  `ingress` last accepted, and records it only once the send succeeded.
- **Inside forwarding keeps the datagram, lowers TTL.** `wire::parse_frame_ip`
  returns `Body::Ipv4` with the datagram as received (re-encoding would
  rewrite ID/flags); `wire::forward_ipv4` decrements TTL, recomputes the
  header checksum and drops TTL <= 1 (`TtlExpired`), in both directions
  through `inner`, so a routing loop through the gateway dies out.
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
- **Package output.** `tools/package` applies one forbidden-root predicate
  (repository incl. `build/`, cargo and rustup homes) to both the blob and
  OUT, requires OUT not to exist, builds in a 0700 staging directory under
  umask 077 and renames it into place only after every check passed.
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

## Known gaps

- No Kani harnesses for `data-core`, `hs-core`, `key-core` (they compile
  libcrux); covered by unit tests and mutation runs instead.
- Transient key copies on the stack (`Key32::from_bytes(*array)`) and
  libcrux's internal state are not zeroized.
- The send-counter-exhausted path in `data` is tested only in wg-core.
