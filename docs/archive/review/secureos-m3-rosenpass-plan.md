# Plan: secureos-m3-rosenpass (rev 7, scope M3a)

M3a makes the VPN post-quantum. The gateway runs a Rosenpass V02
responder in a new `pq` PD, whose McEliece secret lives in a new passive
`pqkey` PD, and `hs` installs WireGuard sessions only with a fresh
Rosenpass PSK (L8). Rosenpass's own cookie gate, its flood cases and the
OSK residue scan move to **M3b** (SC26). Until then images stay dev-only,
which `make package`'s debug-only refusal already enforces (SC20).

Base: M2.5 at `5b406c4`. The review IDs cited below are as follows:
- **F, S and T numbers:** Round-1 findings, recorded in the review
  artifact.
- **Feasibility facts:** also in the review artifact, with upstream
  citations against rosenpass `9e72f1eb` and `0.2.3`.

## Project context

- **Type:** `mixed`.
- **Test infra:** unit tests, Kani, bolero and a QEMU integration suite
  behind `make check`, plus check-selftest. There is no CI.
- **Verification environment:**
  - M2/M2.5 VE1–VE8 still apply.
  - **VE9: the interop oracle is baked into the dev image** [T2, S16].
    - A Dockerfile stage builds upstream rosenpass at master
      `9e72f1eb871c4c403e99e9b78262fff8dd8d7357` and `0.2.3` (tag
      commit `512fe426…`).
      - Source: the GitHub archive of each commit, checked with
        `sha256sum -c`, which satisfies check-pins P1 unchanged
        [R2-S-N5]. Then `cargo fetch --locked` and
        `cargo build --locked --offline`.
      - Toolchain: pinned through rustup.
      - Isolation: the stage has no `/work` or secrets mounted.
    - cmake and `libsodium-dev` come from the already-pinned apt
      snapshot.
    - The binaries install to `/opt/rosenpass-{master,023}`.
    - Their SHA-256 values are committed in the repo; `preflight()`
      checks them and fails with "rebuild the image".
      - Committing these hashes assumes the build is bit-reproducible.
        Phase 2 builds twice with `--no-cache` to check that.
      - If the builds differ, the image records its own hash and source
        commit, and preflight compares the recorded commit with the repo
        pin [R2-T-N8]. That fallback is only a tripwire for a stale image.
        The assurance comes from the sha256-checked source archives and the
        committed `Cargo.lock` [R3-S-M4].
    - check-pins rules and fixtures cover the new stage.
    - The oracle never enters an image (asserted).
  - **VE10: cost measurement (marker `MCE-COST`)** [F4, T7, S3]. Phase 2
    measures the following in-PD under TCG, with `opt-level = "s"`
    release builds, N ≥ 20, reporting median and max:
    - CPU time and wall-clock time for:
      - `pqkey` decapsulation;
      - `pq`'s McEliece and Kyber encapsulations;
      - the hashing of the 524 KB keys;
      - the whole InitHello → RespHello path at the committed budgets;
    - stack high-water marks, by stack painting, for `pq` and `pqkey`;
    - `hs` handshakes per second at its proposed budget;
    - `ingress`'s cost per Rosenpass datagram;
    - the worst-case delay `pqkey` imposes on `hs` [R2-F-N4, R2-S-N7].
  - **Re-checked every run [R2-T-N6, R3-T-M3, R3-F-R3-4]:**
    - `PQ_HANDSHAKE_COST_NS` is a constant in a production crate, set from
      MCE-COST. The `RP_*` and `PQ_KEY_*` assertions derive from it.
    - `pq` emits a new non-coalesced event, `RpCostHighWater`, only when
      its measured handshake cost exceeds the last **emitted** value by
      at least 1/8 (the first measurement always emits). That bounds it to
      about `log₁.₁₂₅(max/min) + 1` events per boot (L10), tested with a
      monotone cost sequence. The reported maximum is never more than
      12.5% below the true maximum, so a too-low constant cannot pass by
      more than that margin [R6-S-Q1′].
      - The cost is wall-clock CNTPCT ns including preemption. Microkit
        exposes no consumed-budget call, so it is measured in a quiet
        window.
      - The event's value travels on a new value-carrying record path in
        `audit-event`: a closed variant whose `a` is the **exact**
        measured cost in µs at emission, not the running count. The 1/8
        rule only gates how often the event fires. The test checks that
        `a` holds the exact cost. No red-proof places the constant at a run-dependent value; only the deterministic red-proofs below are used [R4-S-P2, R4-F-R4-2, R5-F-R5-2, R6-T-S1].
      - At the boundary, a cost exactly at the constant plus slack passes,
        and one above it fails. One red-proof injects a cost of
        constant × 1.5, which must fail; the measured production cost is the
        allow side [R5-S-Q1]. Another red-proof uses a sequence that first
        reports a low cost and then rises by 1.5 × the constant, which must
        also fail [R6-S-Q1′].
    - run.py reads the constant with `rust_const`. It checks the last
      high-water mark from a quiet window, before any flood, against the
      constant plus a named slack.
  - **Guard pages [R2-S-N10]:** Phase 2 also answers whether Microkit 2.3.1
    puts a guard page below each PD stack. The answer is a citation from
    the tool or loader, or a residual entry if there is none.

    The committed command and its results go in the deviation log. They
    size the budgets, buckets and stacks.
- **Every acceptance path is verifiable-local.**

## Objective

1. **Responder.** The gateway is an upstream-compatible Rosenpass **V02
   responder**: Classic McEliece 460896 round 3, Kyber-512 round 3,
   incorrect-HMAC BLAKE2b, and ChaCha20-Poly1305 / XChaCha20-Poly1305.
   Clients always initiate. **Production requires master-line clients**;
   0.2.3 serves as a second interop oracle [S6].
2. **L8.** `hs` accepts a WireGuard initiation only with a fresh PSK for
   that peer. The PSK is the Rosenpass OSK, installed by `pq` less than
   REJECT_AFTER_TIME (180 s) ago by `hs`'s CNTPCT.
   - There is no static or zero PSK, structurally: the static PSKs leave
     the blob, and the WireGuard PSK path takes `&FreshPsk` [S9, S13].
   - Until the first Rosenpass exchange after a boot, every WireGuard
     initiation is refused. After it, a replayed pre-reboot initiation can
     only replace an unconfirmed `next` slot, which is a residual [S11,
     F23].
   - "Fresh" counts from the moment the PSK is installed. An on-path
     attacker can withhold an InitConf for up to two biscuit epochs
     (about 600 s), and its OSK still counts as fresh once installed. This
     is a residual [R2-S-N9].
3. **Separate secrets.** The McEliece secret lives only in `pqkey`, which
   exposes only `PQ_DECAPS` and `PQ_BOOT_SEED`. `pq` cannot reach `key`, and `hs` cannot reach
   `pqkey` [S1, S3, F2].
4. **Bounded work.** No input type reaches `pq` unmetered. Forged
   InitHellos and InitConfs are bounded per source and globally, and every
   other Rosenpass type is dropped at `ingress` [F7, S5].

## Design

### PDs, roles, channels

- **`pqkey`: a new passive PD with role `key`.**
  - **Secrets:** its own secrets MR holds the McEliece secret key and its
    binding data (C2).
  - **Priority:** above `pq`, below `timer`.
  - **Interface:** two oracle labels, `PQ_DECAPS` and `PQ_BOOT_SEED`,
    served to its single caller `pq` over PPC [R2-S-N6].
  - **Cost model:** decapsulation runs on `pq`'s scheduling context, at
    priority 130, so it can preempt `hs`. The delay is bounded by `pq`'s
    budget and period, and MCE-COST records the worst case [R2-S-N7].
    `key` itself is never blocked by it.
- **`key`.** WireGuard secrets only. It drops `PSK_MIX`.
  - **Callers:** `hs` only, enforced by a caller → labels table in
    `key-core`: `Hs → {STATIC_DH, BOOT_SEED}` [S1].
  - **Refusals:** an unknown channel, or a label outside the table, is
    refused before any bucket is spent.
  - **Same mechanism in `pqkey-core`:** `Pq → {PQ_DECAPS, PQ_BOOT_SEED}`.
- **`pq`: a new PD with role `untrusted_input` [S4, F15].**
  - **Fed by:** `ingress` only.
  - **Calls:** `pqkey` by PPC.
  - **Sends:** `PskInstall` to `hs` over a scrubbing link. `hs` notifies
    `pq` after copying, so `pq` reclaims and scrubs [F8].
  - **Timer:** gets ticks for biscuit-key rotation.
  - **Audit:** has its own audit MR and channel [F18].
  - **Peer public keys:** our `spkm` and each peer's `spkt`, about 4.5 MiB,
    are **embedded in `pq`'s ELF** from the generated config. They are
    covered by L6's image hash, with no new prefill MR [F9, S14].
    - The config build writes the key files to `OUT_DIR`, and only `pq`
      loads them, with `include_bytes!`.
    - `gateway.toml` names the key files by path. The committed
      placeholder keys live under `config/keys/` [R2-F-N9].
  - **Boot check:** `pq` verifies that `H(spkt[i]) == config::PEERS[i].rp_hash`
    [S8].
- **`ingress`.**
  - **Demux:** WireGuard arrives on `listen_port` and Rosenpass on an
    explicit `rp_port`, a config field validated as nonzero and distinct
    [F20].
  - **Accepted types:** only 0x81 (InitHello) and 0x83 (InitConf). Every
    other Rosenpass type is dropped [F7, S5].
  - **The mac:** checked through a `RpMac` trait whose key is a build-time
    constant `lhash("mac", spkm)`. The PD adapter does the keyed BLAKE2b,
    so `ingress-core` stays crypto-free and Kani-able [T12].
  - **Buckets:**
    - InitHello: per source, then global (`RP_HELLO_*`);
    - InitConf: its own per-source and global meters (`RP_CONF_*`).

    The constants are sized from MCE-COST, retransmissions included.
    Compile-time assertions in a production crate tie them to `pq`'s
    budget.
  - **Ring reservation:** a reserved share of the `ingress`→`pq` ring
    keeps InitConf from starving InitHello.
    - `ingress` counts outstanding forwards per message type, and the
      count drops on reclaim.
    - A unit test shows InitConfs cannot take the reserved share
      [R2-F-N10].
  - **Forward constructors:** exactly two, `rp_forward_hello` and
    `rp_forward_conf`, each pinned by a test. The `rg` check is declared a
    tripwire [F7, S13].
- **`hs`.** It holds `PskTable { peer → Entry }`, with `enum Entry { Absent, Live { osk: Secret<32>, installed_at }, Expired { installed_at } }`. Only `Live` can yield a `FreshPsk`. The expired state is its own variant, never a zeroed OSK, so no path can hand out a zero PSK [R4-S-P1].
  - **Order of checks** [F1, S11, R2-F-N1, R2-S-N4]:
    1. the `es` DH;
    2. the static-key decrypt and peer lookup;
    3. `ss`;
    4. the timestamp decrypt;
    5. the replay and flood checks;
    6. **`PskTable::fresh(peer, now)`**, which returns `FreshPsk` or refuses
       with `HandshakePskMissing` / `HandshakePskStale`;
    7. the commit.

    The timestamp key is derived from `ss`, so this is the earliest point
    at which the sender is authenticated. A refusal therefore costs 2 key
    calls, and never commits replay or flood state.
  - **Expiry:** `hs`'s 1 Hz tick turns every `Live` entry at or past
    REJECT_AFTER_TIME into `Expired { installed_at }`, zeroizing the OSK
    (L12). A later initiation is refused as `HandshakePskStale`;
    `Absent` gives `HandshakePskMissing` [R2-F-N6, R4-F-R4-5].
  - **Key calls:** a handshake makes 2 `key` calls, so
    `KEY_CALLS_PER_HANDSHAKE` = 2 on every path. The C5 assertions and the
    per-path test are updated, and the assertions now live in hs-core's
    library.
  - **WireGuard PSK path:** wg-core's `StaticKey::psk_mix` is removed. The
    responder takes `&FreshPsk` and mixes it itself [F1].
  - **Draining:** `hs` drains `pq`'s link before `ih` in every pass [F8].
- **Budgets [F3, S4, R2-F-N4, R2-S-N8].** `ratio_sum_cap` stays 0.9 if
  the measured costs fit.
  - **Tainted PDs today:** they use 0.85, made up of:
    - `eth_out`, `eth_in`, `ingress`, `inner`: 0.1 each;
    - `hs`, `data`: 0.2 each;
    - `audit`: 0.05.
  - **Rebalance:** MCE-COST settles the values; nothing is cut without data.
    Removing `PSK_MIX` saves `hs` no CPU, because its `kdf3` already ran
    on `hs`'s scheduling context.
    - If `pq`'s measured need does not fit under 0.9, the cap may be raised,
      with the change recorded in the Law amendments table (L13). The hard
      ceiling is 0.95. That leaves the untainted `timer` reservation
      (0.01) and margin for the passive PDs' init. Their per-call time is
      already counted in their callers' budgets [R4-F-R4-3]. Needing more
      than 0.95 means re-planning, not an amendment.
      The fixtures check the ceiling ± ε [R3-S-M2].
    - The laws fixtures pin both sides: an at-cap allow case and an
      over-cap deny case.
    - The remaining headroom is recorded.
  - **Priorities:** `pqkey` (passive, 130) > `pq` (105) > `ingress`
    (100). `key` stays at 140 and `timer` at 150.
- **Randomness [S7, F16].**
  - **Consumers:** `pq` needs it for:
    - the Kyber encapsulation (RHR4);
    - the McEliece encapsulation (RHR5);
    - `sidr`;
    - the biscuit keys and the biscuit counter.
  - **Hedging:** `pq` draws through a hedged source, using hs-core's
    `HedgedEntropy` pattern over RNDR, CNTPCT and a `pq` boot seed.
  - **The boot seed** [R2-F-N5, R2-S-N3] comes from `pqkey`'s
    `PQ_BOOT_SEED` label.
    - It is computed as `BLAKE2s("pq-boot-seed" ‖ blob_seed ‖ RNDR ‖ CNTPCT)`,
      where `blob_seed` is an independent 32-byte field in the `pqkey` blob,
      distinct from `key`'s seed.
    - The value is the same for the whole boot.
    - `pq` calls it once at init and halts if it is refused. If `pqkey`
      itself halted at boot (a failed KAT or `H(spkm)` check, or RNDR
      unavailable — `pqkey` halts on RNDR failure as `key` does
      [R3-S-M3]), `pq` blocks on the call. That still fails closed: there
      is no PSK, so WireGuard is refused. The boot-check fixtures use
      `pqkey`'s halt message plus the absence of `pq: ready` as their
      needles [R3-F-R3-5].
    - `PQ_KEY_*` reserves `PQ_BOOT_CALLS` = 1 for this call.
  - **Failure:**
    - A failed draw aborts that handshake.
    - A failed biscuit-key rotation leaves `Option::None`. `pq` then
      refuses InitHello and InitConf until a later rotation succeeds; a
      zeroed or stale key is never used.
    - RNDR failing at boot, or CNTFRQ = 0, halts `pq`.
- **OSK export order [F8, S15].** On a fresh, authenticated InitConf (ICR1–7):
  1. send `PskInstall { peer, osk }`;
  2. **only if** the send succeeded: commit `biscuit_used`, store the
     cached EmptyData under a keyed hash of the **whole** InitConf (as
     upstream's `KnownResponseHasher` does), send EmptyData, and zeroize
     `ck` and the OSK in `pq` [F22].

  A failed send leaves no trace, so the client's retransmission is
  processed again. The cache lookup runs **before** `handle_init_conf`
  [F17].
- **Secret types [S12].** Every value derived from ck, from a KEM shared
  secret, from a biscuit plaintext or from the RNG is held in one
  `Secret<N>` type (zeroize on drop, not `Copy`/`Clone`/`Debug`). This
  includes `pqkey`'s reply registers and per-call secret-key copy, and
  `hs`'s and `pq`'s input and scratch buffers, which are zeroed after use.
- **Panics [S6].** `rosenpass-core`, `rosenpass-wire`, `pqkey-core` and
  the PDs carry the workspace's clippy denies. Panics inside dependencies
  (cmr, libcrux) are a residual: they halt `pq`, and under L8 that is a
  total WireGuard outage until reboot.

### Law amendments (architecture plan; each needs sign-off in this plan's review) [S10, S2]

| Law | Change | Residual |
|---|---|---|
| L1 | New tainted PD `pq` (`untrusted_input`), new channels, a second `key`-role PD | — |
| L2 | "At most one `key` PD" becomes "`key` PDs with disjoint secret MRs and disjoint caller sets, each a closed label table". Enforced mechanically [R2-S-N1, R2-F-N3]: every `kind = "secrets"` MR names an `owner`; it is mapped only by that owner; each key PD maps exactly its own; `prefill_path` is allowed on secrets MRs only; no PD has a `pp` channel to two key-role PDs; an MR with no owner is a policy error. McEliece uses implicit rejection, so its input rule is an exact length check. **The constant-time libcrux clause is waived for `pqkey`:** cmr 2.0.2 is unaudited, and no constant-time verification exists | Possible secret-dependent timing in McEliece decoding, observable through RespHello latency. The images are dev-only (SC20) and replacing the crate is SC23. The `PQ_DECAPS` query rate is bounded by `RP_HELLO_*`; its per-day bound is recorded in the deviation log |
| L6 | 4.5 MiB of public keys enter the `pq` ELF. Two secrets blobs instead of one: `key` blob v2 and `pqkey` blob v1, with distinct magics. `tools/package` masks both ranges and swaps both `prefill_path`s [R2-F-N7, R2-F-N8] | none (public, hashed) |
| L8 | Now enforced, with the wording above | The replay residual on `next` |
| L13 | `pq` budget, a rebalanced sum, new priorities | — |
| Packaging | `tools/package` refuses non-debug kernels while `policy/waivers.toml` lists any open waiver (SC23, SC26), naming each one, in addition to SC20. A missing or unparsable waiver file means refuse. The file's schema is `id`, `owner`, `status`. The control class is a fail-closed gate that can be bypassed by editing the file. A check-pins consistency rule binds SC23 to its condition: while `Cargo.lock` contains `classic-mceliece-rust 2.0.2`, `waivers.toml` must list SC23 with `status = "open"` (fixtures: deny / allow / allow, plus cmr present with SC23 closed → deny) [R4-F-R4-4]. SC26 has no mechanical signal and stays manual [R3-S-M1]. The waiver check is proven in `tests/tools/test_package.py` with the SC20 predicate stubbed to pass, so the debug refusal cannot mask it: an open waiver refuses and names itself; a missing or unparsable file refuses; no open waiver allows. A check-selftest case removes the waiver check, with the waiver's name as the needle [R2-S-N2, R3-T-M4] | — |
| R6 | Now also covers Rosenpass: in M3a, an anonymous mac-valid InitHello flood can cut every Rosenpass rekey. L8 then refuses WireGuard after 180 s | Closed by the M3b cookie gate (SC26) |

## Contracts

**C1 — `rosenpass-wire` (new, dependency-free, Kani crate) and
`rosenpass-core` (new, no_std)**
- **`rosenpass-wire`:**
  - total encode and decode for the envelope and for InitHello, RespHello,
    InitConf and EmptyData;
  - in `kani_crates` and the bolero targets, with seeds from upstream
    captures [T12].
- **`rosenpass-core`:**
  - the V02 hash tree, including the root string's historical "BLAKE2s";
  - biscuits;
  - the responder state machine, with the known-InitConf cache;
  - OSK derivation.
- **Seams:** `Decaps`, `Encaps` (Kyber and McEliece, so tests can replay
  upstream's ct/shk values [T1]), `Rng` and the clock.
- **Golden vectors [T1]:**
  - **Driver:** a committed `tools/rp-vectors/` with its own
    `Cargo.lock`, built against upstream `9e72f1eb` with
    `expose_internal_modules` in **V02**. It drives upstream's
    `test_vec_case` init mode.
  - **Output:** committed hex/JSON whose header names the upstream
    revision and the features used.
  - **Use:** pinned in the unit tests. A check-selftest case changes one
    domain label and requires `unit` to fail.
- **Unit tests:**
  - deterministic encapsulation KATs for cmr McEliece and libcrux Kyber
    [R2-T-N12];
  - replay: `biscuit_no` not greater than `biscuit_used` is refused;
  - the same biscuit with a different authenticator is refused, does not
    export and gets no cached answer;
  - an identical retransmission gets the cached EmptyData and does not
    export;
  - a biscuit-key rotation keeps the previous key for one epoch;
  - a failed rotation (RNG failure) refuses InitHello and InitConf, and the
    next good rotation recovers;
  - a failed `PskInstall` produces no EmptyData, and a retransmission then
    succeeds.

**C2 — `pqkey` PD and `pqkey-core`**
- **Oracle:**
  - `PQ_DECAPS`: a request of exactly 24 words whose trailing 4 bytes must
    be zero [F13, S18], and a 32-byte reply;
  - `PQ_BOOT_SEED`;
  - its own bucket, `PQ_KEY_*`, sized by MCE-COST.
- **Bucket assertion:** compile-time, in a production crate:
  `(RP_HELLO_GLOBAL_BURST + pq ring backlog + 1) × 1 ≤ PQ_KEY_BURST − PQ_BOOT_CALLS`
  and `PQ_KEY_INTERVAL_NS ≤ RP_HELLO_GLOBAL_INTERVAL_NS` (one
  decapsulation per InitHello) [R3-S-M5, R3-F-R3-3]. Each is red-proved
  separately, and the production constants are the allow side.
- **Secret key handling:** each call copies the secret key from the
  read-only MR into a buffer that is zeroed afterwards. A persistent
  wrapper is never kept, because cmr zeroizes on drop [S9].
- **`pqkey` blob v1:**
  - contents:
    - the McEliece secret key in cmr layout (13608 B);
    - `H(spkm)`, checked against config;
    - a boot KAT pair (`ct`, `H(shk)`), where `ct` is encapsulated to the
      **configured** `spkm`;
    - `blob_seed`;
  - **`pqkey` decapsulates the KAT at boot and halts on mismatch** [F10,
    S9].
- **WireGuard blob:** `key`'s blob becomes v2 without per-peer PSKs, and
  v1 is refused with `BadVersion` [S9].
- **Acceptance:**
  - a liboqs-encapsulated ciphertext decapsulates to upstream's key;
  - the caller table is tested both ways in both PDs [S1, F14, T9];
  - the buckets are isolated per PD: draining `pqkey`'s bucket in
    `pqkey-core` tests leaves `key-core`'s untouched. No integration case
    is attempted, because the bucket assertion makes rate-limiting
    unreachable from production inputs [R3-T-M1].
  - the length rule: exactly 24 words accepted; non-zero trailing 4 bytes
    refused [R2-T-N11];
  - **three boot-check fixtures, each with its own halt message as the
    needle** [R2-T-N2]:
    - (a) a foreign `pqkey` MR on this image halts on `H(spkm)`;
    - (b) another valid secret key, with the KAT and `H(spkm)` kept, halts
      on the KAT. It is built by a test-only blob-splice helper whose offsets
      are asserted against the `secret-blob` layout constants
      [R3-T-M7];
    - (c) the secret key's halves swapped halts on the KAT.

    (a) and (b) are red-proved separately. A normal boot is the allow side.
  - `pq`'s and `hs`'s boot seeds differ, and both are produced.
- **Laws fixtures** [R2-T-N3]:
  - allow: two key PDs with disjoint MRs and disjoint callers;
  - deny, each failing on L2:
    - a shared secrets MR;
    - a caller with `pp` channels to both key PDs;
    - swapped owners;
    - `pqkey` mapping a non-secrets MR;
    - `prefill_path` on a non-secrets MR;
    - a secrets MR with no owner.
  - `two_key_pds_deny` is replaced by an owner-based deny.
- **Package fixtures:**
  - allow: both blobs swapped in;
  - refuse: any other byte changed; `pqkey`'s blob in `key`'s MR.

**C3 — `pq` PD.** The wiring above, plus:
- **The handler loop:** `ring::pass`.
- **Audits:**
  - `RpInitHello`
  - `RpBiscuitReplay`
  - `RpPskExported`
  - `RpPskInstallFailed`
  - `RpRngFailed`
  - `RpDecapsRateLimited`
  - `RpCostHighWater` (non-coalesced, emitted when the cost exceeds the last emitted value by ≥ 1/8; `a` = the exact cost in µs; see Design)
- **Acceptance:** laws pass, with check-selftest laws cases for each new
  edge (a `pq`→`key` channel, a `hs`→`pqkey` channel, and a writable or
  shared mapping of the `pqkey` secrets MR).

**C4 — `ingress` Rosenpass path.**
- **Behaviour:** as described in Design.
- **Audits:** `RpBadMac`, `RpRateLimited`, `RpTypeDropped`.
- **Tests:**
  - unit tests and Kani with the **production** constants [T9];
  - the `RpMac` adapter is unit-tested against the rp-vectors mac values
    [R2-T-N4];
  - integration pair:
    - an InitHello with one mac byte flipped gets `RpBadMac` and no
      RespHello, while the genuine one completes;
    - a replayed burst from one source above the `RP_HELLO` burst gets
      `RpRateLimited`, and after refill the client completes;
    - red-proved with an always-true adapter;
  - a WireGuard flood leaves the Rosenpass meters untouched, and the
    reverse;
  - a red-proof for each bucket and for the type filter.

**C5 — `hs` L8 and PSK custody.**
- **Behaviour:** as described in Design.
- **Unit tests:**
  - refused at exactly REJECT_AFTER_TIME, accepted at `− 1 ns`;
  - refused with no PSK;
  - a refusal leaves `last_timestamp` and the flood state unchanged;
  - both refusal paths and the accept path cost exactly 2 key calls
    (counting fake);
  - the same initiation is refused before `PskInstall` and accepted after
    it;
  - expiry: the tick at or past 180 s makes the entry `Expired`, so a
    later initiation is refused as `HandshakePskStale` rather than
    `HandshakePskMissing`; at `− 1 ns` the entry is still `Live` [R3-T-M2];
  - an `Expired` entry is refused even if its `installed_at` is set to
    less than 180 s ago; `PskInstall` on an `Expired` entry makes it
    `Live`. Red-proved by letting `fresh()` accept `Expired` [R4-S-P1];
  - the check is per peer: peer 0 fresh, peer 1 absent;
  - supersession replaces the PSK and zeroizes the old one;
  - `PskInstall.peer` is bounds-checked.
- **check-selftest:**
  - `l8-stale` (unit, the age comparison removed; `fresh()` called at
    REJECT_AFTER_TIME with no tick in between);
  - `l8-expiry-tick` (unit, the tick's transition removed: "the entry is
    `Expired` after the tick at 180 s" must fail) [R3-T-M2, R5-T-R3];
  - `l8-order` (unit, the check moved after the commit);
  - `l8-fallback` (integration, an absent PSK treated as zero) [T3].
- **C5 selftest recompute** [R2-F-N2]: with `KEY_CALLS = 2` the existing
  mutations no longer cross the inequalities.
  - `c5-forward-burst` becomes 16 → 63, since (63 + 65) × 2 = 256 > 255.
  - `c5-backlog` and `c5-interval` (1/300) are recomputed to just cross
    the boundary.
  - The unmutated values must still pass.

**C6 — config and mksecrets.**
- **Peer record:** one record per peer, `{ wg_pub, rp_pub, rp_hash }`.
  The validator checks key sizes, `rp_port`, and the peer count against
  `pq`'s table [S8].
- **What `mksecrets` produces:**
  - the gateway's McEliece keypair (cmr keygen);
  - each client's McEliece keypair, exported in the **liboqs layout**
    that upstream reads [F19];
  - a rosenpass TOML per client (`key_out`) and a wg conf without
    `PresharedKey`;
  - both secrets blobs.
- **Acceptance:**
  - import a committed `rp genkey` output, then decapsulate a committed
    liboqs ciphertext and get the expected key; with the halves swapped,
    there must be a mismatch [T11];
  - validator fixtures for sizes ±1 and peer count 8/9.

**C7 — integration** [T3–T6, T13, T17, F11].
- **Client:** upstream `rosenpass` (master) plus **wireguard-go**. A
  `key_out` watcher applies each rotation with `wg set … preshared-key`.
  The Python peers re-read `key_out` before every handshake.
- **Rosenpass traffic:** boot 2 gains a hostfwd for `rp_port`, and the tap
  boots carry it natively.
- **Migration:** every existing boot first runs Rosenpass per peer and
  waits for `RpPskExported` and the `key_out` file before any WireGuard
  traffic. wireguard-go starts only after that.
  - Assertions that can span a rotation use `since=mark` and `>=`.
  - Retry budgets include the rotation window.
  - The moved selftest anchors and needles are listed in the deviation
    log, including `integration`, `integration-count`, `manifest` and
    `c5-key-calls`.
- **New cases:**
  - **Interop:** the OSK matches the client's `key_out`, for master and
    for 0.2.3, and a WireGuard ping then works.
  - **Boot plan** [R2-T-N10, R2-T-N12]:
    - boot 1 (raw frames) and boot 5 (mismatched blob) run no Rosenpass;
    - boot 2 hosts the L8 pair and the expiry case, with peer 1 exempt
      from the prelude;
    - 0.2.3 interop runs in the cookie-a tap boot, before its first flood,
      as its own peer (`--peers 3`), so it never competes with a master
      client's OSK [R3-T-M6];
    - the reboot capture comes from the Python initiator. The same bytes
      first draw `HandshakeOk` before the reset (the allow side).
  - **Floods:** after any migrated WireGuard flood, the next WireGuard step
    restarts the client's rosenpass and waits for a fresh `RpPskExported`
    since a mark, under a named budget [R3-T-M7].
    It fails as "PSK went stale during flood". The observed rotation-loss
    rate is recorded [R2-T-N5].
  - **pq→hs link residue (brought in from M3b)** [R2-T-N7]: after install,
    the OSK (known from `key_out`) is absent from the `pq`→`hs` link
    region, with a control. It reuses `wait_absent`. The red-proof removes
    the reclaim scrub. The full-RAM residue scan stays in M3b.
  - **L8 deny, paired:**
    - in one boot, peer 1 (no Rosenpass, zero PSK) is refused with
      `HandshakePskMissing` and gets no response;
    - meanwhile peer 0 works;
    - then peer 1 runs Rosenpass and succeeds.
  - **Expiry, run concurrently:**
    - peer 1 exports, then its rosenpass is killed;
    - near t0 + 170 s, a handshake is accepted, with t0 = the `key_out`
      write time (before the install);
    - after t0 + 180 s + slack, it is refused with `HandshakePskStale`,
      with t0 = the `RpPskExported` console time (after the install)
      [R2-T-N9].
    - The slack is named once; REJECT_AFTER_TIME is read from source.
  - **Rotation without interruption:** a ping loop runs while the
    client's rosenpass restarts. A new `RpPskExported` follows, a forced
    re-handshake succeeds with the new `key_out`, and no ping is lost
    beyond the budget.
  - **Reboot:** a `system_reset` in the same QEMU. The captured
    pre-reboot initiation bytes are replayed before Rosenpass runs, and
    are refused with `HandshakePskMissing`.
  - **Peer binding:** `mksecrets` writes a test deployment whose records
    are {wg0, rp1} and {wg1, rp0}. This needs one extra `make image`,
    which is counted in the selftest time. The validator separately
    rejects a duplicated `wg_pub` or `rp_pub` (fixture) [R3-T-M5].
    - **Only client 0 runs**, with WireGuard wg0 and Rosenpass rp0.
    - Precondition: `RpPskExported` for client 0's exchange appears, so
      the Rosenpass handshake demonstrably completed.
    - Deny: rp0 installs its PSK at record 1, so client 0's WireGuard
      (record 0) is refused with `HandshakePskMissing` and gets no
      response.
    - Same-boot allow: a Python initiator with **wg1**'s static key and
      PSK = client 0's `key_out` completes (`HandshakeOk`, and the response
      opens). That proves the PSK landed exactly at record 1 [R5-T-R1].
    - Allow side: the correctly bound deployment completes with a ping
      [S8, R2-T-N10, R4-T-Q1, R4-F-R4-1].
    - Running both clients would give each record a fresh but wrong PSK.
      The gateway would then log `HandshakeOk` while every client fails.
      The gateway cannot detect a mis-pairing that a deployment error
      creates, so this is recorded as a residual.
  - **Harness changes** for `--peers 3` [R4-T-Q2]:
    - `run.py build()` takes a peer count;
    - `check_harness_matches_config` pins the third peer's allowed IP;
    - deployment `b` (mismatched blob) is generated with the same peer
      count.
  - **MCE-COST quiet window** [R4-T-Q3]: boot 2's Rosenpass prelude, from
    its console mark until `RpPskExported` for every prelude peer. run.py
    checks the last `RpCostHighWater` emitted inside that range, and
    **fails** if none was emitted in it [R5-T-R3].
- **Gates:** `INTEGRATION-CASES` is recounted. Every new gate is
  red-proved.

**C8 — McEliece assurance spike (SC3).**
- **Checks:**
  - KATs;
  - interop with liboqs both ways;
  - the MCE-COST numbers;
  - a stack measurement at `opt-level = "s"`;
  - a constant-time review of cmr's decrypt path, written up;
  - a dudect-style smoke test run by hand and **kept out of `make
    check`**.
- **Recommendation:** accept, port PQClean round 3, or replace (SC23).
- **Documented residual:** the result is a residual, not a gate, because
  images stay dev-only.

**Forbidden patterns**

- `pattern: (?i)psk_?mix` in `crates/` — reason: the static PSK path is removed (L8) [F21].
- `pattern: derive\([^)]*\b(Clone|Copy|Debug)\b` on any type in `rosenpass-core`, `pqkey-core` or `pq` that wraps `Secret<` — reason: L12 [S12, T15].
- `pattern: getrandom|thread_rng|OsRng` in `crates/` — reason: randomness comes only through `cpu` and the hedged source.

These run as check-pins rules with fixtures, in the `pins` gate, and are
red-proved [T15, R2-T-N11].

**Pinned dependencies** [R2-S-N5]:
- `classic-mceliece-rust =2.0.2` (features `mceliece460896`, `zeroize`,
  no default);
- `libcrux-ml-kem =0.0.11` (feature `kyber`, no default);
- transitively: `sha3` 0.10, `rand_core` 0.6 (implemented over the hedged
  source), `zeroize`. Lock-file changes are read.

## Files to update [F12]

- **WireGuard handshake:**
  - `crates/wg-core/{noise.rs, tests_handshake.rs}`;
  - `crates/hs-core/{lib.rs, tests.rs}` and `crates/pds/hs`.
- **`key`:**
  - `crates/key-core/{lib.rs, tests.rs}` and `crates/pds/key` (caller
    table, `PSK_MIX` removed, `MAX_WORDS`);
  - `crates/secret-blob` (v2 for `key`; `pqkey` v1).
- **New crates:** `crates/{pqkey-core, rosenpass-wire, rosenpass-core}`
  and `crates/pds/{pqkey, pq}`.
- **Config:** `crates/config/{build.rs, src/validate.rs}` and
  `config/gateway.toml` (`rp_port`, peer records, placeholder keys).
- **`ingress`:** `crates/ingress-core/{lib.rs, proofs.rs, tests.rs}` and
  `crates/pds/ingress/{main.rs, cookie.rs, Cargo.toml}` (`rp_mac` adapter,
  `emit_udp` source port, a `PassIo` serve step for `pq`).
- **Shared crates:**
  - `crates/msgs` (Rosenpass datagrams with endpoints, `PskInstall`);
  - `crates/audit-event` and `crates/pds/audit` (new sources and codes);
  - `crates/layout` (channels, sizes).
- **Other PDs:** `crates/pds/timer` (a peer for `pq`).
- **System and laws:** `system/secureos.system`, `policy/laws.toml`,
  `tools/laws` (a second `key`-role PD, its fixtures).
- **Tools:**
  - `tools/mksecrets`;
  - `tools/package`: two secrets MRs, plus the waiver check;
  - `policy/waivers.toml` (new; schema `id`, `owner`, `status`)
    [R3-F-R3-6];
  - `tools/check-selftest`: the new cases, including the waiver case;
  - `tools/rp-vectors` (new);
  - `tools/check-pins` (rules).
- **Tests:** `tests/manifest.txt`, `tests/integration/{run.py, wg.py}`.
- **Build:** `docker/Dockerfile` (VE9), the `Makefile`
  (`host_crates`, `kani_crates`, `bolero_targets`, `pds`), and the root
  `Cargo.toml` (`[profile.dev.package.*] opt-level = 3` for cmr and
  libcrux-ml-kem [T14]).

## Testing strategy

- **Oracles, independent of our code:**
  - upstream binaries for the wire;
  - upstream-generated V02 vectors for the internals;
  - liboqs vectors for the KEM.
- **Verification:** Kani and bolero for every parser and gate.
- **Gates:** every new gate, laws edge and compile-time assertion is
  red-proved.
- **Manifest:** all keys enumerated in Phase 2 [T16].
- **Selftest time:** recorded in the deviation log. An integration case
  filter is used only if the time exceeds 2× the current value.

## Considerations & constraints

- **Assurance gap:** cmr 2.0.2 is unaudited and its constant-time
  properties are unverified (L2 waiver, SC23). The libcrux Kyber code is
  unverified, though it passes KATs and interop.
- **Residuals:**
  - Reboot gap: up to about 130 s with no WireGuard after a reboot.
  - M3a Rosenpass DoS through public-mac InitHello floods, which L8
    amplifies into a WireGuard outage. Closed by M3b (SC26).
  - The `next`-slot replay after the first PSK following a reboot.
  - A wg/rp mis-pairing in a deployment cannot be detected at the gateway:
    it logs `HandshakeOk` while the client fails [R4-F-R4-1].
  - A withheld InitConf (up to about 600 s) still yields a PSK counted
    fresh from install.
  - The full-RAM OSK residue scan is M3b (SC26). In M3a only the link
    residue is verified.
  - A panic in a dependency halts `pq`.
- **Scope contract:**

| ID | Deferred | Owner |
|----|----------|-------|
| SC22 | Rosenpass as initiator | unscheduled |
| SC23 | Replacing cmr 2.0.2 (PQClean round-3 port or an audited crate), and lifting the L2 waiver | M4 |
| SC24 | Protocol V03 | M4 |
| SC25 | Per-peer Rosenpass pre-shared keys | unscheduled |
| SC26 | Rosenpass cookie gate under load, its flood and latency cases, an attribution sniffer for the client, and the guest-RAM OSK residue scan. No flood is needed to starve rekeys (code review S-3): one spoofed mac-valid InitHello per 20 s as a peer's source spends its per-source token, and about 0.1 pkt/s takes the global meter, so the gate must engage on Rosenpass meter refusals, not on traffic volume, and InitConf needs a reserved share of the ingress→pq link. Also the per-source meter is keyed by IP, so at most 6 peers behind one address can keep fresh PSKs (code review F3) | M3b |
| SC16 | Closed | M3a |
| SC3 | Spike done (deviation log, "C8 McEliece assurance spike"): implicit rejection is branch-free, but the compiler turns cmr's Berlekamp-Massey masked select into a secret-dependent load address in the PD ELF (F1). Carried by SC23 with its M4 requirements: value barriers on every masked select, a ctgrind-style test, and a pinned disassembly check | M3a (spike) / M4 |

## User operation scenarios

1. **Normal use.** A laptop runs rosenpass (master) with wg-quick. It
   connects about 1 s later, and the PSK then rotates every 130 s without
   loss.
2. **Gateway reboot.** Clients reconnect at their next Rosenpass rekey,
   within about 130 s. Until then WireGuard is refused.
3. **Flood (M3a).** Anyone with the image can stop Rosenpass rekeys. After
   180 s, WireGuard is refused for every peer. This is acceptable only
   because images are dev-only until M3b.

## Carried-Forward Plan Findings

Plan review closed at Round 6 by saturation. Two measurements are carried
into Phase 2 by design.

### MCE-COST [Round 1: F4, T7, S3] — Accepted (carried to Phase 2)
- **Anti-Deferral check:** a measurement that sizes constants, not a
  deferred fix.
- **What settles it:** the committed in-PD measurement listed under VE10.
  It sets `PQ_HANDSHAKE_COST_NS`, the `RP_*`/`PQ_KEY_*` constants, the
  budgets and the stacks. All results go into the deviation log.
- **Gate:** the marker `MCE-COST` and the Go/No-Go row. It must be locked
  before Phase 3.

### GUARD [Round 2: S10] — Accepted (carried to Phase 2)
- **What settles it:** a citation showing whether Microkit 2.3.1 places a
  guard page below each PD stack, or a residual entry if there is none.
- **Gate:** the Go/No-Go row GUARD. It must be locked before Phase 3.

## Go/No-Go Gate

| ID | Subject | Status |
|----|---------|--------|
| C1 | rosenpass-wire / rosenpass-core | locked |
| C2 | pqkey PD, caller tables, blob v2 | locked |
| C3 | pq PD | locked |
| C4 | ingress Rosenpass path | locked |
| C5 | hs L8 and PSK custody | locked |
| C6 | config / mksecrets | locked |
| C7 | integration incl. migration | locked |
| C8 | McEliece assurance spike | locked |
| MCE-COST | TCG cost and stack measurement (Phase 2) | locked: settled in the deviation log (Batch F, MCE-COST); `make check` green on f667217 (pending by design until then) |
| GUARD | Microkit stack guard-page answer (Phase 2) | locked: answered in the deviation log (Batch F, GUARD), enforced by laws `check_stack_guard` (pending by design until then) |
