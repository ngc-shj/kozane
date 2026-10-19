# Coding Deviation Log: secureos-m3-rosenpass (M3a)

Implementation decisions not spelled out by plan rev 7, or departing from it.

## Prep (`db99846`)

- **Crate skeletons and pinned dependencies were committed once, up
  front,** so that parallel batches would not race on `Cargo.lock`. The
  new crates are `rosenpass-wire`, `rosenpass-core` and `pqkey-core`.
- **Lockfile diff, read by hand:**
  - `chacha20 0.10.2` and `getrandom` enter only through dev or build
    edges (`cargo tree -i … -e normal` is empty).
  - `rand 0.8.8` / `rand_core 0.6.4` come in through `classic-mceliece-rust`.
    Its RNG trait is implemented over the hedged source.

## Batch C (laws L2, waivers, check-pins)

- **"Exactly its own" is strict.**
  - A key PD that maps zero secrets MRs is now an L2 finding. Two
    priority fixtures therefore gained a secrets MR.
  - `key_maps_non_secrets_deny` is now `{L1, L2}`.
  - `two_key_pds_deny` is replaced by
    `two_key_pds_without_own_secrets_deny`.
- **A policy error, not a law finding, for:** a secrets MR with no owner,
  a non-key owner, one key PD owning two MRs, and `ratio_sum_cap` outside
  (0, 0.95]. The parse-error fixtures also check the error text.
- **P7 is pending.** The `(?i)psk_?mix` rule exists but sits in
  `PENDING`, because 25 references remain in `key-core`, `wg-core` and
  `hs-core` until the L8 batch.
  - Turning it on means `PENDING = set()` and `CHECK-PINS-RULES` 8 → 9.
  - The manifest mismatch forces that step to be deliberate.
- **P9 scope** is `rosenpass-core`, `pqkey-core` and `pds/pq`, as the plan
  lists.
- **The waivers parser is `tools/waivers.py`** (tomllib), shared by
  check-pins and `tools/package`. Any `WaiverError` means refuse.

## Batch B (pqkey-core, key caller table, blobs, config, mksecrets)

- **Unused label code removed:** `key`'s `PSK_MIX` and the dead
  `ERR_UNKNOWN_PEER`. `MAX_WORDS` is now 4. `Oracle::handle` takes
  `Option<Caller>`. The refusal order is caller/label, then size, then
  bucket.
- **Blobs:**
  - The `key` blob v2 is `SOSSECR1`, version 2, 4096 B, without per-peer
    PSKs. v1 is refused.
  - The `pqkey` blob v1 is `SOSPQKY1`, `REGION_SIZE` 16384. Its offsets are
    pinned numerically by a test.
  - The liboqs⇄cmr secret-key conversions live in `secret_blob::pq`.
- **No shared `Secret<N>` yet.** pqkey-core uses `zeroize::Zeroizing`
  with an explicit per-call scratch buffer, zeroized after each
  decapsulation (verified by reading `decapsulate`). Unification is
  revisited once `rosenpass-core` lands its `Secret<N>`.
- **pqkey-core has its own `Bucket`,** a copy of key-core's shape. Using
  key-core's would pull in wg-core. It also still carries an unused
  `libcrux-blake2` dependency, to be removed with the next lockfile
  change.
- **The bucket isolation test runs in each crate separately.** A
  cross-crate drain test would need a pqkey-core → key-core
  dev-dependency.
- **Fixture provenance:** `crates/pqkey-core/testdata` holds upstream
  `rp genkey` keys (liboqs layout) and liboqs 0.8.0 ct/shk pairs. The
  generator was a scratch crate and is not committed; the test module doc
  records how they were made. Key A's vector doubles as the boot KAT.
- **Cargo.lock:** three dependency-list lines changed (mksecrets: cmr,
  `rand_core =0.6.4`; pqkey-core: secret-blob). No new packages.
- **Root `Cargo.toml`:** `[profile.dev.package.*] opt-level = 3` for cmr
  and libcrux-ml-kem (plan T14). Debug cmr keygen took about 2 minutes;
  with this it takes about 5 s.
- **Config:**
  - Peer records use `wg_pub`; `[gateway]` keeps `public_key`.
  - Key paths are relative to the toml.
  - `config::gateway_rp_public!()` and `config::peer_rp_publics!()`
    `include_bytes!` the keys from `OUT_DIR`, so the 524 KB keys enter
    only the crate that expands them.

## Batch D (VE9 interop oracle in the dev image)

- **Reproducible builds.** Two `--no-cache` builds of the oracle stage
  produced identical binaries, so the binary SHA-256 values are pinned
  in `tests/integration/rosenpass-oracle.sha256`. The `SOURCE` commit
  files are written but only informational.
- **Network isolation:** the build runs as `RUN --network=none`, so no
  build script can download anything.
- **Source archives:** GitHub archives by full commit, each checked with
  `sha256sum -c`. Existing check-pins P1 covers them; deleting a sha line
  fails P1, which was red-proved on a scratch copy.
  - master: `9e72f1eb…`, archive `8e584909…`, binary `e3f465b6…`.
  - 0.2.3: `512fe426…`, archive `d634faab…`, binary `37ff8500…`.
- **Master's `uds` git dependency** is pinned by its `Cargo.lock` commit
  `b47934fe…`, fetched by `cargo fetch --locked`. There is no separate
  archive hash.
- **0.2.3 links libsodium 1.0.18 dynamically,** from the pinned snapshot.
  `libsodium-sys-stable` hard-enables pkg-config, which refuses static
  system libraries. `libsodium23` is therefore in the final dev image. The
  feasibility build had used 1.0.20; 0.2.3 calls only `sodium_init`,
  `sodium_malloc` and `sodium_free`.
- **Toolchain:** 1.93.1 for both versions; 0.2.3 has no pin of its own.
- **Not in the seL4 image:** the oracle exists only in the dev image.
  Asserting that it never enters an seL4 image is left to the
  integration batch.
- **Preflight:** `check_rosenpass_oracle()` was added to run.py but is
  not yet called. The dev container is switched to the new image after
  batch A, then preflight calls it.

## Batch A (C1: rosenpass-wire, rosenpass-core, rp-vectors)

- **Vectors captured from upstream itself.**
  - `tools/rp-vectors` (its own workspace and lock, toolchain 1.93.1)
    runs one upstream V02 handshake with no PSK.
  - It records the responder through `assert_tv` init mode, and computes
    the hash domains, ICR ck values, OSK and IHR5 shk with upstream
    functions.
  - KEM KATs come from liboqs fed a SplitMix64 `randombytes` stream.
    libcrux Kyber and cmr McEliece match them.
  - There are 60 vectors, plus `spkm`/`spkt`.
  - Regeneration runs in the Dockerfile's `rosenpass-oracle` stage, the
    only one with cmake. The dev container was switched to the new image,
    so the feasibility study's `/tmp/m3r` copy is gone.
- **Upstream quirks that were matched, and differences:**
  - The V02 root string's "BLAKE2s" is kept as is.
  - The first biscuit key goes in slot 1.
  - The envelope mac is `KH(KH(D_mac, spk), msg[..mac])[..16]` using the
    incorrect-HMAC KH, not plain keyed BLAKE2b. C4's `RpMac` adapter must
    use `rosenpass_core::{mac_key, envelope_mac}`.
  - Upstream `handle_msg` tries V03 first, decapsulating once, then V02.
    So upstream does **two** McEliece decapsulations per V02 InitHello;
    ours does one. This matters for MCE-COST comparisons.
  - Upstream leaves stale bytes from an earlier message in EmptyData's
    cookie field. Ours sends zeros.
  - The known-response cache uses keyed BLAKE2b-256 truncated to 16 bytes
    (upstream uses keyed SHAKE256). It excludes the cookie field, as
    upstream does. This is internal to the PD, so not an interop issue.
  - The biscuit counter starts at 1, as upstream does. Keys are fresh each
    boot, so old biscuits cannot open.
- **Clock is an argument.** The clock is a `now: u64` argument rather
  than a trait, in the same style as hs-core.
- **OSK export is two-phase:**
  - `handle_init_conf` → `Conf::Fresh(PendingExport)`;
  - `psk_install()` is sent first;
  - then `commit_conf` (re-checks replay, commits, caches, returns
    EmptyData) or `abort_conf`/drop.
- **McEliece encapsulation:** the production `Encaps` was applied from
  the agent's scratch patch. It adds `rand_core =0.6.4`, which mksecrets
  already locks; Cargo.lock changes one dependency-list line.
  - On RNG failure the fill uses varying values, because a zero fill
    sends cmr's rejection sampling into an endless loop.
  - cmr's `SharedSecret` zeroizes on drop, so it is copied out first.
- **Kani:** each message has `*_parse_is_total` and `*_round_trips`
  harnesses, 10 in all. The first run took about 24 minutes (cached
  afterwards).
- **Dependency residue:** neither of the following is zeroized:
  - libcrux's BLAKE2b state and XChaCha subkeys;
  - by-value stack copies inside libcrux Kyber and cmr, including cmr's
    `gen_e` buffer.
- **Selftest anchor** for the domain-label case: `b"mix"` in
  `crates/rosenpass-core/src/crypto.rs`. Changing it fails 16 tests.
- **Mutation check:** 14 scratch mutations were each caught by their
  intended tests.

## Batch E4 (tools/package: two blobs, waiver gate)

- **Two blobs, each validated by kind.** `--pq-secrets` is a new required
  option. The MRs are found by name (`secrets`, `pq_secrets`). A blob
  carrying the other kind's magic is refused first.
  - The key blob is now also checked for version, checksum and padding;
    before, only size, non-zero and magic were checked.
- **The image may differ only inside the two blob ranges.** Each blob
  appears exactly once, the ranges do not overlap, and the placeholder
  is zero inside both.
- **Waiver gate:**
  - `check_waivers` decides "debug kernel?" with its own predicate, so
    stubbing SC20 cannot mask it.
  - `main` runs SC20 and the waiver check both, always, before any secret
    is read.
  - The waiver file path is fixed to `policy/waivers.toml`. It is not a
    CLI option, so the gate cannot be pointed at another file.
  - **More fail-closed than the plan:** a missing or unparsable waiver
    file refuses even a debug kernel. Only open waivers are limited to
    non-debug kernels.
- **Messages and needles changed:**
  - `no secrets magic` → `no SOSSECR1 magic`;
  - `differs outside the blob` → `…outside the blobs`;
  - the new open-waiver message is
    `package: waiver SC23 (owner M4) is open; …`.
- **Red-proofs:** 16 mutants were run on scratch copies, and all went
  red. `PACKAGE-FIXTURES` rises from 45 to 84.
- **Pending for the integration batch:**
  - the Makefile needs a `PQ_SECRETS` variable and the new argument;
  - check-selftest `package-release` needs `PQ_SECRETS`;
  - the .system needs a `pq_secrets` MR.

## Batch E2 (C4: ingress Rosenpass path)

- **Rosenpass classification has its own outcome type.** `respond` only
  routes by port to `Outcome::Rosenpass`, and the PD then calls
  `rp_classify`, which returns `RpOutcome`. Neither path takes the other's
  state, so the isolation is enforced by the signatures.
- **Order inside `admit`:** ring room, then the per-source meter, then the
  global meter. A ring refusal therefore spends no tokens. (The plan
  listed the meters before the ring reservation.)
- **In-flight accounting** is a FIFO queue of message kinds. It relies on
  pq returning buffers in ring order through the standard `Receiver`.
  A link error retires nothing, which fails safe.
- **Provisional constants**, marked MCE-COST:
  - InitHello: per-source burst 3 per 1 s; global burst 4 per 100 ms;
  - InitConf: per-source burst 3 per 1 s; global burst 8 per 50 ms;
  - `RP_IN_FLIGHT` 16, of which InitHello reserves 8 and InitConf may
    take 8.
- **RespHello and EmptyData** are subject to the same TX reserve as the
  other unauthenticated replies. A suppressed reply is audited as
  `TxNoBuffer` for now.
- **Open items for integration / Phase 3:**
  - The 512 KiB `spkm` is compiled into the ingress ELF, because
    `gateway_rp_public!()` is expanded there to derive the 32-byte mac
    key. A precomputed `config::GATEWAY_RP_MAC_KEY` would remove it.
  - ingress trusts the peer endpoint `pq` gives for each reply. A
    compromised `pq` could aim replies at any endpoint, bounded only by
    the drain cap and the TX reserve. Restricting replies to endpoints
    with an outstanding forward is not yet done.
  - Ring refusals are audited as `RpRateLimited`, and refused replies as
    `TxNoBuffer`; neither has a dedicated event.
- **Cargo.lock:** pd-ingress gains path dependencies on `rosenpass-core`
  and `rosenpass-wire`. No new packages.

## Batch E1 (C5 / L8: wg-core, hs-core, pds/hs)

- **PSK source:** wg-core now takes its PSK from a generic
  `PskSource::Psk: AsRef<Key32>`, because wg-core cannot depend on
  hs-core. `FreshPsk` lives in hs-core with a private field, so
  `PskTable::fresh` is its only constructor, and `Handshaker::handle`
  takes a concrete `&PskTable`.
- **Supersession:** the old OSK being zeroized cannot be observed in safe
  Rust. The test pins replacement instead, and the zeroization relies on
  `Key32` zeroizing on drop.
- **Unread field:** `Expired { installed_at }` is never read and carries
  `#[allow(dead_code)]`.
- **Tick placement:** hs ticks the table on every wakeup, not only on
  timer notifications. The tick is idempotent, and `fresh` re-checks the
  age anyway.
- **Install bounds:** a `PskInstall` peer index is bounds-checked against
  `MAX_PEERS`. A slot above the configured peer count never matches a
  lookup.
- **Audit:** a malformed `PskInstall` is audited as
  `RpPskInstallFailed`.
- **Side fix:** the hs-core tests were stale at HEAD after Batch B (blob v2
  and the `Caller` argument) and were adapted.
- **Selftest anchors for the C5 cases.** Each mutation is the first value
  that breaks the 2-call budget:
  - `FORWARD_BURST` 22 → 63;
  - `IH_BACKLOG` from `+7` to `+48`;
  - `KEY_INTERVAL_NS` from `/500` to `/399`. /399, not the plan's /300,
    because it is the tightest value that fails.

## Batch E3 (C2 PD side, C3: pq, pqkey, system, laws)

- **Errors with no dedicated event** (Malformed, BadMac, Auth, UnknownPeer,
  NoBiscuitKey, Encaps, Decaps refused, Internal, DuplicatePeer) are
  audited as `HandshakeOther` from src=pq.
- **Boot hash check:** pq checks H(spkm) against `GATEWAY_RP_HASH` at
  boot, in addition to the planned spkt checks.
- **Cost:** only InitHello → RespHello is timed.
  - `RpCostHighWater` uses code 0x0048, has its own slot, does not
    coalesce, and carries the exact µs value.
  - It fires on the first observation and then on any rise of at least
    1/8 (`8·us ≥ 9·last`).
- **Hedged RNG:** it lives in pq and has no unit tests; its inputs are the
  boot seed, the draw counter, CNTPCT and RNDR. → Phase 3.
- **Export path:** the `PskInstall` is already sent to hs when
  `commit_conf` runs. If `commit_conf` then fails, hs holds an OSK that pq
  never committed.
  - That OSK comes from an authenticated InitConf and matches what the
    initiator already derived.
  - Only the EmptyData is missing, and the client retransmits.
- **Provisional budgets (MCE-COST):**
  - pq 500/10_000 (0.05), pqkey 1_000/10_000. The sum is exactly 0.9.
  - Both stacks are 0x40_000.
- **ELF size:** pd-pq is 1.29 MB with one peer, ≈ 4.7 MB with eight,
  because the McEliece public keys are embedded.
- **Not added (integration batch):** check-selftest laws cases for a
  pq→key channel, an hs→pqkey channel, and `pq_secrets` mapped writable or
  shared.

## Integration

- **Host freeze.** E2 and E3 ran Kani concurrently in the dev container,
  which had no memory limit. cbmc for msgs peaked near 28 GB RSS; the host
  thrashed and needed a hard reset.
  - `tools/kani-gate.sh` now holds `flock build/kani.lock` around
    `cargo kani`.
  - `docker/Makefile run` sets `--memory`/`--memory-swap 64g`, and the
    running container was updated to match.

## Batch F (C7 integration, MCE-COST, GUARD)

### Integration
- **INTEGRATION-CASES:** 11 → 22. The suite takes 729 s in the container.
- **New cases:**
  - interop with master and with 0.2.3;
  - the L8 pair;
  - the pq→hs link scrub;
  - rotation without interruption;
  - PSK expiry;
  - reboot replay refused;
  - the Rosenpass mac deny and bucket deny;
  - peer binding;
  - the MCE-COST quiet window.
- **Raw-frame and mismatched-blob boots** run no Rosenpass, as planned.
- **`preflight()`:**
  - verifies the oracle binaries' hashes;
  - checks that no oracle ELF header occurs in a packaged loader. A
    4 KiB code slice matched by accident, because the oracle binaries
    share crates with the image.
- **Deployments:** b is packaged with a's `PQ_SECRETS`, so only `key`
  halts in the mismatch boot. Deployment c (records swapped by editing
  gateway.toml) gets its own image.
- **`RpPskExported` stays coalesced.** Only a boot's first export is
  visible.
  - **How the cases prove later installs:** after a rotation, for peer 1,
    in cookie-b and in the reboot capture, a WireGuard handshake with the
    current `key_out` must open its response.
  - **Why not a dedicated event:** a non-coalesced export event would
    need its own audit slot. → Phase 3 / M3b.
- **`key_out` timing:** the client writes `key_out` on RespHello, before
  the install (8.9 s vs 47 s).
  - The expiry case uses its mtime as the lower bound on the install
    time; the allow side is at +170 s.
  - The deny side is measured from the first accepted handshake, as an
    upper bound, plus 185 s.
- **Rotation:** the forced re-handshake is a Python peer-0 handshake with
  the new key. wireguard-go's key is checked with `wg show`. 0 of 53 and
  0 of 43 pings were lost.
- **Peer binding:** client 0's WireGuard side is a Python initiator, not
  wireguard-go.
- **Mac / bucket pair:**
  - Both use an InitHello sniffed from the 0.2.3 client.
  - The bucket deny sends burst + 72 replays to cross a coalesced
    `RpRateLimited` line.
  - The "after refill" side is peer 1's following exchange.
- **Not done:** "a WireGuard flood leaves the Rosenpass meters untouched,
  and the reverse". It is shown only indirectly: cookie-b's exchange
  completes under the band flood. → Phase 3.
- **Red-proved on scratch copies:**
  - `l8-fallback`;
  - pq reclaim removed;
  - RpMac always true;
  - records not swapped;
  - the quiet-window check, offline.
- **Not red-proved:** rotation, expiry, reboot, bucket.
- **Selftest:**
  - `integration-count` needle → "21 < manifest 22";
  - new `integration-pq-residue` and `l8-fallback` cases;
  - the other integration anchors are unchanged.

### MCE-COST (TCG, release PDs)

| Measurement | Median | Max | N |
|---|---|---|---|
| InitHello→RespHello, full budget | 174.8 ms | 215.8 ms | 30 |
| ↳ decapsulation over PPC | 163 ms | 204 ms | |
| ↳ Kyber encapsulation | 1.4 ms | 8.7 ms | |
| ↳ McEliece encapsulation | 3.2 ms | 4.2 ms | |
| ↳ rest (hashing 524 KB keys, AEAD) | 6.4 ms | 9.8 ms | |
| InitConf | 0.14 ms | 0.85 ms | |
| InitHello at the committed budget (500/10_000), wall | 8.5 s | 16.1 s | 26 |

- **Effective CPU share:** pq gets about 2% of the CPU, not the nominal 5%.
- **Boot:** the pqkey boot KAT takes 3.39 s.
- **Stack peaks:** pq 37,360 B; pqkey 53,872 B.
- **Quiet-window `RpCostHighWater`** in real runs: 10.7 s and 7.06 s.
- **Host load:** a Kani run shared the host during the measurement, so
  TCG wall times follow host load.

**Settled values:**
- **pq budget:** 500/10_000 (0.05) kept. Eight peers rekeying every 120 s
  with one retransmission each need about 2.9%. The sum stays at 0.9.
- **pqkey budget:** 1_000/10_000 kept; it only covers init.
- **Stacks:** both 0x20_000, 3.5× and 2.4× the measured peaks.
- **`PQ_HANDSHAKE_COST_NS`:** 20 s, the measured max plus 25%. It lives
  in pqkey-core.
- **InitHello per-source meter:** `RP_HELLO_SRC` 1 per 20 s (the plan said
  3 per 1 s).
  - **Why:** queued retransmissions each cost about 8 s of decapsulation,
    which stretched an exchange to about 45 s. One answer per initiator
    retransmission series suffices.
- **InitHello global meter:** `RP_HELLO_GLOBAL` burst 8 (one per peer
  after a reboot), one per 10 s.
  - **Why 10 s:** that is 12 per 120 s rekey interval, which covers 8
    peers.
  - **Why not 20 s:** the proposed 20 s (≥ cost) would give 6 per 120 s,
    below the steady demand.
  - **Backlog:** the link backlog stays bounded by `RP_IN_FLIGHT`
    regardless.
- **Unchanged:** `RP_CONF_*`, `RP_IN_FLIGHT` 16, `RP_HELLO_RESERVED` 8
  (equal to the global burst).
- **pqkey call budget:** `PQ_KEY_BURST` 32, `PQ_KEY_INTERVAL_NS` 10 s,
  `PQ_BOOT_CALLS` 1.
  - **The C2 invariant**, a compile-time assertion in pqkey-core (now
    depending on ingress-core):
    - `PQ_KEY_BURST - PQ_BOOT_CALLS > RP_HELLO_GLOBAL_BURST + RP_IN_FLIGHT`;
    - `PQ_KEY_INTERVAL_NS <= RP_HELLO_GLOBAL_INTERVAL_NS`.
  - **Selftest:** `c2-hello-burst` (8 → 15, the first value that
    crosses) and `c2-hello-interval` (10 s → 10 s − 1 ns).
- **`PQ_DECAPS` per-day bound (L2 waiver):**
  - at most 8640 + 32 per day, from one per 10 s plus the burst;
  - this is the timing-oracle query bound for cmr until SC23 closes.
- **Not measured:** hs handshakes per second, and ingress's cost per
  Rosenpass datagram.
- **Delay pqkey imposes on hs:** pqkey runs on pq's scheduling context, so
  it is bounded by pq's budget. This is reasoned, not measured.

### GUARD
- **Finding:** Microkit 2.3.1 (`tool/microkit/src/sel4.rs:558-581`)
  places its one guard page *above* the stack, between the stack and the
  IPC buffer.
  - The stack top is 0xffffffe000.
  - A `<map>` ending exactly at the stack bottom is accepted.
  - The page below each stack is unmapped only by layout today.
- **Enforcement:** new laws check `check_stack_guard` (L4).
  - Every map must end at least one page below `STACK_TOP - stack_size`.
  - A pd without `stack_size` is judged at the 16 MiB maximum.
  - Fixtures: `stack_guard_allow` (ends exactly one page below) and
    `stack_guard_deny` (reaches the page).

### Laws: secrets mapped read-only
- **Gap:** `laws` accepted a secrets MR mapped `rw`. This dates from M2
  (`key`'s `secrets`), and the plan's "writable or shared mapping of the
  pqkey secrets MR" edge depended on it.
- **Fix:** L2 now requires perms exactly `r`.
  - Fixture `secrets_writable_deny` added.
  - Seven fixtures that mapped secrets `rw` for unrelated laws now map
    them `r`.
  - Selftest: `laws-pq-key`, `laws-hs-pqkey`, `laws-pq-secrets-writable`.
- **mac pair:** the case now waits out the per-source InitHello meter
  before sending the genuine bytes. The 0.2.3 client had just used the
  same source, so the 20 s meter refused them as RpRateLimited.
- **Verification:** `make check` exit 0 (586 s, with the Kani cache warm)
  on the commit that records this entry. INTEGRATION-CASES 22,
  KANI-HARNESSES 48, UNIT-TESTS 647.
