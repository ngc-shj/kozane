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

## Step 2-5 self-R-check

- **Security, 4 Minor:**
  - **RS1 (fixed):** `PskInstall` no longer derives `PartialEq`. The test
    compares fields.
  - **R2 (fixed):** `msgs::RP_LENS` is asserted against `rosenpass-wire`'s
    lengths in pd-ingress.
  - **R3 (fixed):** P9 also matches `Zeroizing<`, since pqkey-core holds
    its secrets that way, and covers `crates/pds/pqkey`. Two new fixtures;
    CHECK-PINS-FIXTURES 63 → 65.
  - **R1, kept:** three `ct_eq` copies remain, in wg-core, rosenpass-core
    and pqkey-core.
    - The check proposed moving them into `secret-blob`, but only
      pqkey-core depends on it.
    - Doing so would make wg-core and rosenpass-core depend on the key
      blob format crate, which inverts the layering for a five-line
      function.
    - The three copies are identical. The P9 gate and Phase 3 review read
      them as one primitive.
    - Revisit if a shared no_std primitives crate appears.

### Testing findings (3 Major, 4 Minor), all fixed

1. **RT7, selftest needles matched passing runs.**
   - `l8-stale`, `l8-order`, `rp-domain-label` and `rp-mac-always` used
     bare test names, which `unit.log` also prints for a test that
     passes.
   - Each needle is now cargo's failure-only header
     `---- <test> stdout ----`.
2. **RT7/RT8, the integration bucket deny could not attribute the
   refusal.**
   - It sent 73 replays and waited for a coalesced `RpRateLimited`. The
     global meter or the ring could produce that line just as well.
   - Now one replay follows the genuine InitHello. It is sent after the
     source wait has refilled the global meter by at least two tokens (the
     harness asserts that precondition), and must draw no RespHello
     within 2× `PQ_HANDSHAKE_COST_NS`.
   - The mac deny also asserts that the flipped bytes draw no RespHello.
   - New selftest case `integration-rp-src-meter` removes the per-source
     InitHello meter.
3. **RT7, plan-required red-proofs were missing.**
   - New unit selftest cases, each with a failure-only needle:
     - `c2-boot-spkm` and `c2-boot-kat` (fixtures a/b);
     - `c4-hello-src`, `c4-hello-global`, `c4-conf-src` and
       `c4-conf-global` (each meter bypassed alone);
     - `c4-type-filter` (0x01 accepted as InitHello).
4. **Decorative test removed:**
   `a_wireguard_flood_leaves_the_rosenpass_meters_untouched` never passed
   its `RpGate` to `respond`. The isolation in that direction holds by
   signature (Batch E2). UNIT-INGRESS-CORE 80 → 79.
5. **Missing bolero case:** new `bolero-rosenpass-wire` selftest case for
   the third bolero target.
6. **Weak Stale test:** the Stale refusal test now also asserts that it
   produced no install or response. It also asserts that the same
   initiation is accepted once a fresh PSK is installed (nothing was
   committed).
7. **Hard-coded wire constants:**
   - The integration pair reads the mac offset, RespHello's type, the
     meter intervals and `PQ_HANDSHAKE_COST_NS` from source.
   - `rust_usize` now also parses hex constants.

### Functionality findings (1 Major, 3 Minor), all fixed

1. **R49:** the check-pins docstring now declares control classes.
   - P6 is fail-closed; P7–P9 are tripwires, with their known bypasses
     listed.
   - It names the adjudicating controls: the compiler for `Secret<N>`,
     and `PskTable::fresh` for L8.
   - It notes that `Zeroizing` wrappers rely on P9 alone.
2. **R3, mksecrets RNG:** `Urandom` fills a failed read with LCG bytes, as
   `CmrRng` does. A zero fill could hang cmr's sampling before `check()`
   refuses the output.
3. **R3/R42:** `READY_LINE` includes `pq`. The unused `READY` list is
   removed.
4. **R29:** comments corrected.
   - `pq` and `ingress` both expand `gateway_rp_public!`.
   - The C2 assertion lives in pqkey-core.

### Verification after the self-check fixes
- **New selftest cases:** all 13 fail with their failure-only needles,
  including `integration-rp-src-meter`, which takes one integration run.
- **Harness fixes found by the reruns:**
  - `strip_ready` kept removing the ready line being waited for, once
    `pq` joined `READY_LINE`. It now keeps the awaited line, as its
    docstring always said.
  - The bucket pair's reply wait returned only at the end of its
    240 s window, so the replay landed after the source meter had
    refilled. It now returns at the first RespHello, and the harness
    refuses to send the replay outside the source interval.
- **`make check`:** exit 0 (604 s) on the commit that records this entry.
  UNIT-TESTS 646, INTEGRATION-CASES 22, CHECK-PINS-FIXTURES 65.

## C8 McEliece assurance spike

Scope: this section covers only the constant-time review and the dudect smoke test for SC3. It does not cover KATs, liboqs interop, MCE-COST or the stack measurement. The object under review is `classic-mceliece-rust =2.0.2` (cmr), features `mceliece460896` and `zeroize`, round 3, as `crates/pqkey-core/src/lib.rs::decapsulate` calls it. That call is `cmr::decapsulate` → `operations::crypto_kem_dec` → `decrypt::decrypt`.

### 1. Constant-time review

The review was done at two levels:

- **Source:** cmr 2.0.2 from the container's cargo registry. Line numbers below refer to it.
- **Machine code:** two binaries were disassembled with objdump.
  - The **real PD binary** `build/pd-pqkey.elf`. It was built 2026-10-20 04:25 at release profile: opt-level `"s"`, overflow-checks, target `aarch64-unknown-none`, `+v8a,+strict-align,+neon`. Its cmr code is the same as at HEAD, because the cmr pin did not change.
  - A **host opt-level 3 build** of the same crate. This is the binary the dudect run timed.

Secrets in play: the Goppa polynomial `g` and the support `L`, both derived from `sk`; the error vector `e`; the syndrome; and the BM state.

| Step | Source (cmr 2.0.2) | Secret-dep. branch (source) | Secret-dep. index | Variable-time ops | Compiled code (PD ELF / O3 host) |
|---|---|---|---|---|---|
| decaps wrapper | `lib.rs:420` → `operations.rs:120-161` (the non-6960119 variant) | no | no | no | thin wrapper |
| load `g` | `decrypt.rs:40-43`, `util.rs:13` | no | no | no | loop on a constant |
| support gen (Beneš) | `benes.rs:347-377`, `apply_benes` `:256-345`, `layer_in` `:47-72`, `layer_ex` `:91-132`, `transpose.rs:5-30` | no; `if rev`/`if s == 64` are public | no; the condition bits are applied as AND masks | no | branches only on loop counters, bounds and alias checks; no secret `csel` |
| syndrome | `synd.rs:9-27`; `eval` at `root.rs:10-18`; `gf_inv`/`gf_frac` at `gf.rs:251`, `:208-221` | no | no; `r[i/8]` and `l[i]` use public `i` | `gf_mul` (`gf.rs:49-68`) multiplies by `t1 & (1<<i)` | `gf_mul` becomes `tst`+`csel` plus `umull`/NEON `mul`, with no branch. `gf_frac` has no branches; its loops are fixed-count. No `udiv`/`sdiv` anywhere on the path |
| Berlekamp-Massey | `bm.rs:17-73` | no in source: `mne`/`mle` are masks (`:36-45`) and the selects are masked (`:52`, `:55`, `:58`, `:61`) | no in source | no | **finding F1 below** |
| root finding | `root.rs:22-26` | no | no | as `gf_mul` | loop counters only |
| error vector and weight | `decrypt.rs:55-60`, `gf_iszero` `gf.rs:7-11` | no | no; the `e[i/8]` index is public | no | branch-free. The overflow check on `w += t` (`b.vs`) is never taken because `w ≤ 4608` |
| re-encode check (`s` vs `s_cmp`, `w == t`) | `decrypt.rs:62-74` | no; OR-accumulate then `(x-1)>>15` | no | no early exit | branch-free OR reduction |
| confirm hash and implicit rejection | `operations.rs:137-158`: `ret_confirm` is OR-accumulated (`:140-142`), `m = ((ret_decrypt\|ret_confirm)-1)>>8` (`:144-146`), the select is masked (`:153`) | no | no | no early-exit compare | **branch-free in both binaries.** O3 uses an OR reduction, `neg`/`and`/`sub` for the mask and `bif`/`bsl` for the select. The PD ELF loops only on counters (`0x210294`, `0x2102fc`) and has no `csel` |
| SHAKE256 | `crypto_hash.rs:8` (`sha3 0.10.9`, `keccak 0.1.6`) | — | — | — | not reviewed |

**F1: the compiler undoes the BM masked select. Secret-dependent machine code.** The source writes `b[i] = (b[i] & !mle) | (t[i] & mle)` at `bm.rs:57-59`. Here `mle` depends on the discrepancy `d` and on `L`, so on the syndrome and therefore on `e` and the key. LLVM proves `mle ∈ {0, 0xFFFF}` and turns the masked select into control flow or an address select:

- **The PD ELF** (`classic_mceliece_rust::bm::bm`, `0x210484`-`0x210490`) does `tst w20,#1; csel x10, &t[i], &b[i], ne; ldrh w10,[x10]`. Each of the 97 loads per iteration takes its address from `t[]` or `b[]` depending on the secret bit. That is **secret-dependent memory indexing**. Both arrays are small and on the stack.
- **The host O3 build** turns the same lines into a **secret-dependent conditional branch** (`ands w9,w9,w21; tbz w9,#0` at `bm.rs:52-58`). It skips or executes the `b = t` copy, so the branch is taken or not once for each of the 192 iterations.
- Also present: the overflow check at `bm.rs:55` (`n+1-l`, `b.cc` to `panic_const_sub_overflow` at PD `0x21045c`) compares a secret `l` against public `n`. It is never taken, because `l ≤ n` holds at iteration `n`. I rate it benign, but it is a secret-dependent compare that the source does not show.

What leaks: a per-iteration trace of the BM length-change decisions. That trace is a function of the syndrome sequence. Published timing attacks on McEliece decoders recover `e` or key information from this kind of BM/Patterson control-flow trace. That statement is **from memory**, for example Strenzke et al. (2008) and follow-ups, and was not re-checked here. The magnitude is small: tens of cycles per decapsulation in the O3 variant, against about 27 ms. In the PD variant, both arrays are L1-resident. Exploiting it over RespHello latency would be hard. Still, this is a constant-time violation in the shipped binary, and it shows that cmr's constant-time property depends on the compiler and the flags.

**Comparison with PQClean round-3 mceliece460896** (from memory; I did not open the files and give no line numbers). cmr is a near line-for-line port of the reference/"clean" code: `decrypt.c`, `synd.c`, `root.c`, `bm.c`, `benes.c`, `gf.c`, `operations.c`. "clean" `bm.c` uses the same `B[i] = (B[i] & ~mle) | (T[i] & mle)` idiom, so a C compiler is equally free to booleanize it. "vec" bitslices the field arithmetic: an additive FFT replaces `eval`/`synd`, and BM runs on 64-bit bitsliced words with masks. That makes this specific rewrite less likely but does not guarantee anything. **Porting PQClean without value barriers would not by itself fix F1.**

Not checked:

- whether seL4/Microkit sets `PSTATE.DIT`;
- whether `umull`/`mul` timing is data-independent on the eventual hardware core (it is on mainstream Cortex-A, from memory);
- the keccak binary.

### 2. dudect-style smoke test (manual, not in `make check`)

Setup:

- **Source:** a throwaway program, kept in the scratchpad as `c8-dudect/` and not in the repo. It is its own Cargo workspace using the repo's `Cargo.lock`. Dependencies: cmr `=2.0.2` with `mceliece460896`/`zeroize`, and `rand_core =0.6.4`.
- **Build:** offline, in `/work/build/c8-dudect`, which has since been deleted.
- **Method:**
  - One fresh keypair.
  - All inputs are generated before timing.
  - Classes are interleaved by a random coin.
  - Each `cmr::decapsulate` is timed with `isb; mrs cntvct_el0; isb`. `cntfrq` is 1 GHz, so the resolution is 1 ns.
  - The tests: uncropped Welch t, dudect percentile crops `p = 1 − 0.5^(10(i+1)/100)` for i ∈ {0,4,9,19,29,49,69,99}, and a second-order test (centred-squared, uncropped).
- **Commands** (inside `secureos-dev`):
  ```
  cargo build --release --offline        # profile.release: opt-level 3, debug=1
  taskset -c 9 ./target/release/c8-dudect 30000 rand    # A vs B
  taskset -c 7 ./target/release/c8-dudect 30000 valid   # A vs C
  taskset -c 5 ./target/release/c8-dudect 20000 null    # A vs A (null control)
  ```
  The three runs were concurrent, each pinned to its own core. Random interleaving keeps cross-run interference independent of the class.
- **Host CPU:** NVIDIA GB10-class SoC, Arm Cortex-X925 ×10 (3.9 GHz) + Cortex-A725 ×10, governor `performance`. All runs were pinned to X925 cores. **This is not the target.** The target is aarch64 under QEMU TCG today and unspecified hardware later. The timed binary is the host **opt-level 3** build (the one with the F1 branch), not the PD's opt-level `"s"` build.
- **Decision rule (dudect convention):** max |t| > 4.5 over first-order crops ⇒ evidence of leakage. |t| < 4.5 ⇒ "no leakage detected at this N". It never means "constant-time".

| Test | N (class0 / class1) | median decaps | sd (ns) | uncropped \|t\| | per-crop \|t\| (i=0,4,9,19,29,49,69,99) | 2nd-order \|t\| | max \|t\| | detectable Δ at \|t\|=4.5 |
|---|---|---|---|---|---|---|---|---|
| A fixed-valid vs B random-ct (implicit rejection) | 15118 / 14882 | 27.31 ms | 38462 / 42689 | 0.144 | 1.145, 0.032, 0.451, 0.171, 0.258, 0.222, 0.548, 0.864 | 0.673 | 1.145 | ≈ 2.1 µs (≈ 8000 cycles) |
| A fixed-valid vs C random-valid | 14930 / 15070 | 27.29 ms | 8462 / 8375 | 0.002 | 2.144, 0.995, 0.828, 0.249, 0.281, 0.593, 0.187, 0.331 | 1.069 | 2.144 | ≈ 0.44 µs (≈ 1700 cycles) |
| Null control (A vs A) | 9993 / 10007 | 27.29 ms | 11269 / 11412 | 0.939 | 0.692, 0.208, 0.207, 0.393, 0.553, 1.019, 0.954, 0.749 | 0.827 | 1.019 | ≈ 0.72 µs |

Result: **no leakage detected at N ≈ 1.5·10⁴ per class** on this host. This does not contradict F1. The F1 branch is expected to move the timing by tens of cycles, about two orders of magnitude below the effect this N can resolve against a 27 ms operation with about 8-40 µs jitter. Reaching F1's scale (about 10 ns) would take roughly 10⁷-10⁸ samples per class, because the detectable Δ shrinks only as 1/√N. At 27 ms each, that is weeks to years of CPU time. The PD binary and the QEMU TCG target were **not timed**: no QEMU run was allowed, and the PD ELF does not run on the host.

### 3. Recommendation

**Decision rule.** Accept for dev images if two things hold: the compiled implicit-rejection path is branch-free, and every remaining finding is low-magnitude, not observable remotely at the bounded `PQ_DECAPS` rate, and covered by the dev-only gate. Replace (SC23) if any secret-dependent branch or memory address exists in the binary we ship for production.

**Recommendation: accept for dev images; SC23 stays open; replace in M4.**

- Implicit rejection is branch-free in both binaries. No early-exit compare, no division, no secret-indexed table.
- F1 is a secret-dependent load address in the actual PD ELF, and a secret-dependent branch at O3. The source cannot be called constant-time across compilers.
- That meets the "replace" condition for production. It is acceptable for dev images because of what the waiver gate already enforces: `tools/package` refuses non-debug kernels while `policy/waivers.toml` lists SC23 `open`, and check-pins and `tools/package` require SC23 to stay `open` while `Cargo.lock` locks any `classic-mceliece-rust`.

**What SC23 (M4) must deliver**, with the axis that decides between the options. A plain PQClean round-3 port or another unaudited crate would carry F1 forward, because the masked-select idiom is the same. Neither option is sufficient without a binary-level check. M4 should take a round-3-compatible implementation, port it or patch cmr, and add:

- (a) optimization barriers on every mask select: `core::hint::black_box`/`subtle`-style, or an inline-asm select;
- (b) a ctgrind/valgrind-memcheck style host test with `sk` marked secret. **Not run in this spike** because no harness exists yet;
- (c) a pinned disassembly check of the PD ELF's `bm`/`decrypt` that rejects secret-fed `csel` addresses or conditional branches.

Prefer a bitsliced ("vec"-style) port. Its BM and FFT operate on whole-word masks, which compilers are less prone to booleanize.

Documented residual (per C8): this result is a residual, not a gate.

## Phase 3 Round 1 fixes

The full record is in the code review's Resolution Status. Deviations from the plan introduced there:
- **pq `PASS_MSGS`:** 4 → 1. Every answer and audit record leaves after its own message.
- **`Hedged`:** moved from pds/pq into rosenpass-core behind `HedgeHw`.
- **New check-pins rule P10:** a tripwire for `from_bytes(*`. CHECK-PINS-RULES 9 → 10.
- **SC23 binding:** now any `classic-mceliece-rust` version. It is also enforced by `tools/package`'s `check_bindings`.
- **Accepted, with the full Anti-Deferral format in the code review:**
  - F3: the per-source meter keyed by IP (M3b);
  - T4: wireguard-go's own use of a rotated PSK.
- **Reboot red-proof:** none. The PSK table lives in PD RAM, and no code path persists it.

### C8 addendum: the co-resident channel (code review Round 2, S-8)
- **Gap in the decision rule above:** it weighs only remote observability over RespHello latency. A co-resident observer is far finer.
  - `pqkey` is passive and runs on pq's scheduling context: 500 µs per 10 ms. Each decapsulation is therefore preempted thousands of times.
  - The network-facing `eth_in` (priority 150) shares the single core and its L1D (L11), and packet arrivals can make it preempt `pqkey` at chosen moments.
  - F1's `csel`-selected load from `t[]` or `b[]` is the access pattern an L1D prime+probe recovers. A compromised driver therefore observes it at cache-line granularity.
- **Why dev-only acceptance still holds:** this channel belongs to the architecture's accepted R3 (single-core shared caches), and the gate stands as before. While SC23 is open:
  - a non-debug kernel is refused;
  - SC23 cannot close while any cmr is locked (P6 and `check_bindings`).
- **What the dudect result says about it:** nothing.
- **M4 requirement (c) is widened, and (b) likewise:** the disassembly check must reject secret-fed load and store addresses, not only conditional branches. The ctgrind-style test must flag secret-dependent addresses.

## Selftest time (code review T11)
- **Full run:** `tools/check-selftest` on 35ccd4f, in the dev container: 4105 s (68 min), 53 layers.
  - It includes `check-propagation`, which runs `make check` once per gate, and 10 integration cases (one full suite run each).
  - No M2.5 time was recorded, so this run is the baseline for the plan's rule: add an integration case filter only if the time exceeds 2× this baseline.
- **One failure, from a stale needle:** the `manifest` case expected "UNIT-AUDIT-EVENT: 29 < manifest 30", but Phase 3 had added audit-event tests.
  - That needle and the `integration-count` one are now derived from `tests/manifest.txt`, so they follow it.
  - Re-run: `manifest` ok ("32 < manifest 33"). `integration-count` derives the string it already passed with ("21 < manifest 22").
