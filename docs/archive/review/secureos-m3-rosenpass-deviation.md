# Coding Deviation Log: secureos-m3-rosenpass (M3a)

Implementation decisions not spelled out by plan rev 7, or departing from it.

## Prep (db99846)

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
