# Plan Review: secureos-m3-rosenpass

## Feasibility study (input to plan rev 1)
- **Who and where:** a delegated research agent, working only in the dev
  container's `/tmp/m3r`. The repository was not modified.
- **Upstream sources:** rosenpass master `9e72f1eb871c4c403e99e9b78262fff8dd8d7357`
  (0.3.0-dev) and release `0.2.3` (tag `512fe426be9281366d92a910d391fe8ddd72bd10`).
  Citations below are relative to `rosenpass/src/` at master unless they
  name `papers/`.

### Protocol facts
- **Static KEM:** Classic McEliece 460896 round 3 (pk 524160, ct 188, shk 32).
  Sources: `papers/whitepaper.md` L101-108, `cipher_traits/algorithms.rs`
  L138-160.
- **Ephemeral KEM:** V02 uses Kyber-512 round 3 and V03 uses ML-KEM-512.
  They are not byte-compatible (tested). Source:
  `ciphers/subtle/ephemeral_kem_choice.rs`.
- **Keyed hash:** V02 uses the "incorrect HMAC" over keyed BLAKE2b
  (whitepaper L69-80 and the Errata; `incorrect_hmac_blake2b.rs`). V03 uses
  SHAKE256.
- **Domain tree:** the V02 root string literally says "BLAKE2s". This is a
  historical quirk that must be copied. Source: `hash_domains.rs` L116 ff.
- **Envelope:** `type ‖ reserved[3] ‖ payload ‖ mac[16] ‖ cookie[16]` (`msgs.rs` L81).
- **Biscuit:**
  - Plaintext is `pidi ‖ biscuit_no[12] ‖ ck`, 76 B. Under XAEAD it becomes
    116 B.
  - The epoch is 300 s.
  - Replay rule: `biscuit_no` must be greater than `biscuit_used`; an equal
    value means a retransmission.
  - Sources: `protocol.rs` L3421-3550 and L4088-4140; `constants.rs` L45.
- **Message sizes**, measured on the wire:

  | Message | Size (B) |
  |---|---|
  | InitHello | 1092 |
  | RespHello | 1132 |
  | InitConf | 176 |
  | EmptyData | 64 |
  | CookieReply | 1092 |
- **Responder-only operation:** verified against upstream, and the OSKs
  matched.
- **OSK export:** the responder exports on a fresh InitConf (ICR1-7), never
  on a retransmission (the v0.2.2 fix).
- **OSK derivation:** `KH(ck, ext_wireguard_psk_osk)`.
- **Timers:**
  - rekey 120 s (responder) / 130 s (initiator);
  - reject 180 s;
  - retransmit from 0.5 s, doubling, capped at 10 s.

  Source: `constants.rs` L11-64.
- **Cookie mechanism:**
  - It is experimental, and the 0.2.3 release has no CookieReply handler.
  - Master initiators do handle CookieReply.
  - Cookie hashing is always SHAKE256 (`protocol.rs` L2022-2160, L2400).
- **The responder needs each peer's full McEliece public key,** for RHR5
  encapsulation and hashing under ck (`protocol.rs` L3827-3960).

### Crates
- **Classic McEliece:** `classic-mceliece-rust` 2.0.2 is round 3. Version
  3.x is round 4 and incompatible.
  - It is `no_std`.
  - It interoperates both ways with liboqs 0.8.0.
  - Its secret-key layout differs: `cmr_sk = [0;40] ‖ oqs_sk[576..] ‖ oqs_sk[..576]`.
  - Decapsulation takes 27.3 ms on the host (liboqs: 0.147 ms) and uses
    about 40 KB of stack.
- **Kyber:** `libcrux-ml-kem` 0.0.11 with the `kyber` feature gives Kyber
  round 3. Interop is verified. It is not formally verified. Stack use is
  about 14 KB in release and about 270 KB in debug.
- **Keyed BLAKE2b:** `libcrux-blake2` 0.0.9 does it, and equals RustCrypto
  `Blake2bMac<U32>`.
- **XChaCha:** `libcrux-chacha20poly1305` 0.0.10 includes it.
- **no_std build check:** a probe crate using all of these builds for
  `aarch64-sel4-microkit`.

### Interop oracle
- **Builds:** upstream master and 0.2.3 build in the container, with
  cmake 3.31.6 (SHA-256 checked) and libsodium 1.0.20 built from source.
- **Runs:** both run in `unshare -Urn`, and kernel WireGuard works in the
  netns.
- **Cross-version results:**
  - 0.2.3 ↔ master V02: OK;
  - master V03 → 0.2.3: fails, as expected.

---

# Review round: 1
Date: 2026-10-19

## Changes from Previous Round
Initial review of plan rev 1. The merge was done by hand.

## Merged findings (rev 2 resolution)
- **Key PD separation:** S1 (Critical), S3, F2. Resolved by a new
  passive `pqkey` PD (role `key`) holding the McEliece secret, plus
  closed caller → label tables in both key PDs. Decapsulation time stays
  on `pq`'s scheduling context, so `pq` never reaches `key`.
- **Scope split:** M3 → M3a + M3b (SC26). The Rosenpass cookie gate,
  floods and OSK residue scan go to M3b, while images stay dev-only.
- **L8 placement:** F1, S11, S13, F23. The check now runs after the
  static decrypt and the replay/flood checks, before `ss` and the commit.
  `FreshPsk` comes from `PskTable::fresh`, and wg-core's `psk_mix` is
  removed. The wording is restated.
- **Budgets and roles:** F3, S4, F15. `pq` is `untrusted_input`, the
  0.9 cap is kept, the budgets are rebalanced via MCE-COST, and
  priorities are stated.
- **Cost measurement:** F4, T7, S3. MCE-COST is redefined (full path,
  CPU and wall time, stack, `opt-level = "s"`).
- **Message metering:** F7, S5. Only InitHello and InitConf are
  accepted, each with per-source and global buckets, plus a ring reserve
  and two named constructors.
- **Export order:** F8, F22, S15, F17. `PskInstall` is sent before the
  commit; the cache is keyed by the whole InitConf and looked up first;
  ck and the OSK are zeroized after export.
- **Public keys:** F9, S14. Embedded in the `pq` ELF.
- **Key binding and blob v2:** F10, S9. Boot KAT and `H(spkm)` binding;
  blob v2 without PSKs, v1 refused; the secret key copied per call.
- **Integration migration:** F11, T5. Planned in C7.
- **Files to update:** F12. Listed.
- **Request encoding and caller tables:** F13, S18, F14, T9. 24 words
  with zero padding; the caller table is tested both ways.
- **Rosenpass port:** F20. An explicit `rp_port` field.
- **Forbidden patterns:** F21, S12, T15. Patterns widened, a
  `Secret<N>` type introduced, and the patterns gated as check-pins
  rules.
- **Peer binding:** S8. A single peer record, a boot hash check, and an
  integration test with swapped keys.
- **Randomness:** S7, F16. A hedged RNG; a failed rotation leaves
  `None`.
- **Law amendments:** S10, S2. An amendments table, including the L2
  constant-time waiver for `pqkey` (dev-only, SC23).
- **Client policy:** S6. Production requires master clients; the M3a
  DoS residual is stated.
- **Vectors and oracle:** T1, T2, S16. A V02 golden-vector driver,
  oracles baked into the Dockerfile, and check-pins coverage.
- **Integration cases:** T3, T4, T6, T13, T17. The L8 cases are paired,
  expiry runs concurrently, rotation is handled, wireguard-go is chosen,
  and the reboot is replayed.
- **Kani scope:** T12. `rosenpass-wire` is split out, and the mac sits
  behind a trait.
- **C6 acceptance:** T11, F19. Added, including the liboqs export.
- **Debug profile and stack:** T14, S17. A dev-profile `opt-level`, and
  stack measured at `opt-level = "s"`.
- **Manifest and selftest time:** T16. To be enumerated in Phase 2.
- **Deferred to M3b (SC26):** T8 (cookie flood attribution) and T10 (OSK
  residue oracle).

## Raw expert outputs
# Functionality expert — M3 plan Round 1
Verified upstream: timers, V02 default, RP port = WG−1, sizes, OSK export at ICR7.
F1 Major (R29,R49): L8 refusal "before any key call" infeasible — peer known only after es DH + enc_static open (wg-core noise.rs consume_initiation); placement must be after {t} decrypt + replay/flood checks, before commit (avoid oracle for unauth senders, don't burn replay state); psk_mix inside wg-core StaticKey trait must change; per-path test 2 calls; allow/deny pair; last_timestamp unchanged on refusal; red-prove.
F2 Major (R49): passive key shared by pq and hs → decaps time on pq SC blocks hs key calls; per-caller bucket doesn't isolate time; MCE-COST wall-clock; size pq forward rate to bound key occupancy with compile-time assertion; integration: WG handshake latency under RP flood bounded.
F3 Major (L13): pq priority/budget/period unspecified; tainted ratio sum 0.85 vs cap 0.9; ingress extra work; pq priority < key 140; rebalance with rationale + laws fixtures.
F4 Major (R53): VE10 omits pq McEliece encaps, Kyber encaps, 524KB hash; encaps stack unmeasured; probe at opt 3 vs workspace opt s; retransmit at 0.5s multiplies decaps; measure whole path CPU+wall under image profile.
F5 Major (R29): cookies need SHAKE256 (libcrux-sha3 not in table); cookie secret custody contradictory (ingress vs pq vs core); fix: ingress holds RP cookie secret; pin libcrux-sha3; split core so ingress links only mac/cookie; render cookie_key and mac key as build-time constants (config build.rs); golden vectors for both trees.
F6 Major (R1,R29): ingress-core Gate WG-typed (INITIATION_LEN, COOKIE_REPLY_LEN 64 vs 1092, module constants) → generic refactor of Kani-proved code; shared TX_RESERVE split between gates.
F7 Major (R42): InitConf passthrough unthrottled (mac forgeable with public spkm) starves pq; member-set claim wrong; other types must be dropped (responder-only). Fix: InitConf per-source+global bucket, ring share; drop others; enumerate both constructors.
F8 Major (R38): OSK export ordering — PskInstall send failure after biscuit_used commit/EmptyData is unrecoverable (~130 s). Fix: send PskInstall first, commit/cache/EmptyData only on success; hs drains pq ring before ih; hs notifies pq for reclaim/scrub; test forced failure.
F9 Major (L6,R41): pq_pubkeys MR conflicts with laws prefill rule (check.rs:335), no MR kind, package diff-only-in-secrets check, or 4.5 MiB in config.rs; choose mechanism + list changes + laws fixtures.
F10 Major (R41): no boot check binding McEliece sk to spkm; implicit rejection → silent failure. Fix: blob carries BLAKE2s(spkm) checked vs config; mksecrets KAT pair (ct, BLAKE2s(shk)) decapsulated at boot; halt; red-prove.
F11 Major [Adjacent]: existing integration/selftests depend on static PSK (run.py:681-696,1182; wg.py; mksecrets main.rs:158; check-selftest integration case); C7 must plan migration and manifest.
F12 Major: no files-to-change list (enumerated: wg-core noise/tests_handshake; hs-core; pds/hs; key-core; pds/key; secret-blob REGION_SIZE 4096→≥16 KiB, VERSION, PSK removed, MAX_PEERS formula; config build.rs/validate.rs, gateway.toml; ingress-core lib/proofs/tests; pds/ingress main/cookie/Cargo (emit_udp source port, PassIo serve_pq); msgs; audit-event; pds/audit [Source;6]→7; pds/timer PEERS 3→4; layout; secureos.system (secrets MR size, pq, pq_pubkeys, audit_pq, channels); laws.toml; tools/laws; mksecrets; tools/package; check-selftest; manifest; run.py/wg.py; Dockerfile; new crates rosenpass-core, pds/pq).
F13 Minor: ct 188 B not 8-aligned; exact length = 24 words with last 4 bytes zero + deny test; MAX_WORDS 24.
F14 Minor (RS2): per-caller label allowlists both directions + allow pairs; key protected() channel check and per-channel bucket.
F15 Minor prose: no 'tunnel' taint role; hs is untrusted_input.
F16 Minor prose [Adjacent L9]: responder has no ephemeral Kyber keypair; randomness for Kyber encaps, McEliece encaps, sidr, biscuit keys/counter; hedging like HedgedEntropy?
F17 Minor prose: retransmission detected via KnownInitConfResponse cache (hash of whole InitConf) before handle_init_conf; ICR5 rejects equal biscuit_no.
F18 Minor (R4,R12): RpBadMac belongs to ingress; ingress RP events missing; audit_pq MR/channel; new codes in Event::ALL.
F19 Minor (R40): client sk export cmr→liboqs conversion with interop test.
F20 Minor (RS3): RP port listen_port−1 → validator listen_port ≥ 2 or explicit field.
F21 Minor: forbidden pattern should be (?i)psk_?mix incl. PSK_MIX_*.
F22 Minor [Adjacent] (R39): pq zeroize ck/OSK after PskInstall; hs bounds-check PskInstall.peer.
F23 Minor [Adjacent]: cross-reboot replay claim holds only until first PSK install; reword.

# Security expert — M3 plan Round 1
S1 Critical escalate (R43,R42,L2): key gains second caller without caller→label binding; key PD checks only channel != HS; Oracle::handle has no caller; compromised pq gets STATIC_DH (KCI/impersonation) and BOOT_SEED (hs hedge). Fix: closed caller→labels table, Caller enum, refuse before bucket, deny/allow pairs, red-prove; declare laws can't enforce per-label.
S2 Major (R43,L2): cmr 2.0.2 breaks L2 constant-time libcrux clause; amend L2 with sign-off; timing gate for non-dev images (package refuses until gate or SC23); quantify oracle query rate.
S3 Major (L13): passive single key → decaps head-of-line blocks hs (wall = C/r_pq; budget exhaustion mid-decaps); VE10 report hs wait; compile-time bound; second key-class PD needs L1/L2 changes (two_key_pds_deny); allow test hs latency bound.
S4 Major (R29,L13,L1): no 'tunnel' role (policy.rs roles); ratio_sum_cap 0.9 vs 0.85 used; specify pq role untrusted_input, budget/period, rebalance; selftest for channels and priority vs key/timer.
S5 Major (RS2,R29): RP gate lacks per-source bucket; InitConf and other types unmetered (upstream under load rejects all but 0x81/0x83); retransmissions. Fix: per-source InitHello bucket with RP constants, InitConf meters, drop others, reserve ring share, include retransmit in assertion, allow test.
S6 Major (R29,R49): L8 makes any RP outage total WG outage; 0.2.3 anonymous cheap DoS via spoofed mac-valid floods (public mac key); pq halt permanent (panics in unchecked deps, RNDR). Decide production requires master clients; record residual; no-panic policy; don't weaken L8.
S7 Major (L9,R55): RNG failure → all-zero biscuit key (forge biscuits → attacker-known OSK) / zero coins. Fix: Option biscuit key, refuse on failed rotation; hedged RngCore (HedgedEntropy pattern) aborting handshake; tests.
S8 Major (R42): pq/hs peer index binding unspecified; one config record {wg_pub, rp_pub}; validator; pq boot check H(pq_pubkeys[i]) == rp_hash; hs bounds-check; integration swapped mapping.
S9 Major (L2,L8,L12): secret-blob v2: remove static PSKs, refuse v1; bind sk to spkm (H(spkm)); REGION_SIZE 4096 < 13608; cmr SecretKey::from zeroes borrowed buffer → per-call copy. Boot KAT self-test.
S10 Major (R43): enumerate law amendments (L1 second key caller/new PD, L2 caller set + CT, L6 4.5 MiB, L13 cap, R6) with residuals and sign-off.
S11 Minor: cross-reboot replay claim overstated; "before any key call" impossible; place after static decrypt, before ss; residual next-slot replay.
S12 Minor (R42,R39,L12): zeroization member set incomplete (shk, encaps secrets/coins, biscuit plaintext, handshake keys, hasher key, PskInstall buffers, hs input); single Secret<N> type; wider grep; zero-after-use tests.
S13 Minor (R49): C5 freshness is hs code; structural FreshPsk from PskTable::fresh; boundary 180 s refused / 179.999 accepted; rg tripwire.
S14 Minor (L6): pq_pubkeys fill; embed in pq ELF from config (image hash) or amend law.
S15 Minor (R29): InitConf retransmit keyed by hash of whole InitConf (KnownResponseHasher); delayed InitConf up to ~600 s fresh from install; tests same biscuit different auth rejected; document delay.
S16 Minor (A5): oracle supply chain: rolling libsodium; fetch outside Dockerfile; build scripts in /work container; fix: fixed tarball + minisign, Dockerfile stage w/o /work, cargo fetch + --offline; oracle never in image.
S17 Minor: stack sizing at opt s; guard page question.
S18 Minor (RS3): 188 B ct = 24 words with trailing 4 zero bytes; MAX_WORDS zeroing loops.
RIC: R29 (crate table missing libcrux-sha3, sha3 0.10, rand_core 0.6), R39 S12, R42 S1/S8/S12, R43 S1/S2/S10/S14, R49 S6/S13, R55 S7, RS2 S5, RS3 S18; RS1 carry constant-time cookie compare; cookie secret only in ingress.

# Testing expert — M3 plan Round 1
T1 Major (RT1): golden-vector capture undefined; upstream committed vectors V03-only (rosenpass/tests/test_vector_crypto_server.rs uses V03); upstream records named values (ct/shk), RNG replay won't reproduce. C1 lacks KEM encaps seam. Fix: committed capture driver tools/rp-vectors (own Cargo.lock) depending on upstream `9e72f1eb` with expose_internal_modules, V02, plus experiment_cookie_dos_mitigation build for cookie values; commit hex/JSON with header; add Kem/Encaps seam; selftest changing a domain label must fail unit.
T2 Major (RT1): oracle build not in image/offline; libsodium-stable rolling; no --locked for 0.2.3; master toolchain 1.93.1; git dep; check-selftest copy skips build/target. Fix: Dockerfile layer (git by full hash, --locked, rustup pinned toolchain, /opt/rosenpass-{master,023}); cmake + libsodium-dev from pinned apt snapshot; committed sha256 of binaries checked by preflight; extend check-pins.
T3 Major (RT4,RT10,RT7): L8 deny vacuous vs zero-PSK fallback unless client sends zero PSK; no boundary allow; per-peer; no "before key call" test. Fix: same boot peer1 no PSK vs peer0 fresh → HandshakePskMissing + no response, then allow after rosenpass; unit REJECT_AFTER_TIME−1ns accepted / at refused; counting key 0 calls; selftest l8-fallback (integration), l8-stale (unit), l8-order (unit).
T4 Major: client hook can't shorten gateway's 180 s; upstream has no hook. Fix: drop hook; concurrent expiry case (t0 from RpPskExported; kill client rosenpass; at t0+170 allow; after t0+180+slack refuse HandshakePskStale); constants read from source; unit boundary.
T5 Major (RT7): all 11 existing integration cases use static PSK; under L8 need rosenpass first and key_out PSK; selftest anchors/needles (integration anchor, integration-count, manifest, c5-key-calls with KEY_CALLS 3→2). Fix: C7 migration subsection.
T6 Major (flaky): 130 s rotation mid-boot; wg-go caches PSK; early wg-go attempts make HandshakePskMissing totals nondeterministic. Fix: key_out watcher applying rotations, PyPeer re-reads, start wg-go after first export, since/>= assertions, rotation in retry budgets.
T7 Major (RT1): MCE-COST undefined; McEliece/Kyber encaps in pq and handshake latency under TCG unmeasured (retransmit at 0.5 s → extra decaps); no CF-analog for Rosenpass cookie path (CookieReply 1092 B); no runtime guard on assertion input. Fix: committed in-PD CNTPCT measurement (release, opt s, N>=20, median/max) for decaps, McEliece encaps, Kyber encaps, handshake latency; CF-analog probe; key audits per-decaps cost; integration asserts <= constant.
T8 Major (RT10,RT4,RT1): cookie flood no deny/attribution/ingress audits; master-client cookie completion undemonstrated; responder cookies feature-gated upstream. Fix: VE11 demonstrate; audits RpUnderLoad/RpCookieReplySent/RpCookieAccepted; deny (no cookie → CookieReply, RpInitHello total unchanged); allow attributed via sniffer; selftest integration-rp-cookie injected in Rosenpass wiring; flood replays captured mac-valid upstream InitHello; 0.2.3 allow after RpLoadCleared or own boot.
T9 Major (RT10,RT5): per-caller refusal one-sided; bucket isolation and gate isolation untested; Kani with production constants.
T10 Major (RT4): zeroization acceptance lacks oracle; reuse pmem residue scan with control (key_out gives OSK bytes); red-prove.
T11 Major (RT1): C6 lacks acceptance; sk layout conversion untested on real rp genkey output; implicit rejection makes wrong conversion silent. Fix: committed rp genkey output + liboqs ct → expected shk; swapped halves mismatch; validator fixtures; state integration path (cmr keygen).
T12 Major (RT5): Kani infeasible on crypto-laden rosenpass-core; split dependency-free rosenpass-wire (kani + bolero with upstream seeds); ingress-core mac behind trait (no libcrux in kani crate); adapter tested vs T1 vectors.
T13 Major: scenario 1 rotation without traffic interruption untested; ping loop across restart + re-handshake with new key_out + old OSK absent.
T14 Minor: debug profile stack/speed on host tests and mksecrets (Kyber 270 KB, 524 KB pk moves); profile.dev opt-level 3 for cmr/libcrux-ml-kem; in-PD stack measurement at opt s.
T15 Minor (RT7): forbidden patterns and rg member-set check not bound to a gate; add to check-pins/lint with fixtures; drop =3. pattern (lock pins).
T16 Minor: manifest keys, host_crates/kani_crates lists, BOLERO-TARGETS, needles, selftest time cost not enumerated.
T17 Minor: pick wireguard-go; name the boot; hostfwd for 51819; reboot replay via system_reset with captured initiation before new rosenpass; keep dudect out of make check.
Adjacent: A1 SHAKE256 crate missing for V02 cookies; A2 InitConf flood unmetered to pq; A3 post-reboot replay accepted once PSK present (unconfirmed session); A4 mismatched McEliece key silent.

---

# Review round: 2
Date: 2026-10-19

## Changes from Previous Round
Plan rev 2 (scope M3a):
- a `pqkey` PD with caller tables;
- the M3b split (SC26);
- L8 placement;
- `PskInstall` sent before the commit;
- public keys in the ELF;
- blob v2 and the boot KAT;
- the VE9 Dockerfile oracle;
- the C7 migration.

## Round-2 findings and rev-3 resolution
- **L8 check order:** R2-F-N1, R2-S-N4, R2-T-N1 (superseded). The correct
  order is es → static/lookup → ss → timestamp → replay/flood → fresh →
  commit. Both refusal paths and the accept path cost 2 calls.
- **C5 selftest mutations:** R2-F-N2. Recomputed for `KEY_CALLS = 2`.
- **Laws enforcement of L2:** R2-F-N3, R2-S-N1, R2-T-N3. Secrets MRs now
  carry an `owner`; no PD may hold `pp` channels to two key PDs; laws and
  package fixtures are listed.
- **Budgets:** R2-F-N4, R2-S-N8. No cut without data; MCE-COST extended;
  the cap may be raised through the amendments table; the at-cap allow
  and over-cap deny fixtures are pinned.
- **`PQ_BOOT_SEED`:** R2-F-N5, R2-S-N3, R2-S-N6. Consistent label set;
  `blob_seed`; a construction with domain separation; a bucket assertion.
- **Waiver coupling:** R2-S-N2. A `policy/waivers.toml` file coupled to the
  package refusal.
- **PSK expiry zeroization:** R2-F-N6. Done by the `hs` tick.
- **Blob formats:** R2-F-N7, R2-F-N8. Two blobs, two masks, two magics.
- **Key embedding:** R2-F-N9. `OUT_DIR` plus `include_bytes!`;
  placeholder keys under `config/keys/`.
- **Ring accounting:** R2-F-N10. In-flight counts per message type.
- **Vacuous bucket test:** R2-F-N11. Replaced by an integration test of an
  `hs` handshake under `pqkey` rate limiting.
- **Boot-check fixtures:** R2-T-N2. Three, each with its own needle.
- **RpMac:** R2-T-N4. Adapter vectors plus an integration mac/bucket deny
  pair.
- **Rotation during floods:** R2-T-N5. Wait for a fresh PSK after each
  flood.
- **MCE-COST drift:** R2-T-N6. Re-checked on every run.
- **pq→hs link residue:** R2-T-N7. Brought into M3a; the full-RAM scan
  stays in M3b.
- **Oracle hash:** R2-T-N8. A reproducible-build check, or a recorded
  hash.
- **Expiry t0:** R2-T-N9. Two bounds.
- **Boot plan and peer binding:** R2-T-N10, R2-T-N12. Boot plan,
  peer-binding construction, the 0.2.3 boot, reboot-capture allow side,
  and encapsulation KATs.
- **One gate and missing denies:** R2-T-N11. A single gate, the
  trailing-bytes deny, and a flood-state check.
- **Oracle source:** R2-S-N5. GitHub archive by commit plus SHA-256;
  crates pinned.
- **Delay wording:** R2-S-N7. Reworded.
- **Withheld InitConf:** R2-S-N9. Bound documented.
- **Guard page:** R2-S-N10. A Phase-2 question with a residual fallback.

## Raw expert outputs
# Functionality — M3 plan Round 2
Resolved: F2, F4, F5, F6, F7, F8, F9, F10, F11, F13, F15–F23. Partial: F1 (N1), F3 (N4), F12 (N3), F14 (N5).
N1 Major prose (R29): L8 order impossible — timestamp key derives from ss; order must be es → static decrypt/lookup → ss → timestamp decrypt → replay/flood → fresh → commit (refusal 2 calls, authenticated); allow/deny same initiation before/after PskInstall.
N2 Major (R3,RT7): KEY_CALLS=2 makes c5-forward-burst (22: 174<=255), c5-backlog (+7: 174), c5-interval (1/500: 4ms<=5ms) mutations pass → recompute to just cross boundary at 2 calls (e.g. FORWARD_BURST 63 → 256>255; interval 1/300); allow-side unmutated pass.
N3 Major (R49,R52): laws: policy.rs:310 single secrets MR; check.rs:312 single secrets_mr; :335 prefill one MR; :346-349 second key PD = L2; fixture two_key_pds_deny; need owner per secrets MR; each key PD maps exactly its own; no PD PPC to two key PDs; C3 selftests trip L4 not L2; new deny fixtures with allow pairs failing on L2.
N4 Major (R29,R53): hs 0.2→0.15 rationale false (PSK_MIX kdf3 ran on hs SC anyway); unmeasured; ingress extra BLAKE2b load; sum exactly at cap (f64 0.8999…). Measure hs handshakes/s and ingress per-datagram cost or raise cap with sign-off.
N5 Major (R3): PQ_BOOT_SEED contradicts Pq→{PQ_DECAPS}; pqkey blob lacks seed; boot call not in bucket invariant. Fix table everywhere; boot_seed[32] in pqkey blob; assertion (RP_HELLO burst + ring backlog)×1 ≤ PQ_KEY_BURST − PQ_BOOT_CALLS with red-proof; pq calls at init, halts on refusal.
N6 Minor (R39): PSK expiry zeroization dropped; hs tick zeroizes at ≥180 s; unit test.
N7 Minor (L6): package two blobs/masks/magics; amend L6.
N8 Minor prose: pqkey blob version naming (key v2, pqkey v1, separate magics).
N9 Minor (execute): 4.5 MiB embed via OUT_DIR include_bytes in pq only; gateway.toml key paths; placeholder keys location.
N10 Minor (execute): ring reservation needs per-type in-flight accounting.
N11 Minor: cross-PD bucket isolation test vacuous; replace with hs handshake under pqkey rate-limit (integration).
Checked OK: priorities; hs drains pq before ih.

# Security — M3 plan Round 2
No Critical; Round-1 Critical/Major resolved or waived (S2 waiver needs N2; S7 seed source N3; S10 N1; S11 N4; S15 N9; S16 N5; S17 N10).
N1 Major (R52,R49,L2): laws can't express secrets-MR ownership/disjoint callers (check.rs first secrets MR only; key_pds>1 = L2). Fix: owner on secrets MRs; each secrets MR mapped only by owner; each key PD exactly its own; prefill on every secrets MR only; no PD with pp channels to two key PDs; fixtures deny/allow; ownerless = policy error; replace two_key_pds_deny with owner-based deny.
N2 Major (R49,R43): dev-only package refusal tied to SC20 (M7) only; couple to waivers SC23/SC26 via committed policy/waivers.toml; package refuses non-debug while waivers open; selftest deny/allow; missing/unparsable = refuse.
N3 Minor(b) (L9,R29): PQ_BOOT_SEED source: independent boot_seed in pqkey blob; BLAKE2s("pq-boot-seed" ‖ seed ‖ RNDR ‖ CNTPCT); idempotent; halt on RNDR fail; test pq/hs seeds differ.
N4 Minor(a) (R29): L8 order impossible; correct: es → static/lookup → ss → timestamp → replay/flood → fresh → commit.
N5 Minor(a) (A5): VE9 git checkout vs check-pins P1; use GitHub archive by commit + sha256; pin new crates (cmr =2.0.2, libcrux-ml-kem =0.0.11 kyber, sha3 0.10, rand 0.8, zeroize).
N6 Minor(a): pqkey label set consistent {PQ_DECAPS, PQ_BOOT_SEED}.
N7 Minor(a): "WireGuard unaffected" overstated — pqkey prio 130 on pq SC preempts hs; bounded by pq budget.
N8 Minor(b) (R53): budget sum exactly at cap; record headroom; fixtures at-cap allow / over-cap deny.
N9 Minor(a): delayed InitConf (~600 s) freshness bound documented in L8 and residuals.
N10 Minor(a) question: Microkit stack guard page? citation or residual.

# Testing — M3 plan Round 2
Resolved T1, T3, T4, T5, T6, T9, T11–T17 (with gaps → N-items); T8 deferral OK; T10 conditional; T7 partial.
N1 Major (RT7,RT5): refusal key-call count vs order (superseded by Func N1: correct order puts ss before fresh → refusal 2 calls; keep red-proof l8-order).
N2 Major (RT7,RT4): boot KAT and H(spkm) not isolated; KAT ct must be encapsulated to configured spkm; three fixtures: (a) foreign pqkey MR → H(spkm) halt; (b) sk replaced, KAT+H kept → KAT halt; (c) halves swapped → KAT halt; separate needles; red-prove (a),(b).
N3 Major (RT7,RT10): laws/package allow/deny fixtures for two key PDs (allow disjoint; deny shared MR, caller of both, pqkey maps non-secrets, prefill on non-secrets, ownerless third secrets MR); PACKAGE-FIXTURES both MRs swapped allowed / other byte or pqkey blob in key MR refused.
N4 Major (RT5,RT10): no e2e deny for RpMac/RP buckets; adapter unit test vs rp-vectors; integration pair: flipped mac byte → RpBadMac + no RespHello, genuine completes; replayed InitHello burst from one source → RpRateLimited, after refill client completes; red-prove always-true adapter.
N5 Major (flaky): migrated WG floods starve RP rotation → stale PSK; wait for fresh RpPskExported after floods or restart client rosenpass; named failure; record rotation loss.
N6 Major (RT1): MCE-COST constants never re-checked; pq audits per-handshake cost; run.py prints and fails if above constant (+slack); red-prove lowering constant.
N7 Major (RT4): T10 deferral → either bring pq→hs link residue case now (wait_absent with control, OSK from key_out) or state L12 OSK zeroization unverified residual (SC26).
N8 Minor(b) (RT1): oracle sha256 requires reproducible build; check twice --no-cache or record image hash vs repo pin.
N9 Minor(b): expiry t0 bounds: allow side from key_out write time; deny side from RpPskExported console time.
N10 Minor(a): migration prelude vs peer-1 L8 deny boot; boots without rosenpass (raw frames, mismatched blob); peer-binding case construction and assertion.
N11 Minor(a): one gate for forbidden patterns; C2 trailing-4-bytes non-zero deny; C5 flood state unchanged too.
N12 Minor(b): name 0.2.3 boot/config; reboot capture from Python initiator with prior HandshakeOk allow side; deterministic encapsulation KATs for cmr/libcrux Kyber.

---

# Review round: 3
Date: 2026-10-19

## Changes from Previous Round
Plan rev 3 made these changes:
- corrected the L8 order;
- owner-based laws;
- tied waivers to packaging;
- added `PQ_BOOT_SEED` with `blob_seed`;
- re-checked MCE-COST on every run;
- added the link residue case;
- added the boot-check fixtures.

## Round-3 findings and rev-4 resolution
- **Rate assertion** (R3-S-M5, R3-F-R3-3): `PQ_KEY_INTERVAL_NS ≤ RP_HELLO_GLOBAL_INTERVAL_NS`.
- **Waiver file** (R3-S-M1): a check-pins rule binding `Cargo.lock` cmr 2.0.2 to SC23. The control class is declared.
- **Budget ceiling** (R3-S-M2): hard ceiling 0.95; anything beyond means re-planning.
- **`pqkey` RNDR failure** (R3-S-M3): `pqkey` halts if RNDR fails at boot.
- **VE9 fallback** (R3-S-M4): declared a tripwire; the assurance inputs are named.
- **Prose fixes** (R3-F-R3-1, R3-F-R3-2): the label set and blob naming are fixed.
- **Cost carrier** (R3-F-R3-4, R3-T-M3): `PQ_HANDSHAKE_COST_NS` drives the assertions; `RpCostHighWater` is emitted on rise only; the run.py check runs in a quiet window.
- **`pq` behaviour when `pqkey` halts** (R3-F-R3-5): `pq` blocks, and that still fails closed; the needles are stated.
- **Files list** (R3-F-R3-6): adds `waivers.toml`, the package waiver check and the selftest case.
- **Integration case** (R3-T-M1): the unreachable "hs under pqkey rate-limit" case is dropped in favour of unit isolation tests.
- **PSK expiry** (R3-T-M2): a tombstone keeps `HandshakePskStale` observable; `l8-stale` and `l8-expiry-tick` are red-proved separately.
- **Waiver proof** (R3-T-M4): proven with SC20 stubbed, plus a selftest case removing the waiver check.
- **Peer binding and 0.2.3 peer** (R3-T-M5, R3-T-M6): explicit swapped records, a validator duplicate fixture, and an own peer for 0.2.3.
- **Floods and fixture (b)** (R3-T-M7): rosenpass restarts after floods; the splice helper is tied to the layout constants.

## Raw expert outputs
# Functionality — M3 plan Round 3
No Major. Round-2 N1–N11 resolved (N8 partly: R3-2). c5-backlog needs X ≥ 112.
R3-1 Minor(a): Objective 3 "exposes only Decaps" vs {PQ_DECAPS, PQ_BOOT_SEED}.
R3-2 Minor(a): C2 heading "Secrets MR v2" vs pqkey blob v1.
R3-3 Minor(a) (R3): pqkey rate assertion PQ_KEY_INTERVAL_NS ≤ RP_HELLO_GLOBAL_INTERVAL_NS (= Sec M5).
R3-4 Minor(a) (R12,R40): per-handshake cost has no audit carrier (records {code,total,lost}, coalesced); define non-coalesced parameterised code (cost µs in a) or debug print; list in C3.
R3-5 Minor(a) (R49): pq blocks (not halts) if pqkey halted at init; state "pq blocks; no PSK; WG refused"; fixture needles = pqkey halt message + absence of "pq: ready".
R3-6 Minor(b): files list omits policy/waivers.toml (schema id/owner/status), package waiver check, selftest cases.

# Security — M3 plan Round 3
No Critical/Major. Round-2 N1–N9 resolved; N10 tracked (Phase-2 question).
M1 Minor(b) (R49): waivers.toml honour-system; check-pins consistency rule: Cargo.lock contains classic-mceliece-rust 2.0.2 ⇒ waivers lists SC23; fixtures deny/allow/allow; SC26 manual (stated).
M2 Minor(b) (R43,R53): cap raise needs hard ceiling (< 1.0 minus non-tainted reservations, margin for key/pqkey); beyond ceiling = re-plan; fixtures ceiling ± ε.
M3 Minor(a) (L9): pqkey halts on RNDR failure at boot; add to C2.
M4 Minor(a) (R51,R49): VE9 fallback compares self-recorded commit → declare tripwire; real assurance = archive sha256 + Cargo.lock.
M5 Minor(a) (RS2): pqkey bucket rate assertion PQ_KEY_INTERVAL_NS ≤ RP_HELLO_INTERVAL_NS; red-prove.

# Testing — M3 plan Round 3
Round-2 resolved (N1 superseded, N2–N5, N7–N9, N12; N6/N11 partial).
M1 Major (RT4,RT7): integration "hs succeeds while pqkey rate-limited" unreachable (bucket assertion forbids) → drop; unit tests + assertion red-proof + optional scratch measurement.
M2 Major (RT4,RT7): expiry tick zeroizes → deny sees Missing not Stale; l8-stale masked. Fix: tombstone (installed_at kept, osk zeroized) so Stale reportable; unit l8-stale (no tick) and l8-expiry-tick separately.
M3 Major (RT1,L10): per-handshake cost unauditable (Record totals, coalesced; per-handshake non-coalesced violates L10); no named cost constant; preemption flakes max. Fix: PQ_HANDSHAKE_COST_NS in production crate driving assertion; high-water-mark event on rise (state edge, a = cost); run.py checks quiet-window HWM vs constant + slack; red-prove.
M4 Major (RT7): waiver package deny falsely attributed to SC20 debug refusal; prove in test_package.py with SC20 stubbed (open waiver refuses naming it; missing/unparsable refuses; none allows); selftest removing waiver check with waiver needle.
M5 Minor(a): lint vs pins leftover; peer-binding records explicit ({wg0,rp1},{wg1,rp0}); validator duplicate wg_pub/rp_pub fixture; extra make image counted.
M6 Minor(a): 0.2.3 client peer identity vs prelude master client; own peer or stop master; before first flood.
M7 Minor(b): restart rosenpass after floods instead of waiting ≤130 s; fixture (b) blob-splice helper tied to secret-blob layout constants.

---

# Review round: 4
Date: 2026-10-19

## Round-4 findings and rev-5 resolution
- **Peer binding** (R4-T-Q1 and R4-F-R4-1, Major, convergent): only
  client 0 runs, giving deny `HandshakePskMissing` at record 0; the bound
  deployment is the allow side; the mis-pairing is recorded as a residual.
- **Cost events** (R4-S-P2, R4-F-R4-2): power-of-two buckets, bounded to
  about 32 events per boot; a value-carrying audit path; wall ns measured
  in a quiet window.
- **Expired entries** (R4-S-P1, R4-F-R4-5): `enum Entry { Absent, Live, Expired }`;
  `FreshPsk` only from `Live`; tests and a red-proof.
- **Ceiling and assertion** (R4-F-R4-3): the 0.95 rationale is corrected;
  the assertion uses `RP_HELLO_GLOBAL_BURST`.
- **SC23 rule** (R4-F-R4-4): it requires `status = open`; added a fixture
  with SC23 closed.
- **Harness** (R4-T-Q2): `--peers 3` harness changes.
- **Quiet window** (R4-T-Q3): defined as the boot-2 prelude range.

## Raw expert outputs
# Functionality — M3 plan Round 4
Resolved R3-1..R3-6.
R4-1 Major (R29,R40) [Adjacent]: peer-binding with both clients → both indices fresh (wrong) PSK → no Missing; gateway HandshakeOk, client fails. Fix (i) only client 0 runs Rosenpass → deny Missing at index 0 / allow bound deployment; or (ii) both → client handshake fails, gateway HandshakeOk; residual: L8 can't detect mis-pairing at gateway.
R4-2 Minor(a) (R49,L10): RpCostHighWater rise-only unbounded at µs granularity; emit only on ≥1/8 rise or power-of-two crossing (≤ log2(max/min)+1); unit "wall ns incl. preemption".
R4-3 Minor(a): 0.95 rationale wrong (passive time already in caller budgets; only timer 0.01 untainted); bucket assertion operand RP_HELLO_GLOBAL_BURST.
R4-4 Minor(a) (R49): SC23 rule must require status=open; fixture cmr present + SC23 closed → deny.
R4-5 Minor(a): Design expiry text and PskTable type (Option<Osk>, installed_at) to match tombstone.

# Security — M3 plan Round 4
No Critical/Major. Round-3 M1–M5 resolved. R43: tombstone retains no secret; audit integers L10-compliant.
P1 Minor(b) (R55,L8): tombstone must be a distinct Expired variant: enum Entry { Absent, Live { osk, installed_at }, Expired { installed_at } }; FreshPsk only from Live; tests Expired with recent installed_at refused, Live at 180−1ns accepted, PskInstall on Expired → Live; red-prove fresh() accepting Expired.
P2 Minor(b) (R29,L10): RpCostHighWater rise-only unbounded; power-of-two µs buckets (≤ ~32 events/boot), test monotone sequence ≤ ceil(log2(max)); define CPU vs wall (CPU on pq SC preferred); value-carrying record path (Coalescer::record writes a = total).

# Testing — M3 plan Round 4
Resolved M1–M4, M6, M7; M5 partial.
Q1 Major (RT4): peer-binding with both swapped clients running → both records fresh → HandshakePskMissing never fires; run only client 1 (record 1 no PSK → Missing, no response) or assert response-not-open/no SessionPromoted/ping fails; allow side = bound deployment.
Q2 Minor(a): --peers 3 needs run.py build() and check_harness_matches_config updates; deployment b same peer count.
Q3 Minor(b): MCE-COST quiet window = console-mark range (boot-2 prelude until RpPskExported for every prelude peer).

---

# Review round: 5
Date: 2026-10-19

## Findings and rev-6 resolution
# Round 5
Func: no Major; R4-1..R4-5 resolved. R5-1 Minor(a) C3 audit text; R5-2 Minor(a) carry exact cost, bucket gates emission.
Sec: no Critical/Major; P1, P2 resolved; SC23 status=open correct; peer-binding sound; mis-pairing residual accurate (fails closed). Q1 Minor(b) = same as R5-2 (exact value; boundary; red-proof injected 1.5x).
Test: R1 Major (RT4,RT10) peer-binding deny vacuous → precondition RpPskExported + same-boot allow (wg1 + client 0 key_out completes); R2 Minor(b) = exact µs (done); R3 Minor(a) quiet window fails when none in range; l8-expiry-tick needle → Expired.

Resolutions:
- R5-F-R5-1 and R5-F-R5-2: wording fixed; the exact cost travels in `a`, and the bucket only gates emission.
- R5-S-Q1: boundary stated, plus a red-proof with an injected cost of constant × 1.5.
- R5-T-R1: precondition plus a same-boot allow.
- R5-T-R3: the window fails when no event falls in it; the needle is updated.
- R6-S-Q1': emit on ≥1/8 rise over last emitted (bounded log1.125), reported max ≤12.5% low; rise-within-bucket red-proof.

---

# Review round: 6
Date: 2026-10-19

## Findings
- **Security:** no Critical or Major findings.
  - Q1′ [Minor(b)]: the exact value was captured only at the bucket
    crossing.
- **Functionality:** no Critical or Major findings.
  - R6-1 [Minor(a)]: the same issue as Q1′.
- **Testing:** no Critical or Major findings; the testing perspective is
  saturated.
  - S1 [Minor(b)]: the red-proof that set the constant "just below the
    observed value" is run-dependent.

## Resolution (rev 7)
- **Q1′ / R6-1:** the event is emitted on a rise of at least 1/8 over the
  last emitted value. That bounds the count to about
  `log₁.₁₂₅(max/min) + 1`, and the reported maximum is at most 12.5% below
  the true one. It is red-proved with a sequence that rises inside one
  bucket.
- **S1:** the run-dependent red-proof is dropped. The deterministic
  boundary pair and the 1.5× injection remain.

## Saturation call (Round 6)
1. Six rounds are complete.
2. No Critical or Major finding is open. MCE-COST and GUARD are carried
   by design as measurements, with Anti-Deferral entries.
3. No open finding is against the design. Q1′/R6-1 was a design-level
   Minor and is fixed in rev 7.
4. The remaining items are applied, or reachable only by executing.

**Decision:** plan review is closed. C1–C8 are locked. Proceed to Phase 2.
