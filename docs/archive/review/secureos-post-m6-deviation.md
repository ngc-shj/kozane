# Coding Deviation Log: secureos-post-m6

## Slices 1–2 (P1 with amendment A1, P2)

Gates run:
- make lint/lint-pds/unit/laws/pins green on the merged tree;
- Kani, each new or changed harness alone on gx10 or z1mn: the 7
  `rp_unfinished_*` harnesses and every changed `rp_*` harness, rc=0;
- `rp-rotating-spoof` red with its needle (mrx33);
- `rp-cookie-gate` red with its needle (mrx33).

Deviations and findings:

- **P2, `rp spoof`.** As the plan's diagnosis states: the verdict window
  ended at the victim's completion (0.75 s), before the next spoof (1 s
  period). The case now spoofs until a CookieReply reaches the spoofed
  endpoint, and fails only on `RpLoadCleared` first or the liveness
  timeout. It passes on mrx33 too.
- **P2, `rp latency` (recurrence of the M4 observation; a test defect).**
  - **Evidence.** On z1mn, alternating 3-and-3 runs of the A1 tree and of
    the pre-A1 tree (3bb8e5b) each failed 1 of 3. So the failure predates
    A1.
  - **Mechanism.** A per-attempt trace showed the first initiation
    answered, before the setup exchange's export reached `hs` (expected:
    `py_installed` retries). Every later initiation went unanswered.
  - **Why.** Over the 20 s window, the 200/s spoof offered about 4000
    frames. Ingress served about 1400 (`RpCookieReplySent`) and the NIC
    dropped about 2500 (`eth_out RxNoBuffer`). Under TCG, ingress's
    budgeted rate on this path is about 70 InitHellos/s, against 968/s on
    the WireGuard cookie path (capacity probe). That gap is mac and cookie
    work on an InitHello of about 1 KiB. The peer's initiations were
    dropped with the flood, so the verdict measured RX overflow luck.
  - **Fix.** `RP_LATENCY_SPOOF_RATE` = 20/s, which still holds load (the
    global meter refills one per 10 s). The case waits for `RpUnderLoad`
    before judging. A new precondition, `rx_overflow`, fails the case when
    `RxNoBuffer` appears in the window. The budget is not widened.
  - **A first cut waited for a new `RpUnderLoad` since the mark, and timed
    out.** Load can already be on at the mark, engaged by the setup
    exchange's uncookied InitHello on a drained unfinished meter. The case
    now reads state through `wait_rp_loaded`: the gate is on when there
    are more `RpUnderLoad` lines than `RpLoadCleared` lines.
  - **The loaded failures on z1mn (2 of 3 under 2 busy cores; gx10 passed
    3 of 3) were not handshake failures.** A trace of the tries and of
    the WireGuard frames showed one initiation, answered in 25 ms, and
    the handshake succeeded. The `Fail` came from `spoof.verify` right
    after: at 20/s, a just-started spoofer thread delayed by host load
    delivers fewer than 90 % of a dozen scheduled datagrams. The case's
    `except` rewrote every `Fail` as "no WireGuard handshake".
    - **The fix:** the case waits for one second's worth of spoofs
      (`wait_delivered`) before judging, and its message keeps the cause.
    - **Kept for diagnosis:** the per-try trace in `py_installed`, the
      WireGuard frame trace on failure, and `PyPeer.lost` (ENOBUFS from a
      full tap queue, which was silently swallowed before).
  - **The precondition's red-proof:** at 200/s the case fails with
    "precondition: the outside NIC dropped frames (RxNoBuffer)" (mrx33).
  - **Not changed.** `rp combined flood` keeps 200/s. Its purpose is
    overload, including tier-2 suppression, and its client retransmits on
    upstream's backoff within the budget.
- **P2 step 4, the wall-clock verdict audit (T8).**
  - **Keepalive's 10–13 s window.** The lower bound is a safety verdict
    that load cannot break (load only delays). The upper bound is a
    liveness bound with a 3 s margin. The quiet and deny windows are
    "nothing arrives" verdicts, which delay cannot falsify.
  - **`py_ping`.** A liveness timeout: 3 tries, each answered within 3 s.
  - **The paired flood band.** 1.4 × the arrival refill, valid while C ≥
    C_MIN × refill. The same boot's capacity probe measures C (968/s on
    gx10).
  - **The rp fan-in budget.** 3 × 16.1 s + 10 s + 10 s = 68 s, a liveness
    bound. Idle InitHellos cost about 0.7–2 s, so the margin is above 10×.
  - **rp latency's 19 s.** A liveness bound with the RX precondition above.
- **The memory rule "integration only on a host with no solver"** is
  retired for these two boots only, after these runs:
  - `rp gate boot` under 2 busy cores passed 3 of 3 on z1mn and 3 of 3 on
    gx10. One more z1mn run failed in setup (`make package`), right after
    an interrupted run had been killed on the shared `pd_target`. It
    reached no verdict and was rerun;
  - `cookie boot a` under 2 busy cores passed 3 of 3 on z1mn;
  - both boots passed once on gx10 beside a capped Kani harness.

## Slice 3 (P3)

Gates run:
- unit/lint/pins green;
- Kani: `cap_status_is_pure_and_never_confirmed_before_a_confirmed_extend`
  alone (3/3 covers), then the tpm2-wire gate, 11 of 12. Its twelfth,
  `unseal_after_the_cap_is_refused`, ended with "CBMC failed with status
  15": SIGTERM from the P4 incident below, not a failed check. It was
  rerun alone with `tools/kani-harness --exact`;
- QEMU `tpm cap failure` boot green (mrx33);
- `cap-failure-ignored`, `cap-barrier-skipped` and the rewritten
  `sealed-cap` red with their needles.

Deviations:
- **Audit slots.** `RpUnfinishedLoad` = 0x005a (slot 62) and `TpmCapFailed`
  = 0x005b (slot 63). Slices 2 and 3 were written in parallel and both took
  slot 62. The merge resolved that, and `FIXED_SLOTS` is now 64.

## Slice 4 (P4 (b), (c); P5; P6)

- **P4 (b), `tools/selftest-split`.** Commands: `plan`, `pack`,
  `run <qemu|solver|pds|rest>` and `merge`. Classification uses
  check-selftest's `CASES` and `closure()`, plus each recipe's
  `$(MAKE) <target>`. The current split is qemu 41, solver 16, pds 7 and
  rest 156.
  - **Beyond the plan:**
    - check-selftest refuses unknown case names;
    - `rule_prerequisites` joins backslash-continued lines;
    - check-selftest prints `SELFTEST-CASE <name> ok|FAIL` for the merge;
    - `qemu` and `pds` share a lock on the `pd_target`;
    - a pack made at another commit is refused.
  - **Not exercised end to end yet:** it first runs in slice 6.
- **P4 (c), `tools/kani-guarded` and `tools/kani-harness`, now in Python.**
  - **Behaviour changes from the build/ scripts:**
    - only cbmc under this run's gate is counted and stopped, where the
      shell version counted every cbmc on the host;
    - the exit code is the gate's, or 1 when the guard tripped;
    - `-p <crate>` is required, and the harness name is passed as given.
  - **Incident.** While proving its tests could fail, the subagent ran a
    deliberately broken kani-guarded with the descendant filter removed.
    It signalled a real cbmc of the running tpm2-wire gate, as slice 3
    records.
    - **The fix:** both tools match only the cbmc name in
      `SECUREOS_KANI_CBMC` (default `cbmc`), and the tests set it to
      `cbmc-fixture-<pid>`. A broken filter can no longer reach a real
      solver.
- **T16, `check-selftest --dry`.** Each injection is applied to a freshly
  synced copy, and nothing is made; all 220 cases take about 3 minutes.
  The fixture is red when `dry_case` ignores a miss.
  - **Its first run found two dead anchors**, both in tls's main.rs:
    - `tls-key-halt` was broken by P3's `TpmCapFailed` record;
    - `proxy-pd-backend-rst` was already dead at HEAD, since M6 moved the
      backend end into the `BackendEnd` match. M6 deferred its full
      selftest, so nothing caught it.
  - **The fix.** Both are re-anchored with the same mutation, and their
    QEMU red-proofs are rerun.
- **P5, the amd64 image.**
  - **The image.** docker/Dockerfile selects per-architecture artifacts by
    BuildKit's `TARGETARCH`: rustup-init, Z3, the Arm GNU toolchain, the
    Microkit SDK and the Kani bundle.
  - **How the new pins were checked.** Each x86_64 hash was checked against
    an independent source:
    - rustup's `.sha256`;
    - Arm's `.sha256asc`;
    - GitHub's asset digests for Z3, Microkit and Kani;
    - the Microkit signature, against the pinned key.
    The aarch64 rustup-init hash recomputed to the existing pin.
  - `make -C docker build-amd64` added. The image builds on
    ul9c-wsl2-island; two transient TLS download failures were retried.
  - **Acceptance amended.** "`make unit` passes on x86_64" does not hold,
    and the QEMU run is deferred. Four aarch64-host assumptions block it:
    - `crates/cpu`'s host build uses aarch64 inline asm (`mrs
      cntpct_el0`, `mov sp`), so `make unit` fails;
    - `ct-harness` links with `--fix-cortex-a53-843419`, so `make test`
      fails at `ct`;
    - U-Boot is built natively (`-march=armv8-a+crc`). Its measured values
      are pinned in run.py, so a cross build is a measurement change;
    - run.py pins the rosenpass oracle binaries' sha256, which differs per
      architecture.
  - **Decision.** The build is the acceptance. The x86_64 run would change
    measured-boot pins for test capacity only, so it stays deferred, with
    these four named blockers.
- **P6.** The repository had no README. The backend trust contract (S8)
  was written in full and lands in the public README of the
  `docs/public-release` branch (prepared in another session; verified to
  carry the section verbatim), not in this commit, so the two README
  additions do not collide.

## External notes received (2026-10-26, from another session's qedos comparison)

- **Clients without PQ groups (new residual under L14).** iPad WebKit (iOS
  version unknown) offered only x25519 and secp* in its ClientHello. The
  gateway's TLS requires X25519MLKEM768, so such clients cannot connect.
  L14 stays; there is no classical fallback.
- **Laws checker scope (later candidate).** `tools/laws` checks the
  `.system` against `policy/laws.toml`. It does not read Microkit's
  generated report. Auditing the generated capability graph would catch a
  Microkit translation fault; it is recorded as a candidate, not done.
- **raspi4b has no GENET in QEMU.** This supports building M7 on `virt`.

## Slice 5 (P7, the rename to Kozane, with P4 (a))

Gates run:
- make lint/lint-pds/unit/laws/pins/repro green on gx10;
- check-selftest `--dry` 220 of 220;
- check-pins fixtures 281 of 281;
- QEMU on z1mn: `measured boot` (the new banner), `sealed boot` and
  `tpm cap failure` green.

The full `make check` and selftest are the combined long run (slice 6).

- **The substitution.** It covered every tracked file outside docs/archive
  and third_party: `secureos` → `kozane` and `SECUREOS_` → `KOZANE_`.
  - Citations of archive file names (`secureos-pq-vpn-architecture-*`,
    `secureos-m<N>-*`, `secureos-post-m6-*`) were held out, as the plan
    requires.
  - **Files renamed:** `system/kozane.system` and
    `support/u-boot/kozane.config`.
  - **Docker names:** `kozane-dev` (image and container), the volume
    `kozane-cargo-registry` (copied from the old one, which is kept for
    now), and `kozane-rp-oracle`. The containers were recreated with
    docker/Makefile's `run` flags on gx10, z1mn and mrx33. The image
    content is unchanged, since only its tag is new. `make -C docker run`
    was not used: it rebuilds first, and P5's Dockerfile change misses
    the cache on arm64.
- **Removed: `crates/pds/hello`.** The M0 hello PD was a workspace member
  that no image contained (the Makefile's `pds` list omits it). It is
  removed with its Cargo.lock entry, so the public tree has no dead PD.
  The laws fixtures still name `pd-hello.elf`, as fixture text.
- **Format changes:**
  - **Release domain** `kozane-release-v1\0`. There is a new test,
    `a_signature_over_the_old_domain_is_refused`: with the right keys, a
    signature over the old domain fails, and the same construction over
    `DOMAIN` verifies, which proves the domain caused the refusal. No
    fixture is pre-signed; the tests sign their own.
  - **Cookie nonce label** `kozane cookie reply nonce`.
  - **rp-vectors.** `cookie.txt` was regenerated through the pinned oracle
    image (`--cookie`). Only `shake.data` and `shake.out` changed, the
    label-dependent lines.
    - The keyed-hash KAT label in `v02.txt` stays `secureos …`. Only a
      full regeneration rewrites it, and that also draws new keys, so it is
      not label-only. It is a test input, not a wire format, and it is
      listed in the allowlist.
  - **U-Boot banner and boot script** (`kozane: measured`, `kozane: boot
    refused`). PCR 8's expected value is computed at run time
    (`tools/measure.py`), not pinned, so no constant changed.
  - **`--remap-path-prefix=…=/kozane` and `~/.cache/kozane/pd-target-*`.**
    The reproducible digests change; `make repro` was rerun.
- **Test vectors and fixtures:**
  - **wg-core's keyed-BLAKE2s vectors** were recomputed with Python
    `hashlib`. The old labels reproduce the old values, which checks the
    method.
  - **`ecdsa_sigs.txt` and `keylog.txt`** were regenerated with
    `tests/tls/*.py`.
  - **A capture finding.** `openssl s_client` reads a line starting with
    "k" as its KeyUpdate command. The renamed line "kozane keylog
    fixture…" therefore became a KeyUpdate, and the capture failed with
    InvalidTag. The lines now start with "The kozane…", and a comment
    records the constraint.
- **S7, stale variables fail closed.**
  - `crates/config/build.rs` panics when `SECUREOS_CONFIG` is set without
    `KOZANE_CONFIG`; there is a fixture in `test_config_build.py`.
  - `run.py` refuses to start when any `SECUREOS_*` variable is set
    without its `KOZANE_` name. This is checked first in `main`, before
    any build, and was seen to refuse `SECUREOS_IT_BOOTS=x`.
- **P23, the old name.** A new check-pins rule. It skips docs/archive,
  third_party, build, target, .git and .claude. Elsewhere, a line naming
  `secureos` (or `secure_os`, `secure-os`, in any case) passes only if
  it is an archive citation, or its file is in `policy/old-name-allowlist`
  with a reason.
  - A listed file that still exists but no longer names it is a stale
    entry. A listed file that is gone is not judged: the P7 fixtures
    replace `crates/` wholesale.
  - It has four fixtures: three red, one allow.
- **P4 (a), the proof lock.** It moved to `/tmp/kozane-proof.lock` and
  `KOZANE_PROOF_LOCK(ED)`. The switch was made with the containers just
  recreated, so nothing held the old path. Every proof cache is
  invalidated once, inside the long run.
- **Git history, before publishing all of it.** A search of every commit
  found:
  - PEM private keys, AWS keys, GitHub tokens: none;
  - `PrivateKey =` lines: only WireGuard config templates;
  - key-like file names: only the laws fixtures.
  The M5 dev release keys are generated at run time, so none was
  committed.
