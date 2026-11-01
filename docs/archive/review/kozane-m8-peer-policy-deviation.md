# Coding Deviation Log: kozane-m8-peer-policy

Observations and deviations against
[kozane-m8-peer-policy-plan.md](kozane-m8-peer-policy-plan.md), in order.

## Slice 0: probes

Probe scripts live under `build/probes/` (untracked scratch), and each
result below names the facts it established. The scripts run in the
`kozane-dev` container on gx10 unless stated.

### P1 — swtpm NV semantics (passed, 2026-10-29)

Run on swtpm 0.7.1 with tpm2-tools 5.7 (`build/probes/p1/{probe,special,undef}.sh`, twin
`build/probes/p1/twin.py`). Every check passed:

- **Definitions.** The counter `0x01500100` was defined with attributes
  `0x42040414` and the base `0x01500101` with `0x42042404`, both under the
  platform hierarchy and both with the delete policy. The attribute sets
  are the C3 ones:
  - counter: `TPM_NT_COUNTER`, `AUTHWRITE`, `AUTHREAD`, `NO_DA`,
    `POLICY_DELETE`, `PLATFORMCREATE`;
  - base: the same bits with `WRITEDEFINE` instead of the counter type.

  tpm2-tools' attribute keywords do not cover `policy_delete`, so the
  numeric values are used. The host twin needs them anyway.
- **Delete policy twin.** The twin computes
  `PolicyCommandCode(NV_UndefineSpaceSpecial) ∧ PolicySigned(op1) ∧
  PolicySigned(op2)` with a fixed `policyRef`, and the TPM accepted that
  digest as the indices' authPolicy.
- **Counter and base.** The first `NV_Increment` gave counter 1 on a fresh
  swtpm, and the next increment gave exactly +1. With `base =
  counter.wrapping_sub(7)`, the logical version came out as 7. A write to
  the base after `NV_WriteLock` was refused.
- **Names.** Both Names match the twin. The counter's Name includes
  WRITTEN, and the base's Name includes WRITTEN and WRITELOCKED.
- **Plain undefine is refused by the TPM.** A raw `TPM2_NV_UndefineSpace`
  of the counter returns `0x282` (TPM_RC_ATTRIBUTES on the NV handle),
  under both the owner and the platform hierarchy. The probe sends it raw
  because tpm2-tools refuses it client-side, so the tool alone never
  reaches the TPM.
- **TPM2_Clear.** `TPM2_Clear` (platform) succeeds and leaves both indices
  with their Names and the counter value unchanged.
- **Persistence.** The counter value survives a SIGKILL of swtpm followed
  by Startup(CLEAR).
- **`resetCount`.** It goes up by exactly 1 across a power cycle, both
  after an orderly Shutdown(CLEAR) and after a SIGKILL. That is the C10
  `reset_at_provision + 1` fact.
- **`NV_UndefineSpaceSpecial`.** It succeeds only with both operators'
  PolicySigned in the session, each bound to the session's own
  `nonceTPM`, `expiration = 0`, the fixed `policyRef`, and `cpHashA` of
  this command and index. The refusals:
  - one signature only: refused (policy check);
  - signatures bound to the other index's cpHash: both PolicySigned
    calls are accepted, then the command is refused;
  - a signature replayed into a new session: PolicySigned refuses it
    with `TPM_RC_SIGNATURE` (0x5DB), because the nonce differs.
- **Capabilities.** `phEnableNV` and `phEnable` are readable through
  `GetCapability`, and `ownerAuthSet` is 0.

Note for C3: tpm2-tools leaves `loadexternal` objects loaded. More than
three PolicySigned calls in one run exhaust swtpm's object slots
(`0x902`) unless transient contexts are flushed. The provisioning tool
must flush after each one.

### P2 — no_std signature verification (build and vectors passed; TCG timing moved)

Probe crate: `build/probes/p2`. It contains the verify path the `policy`
PD would use, with Ed25519 AND ML-DSA-65 over `DOMAIN ‖ body` and an
empty ML-DSA context, the same convention as `tools/release`.

- **Build.** It builds for `aarch64-sel4-microkit` with
  `-Z build-std=core,compiler_builtins` (core only, no alloc), at
  `tools/release`'s pins `libcrux-ml-dsa =0.0.11` and
  `libcrux-ed25519 =0.0.10`.
- **Lockfile impact.** Only those two packages are new to the PD
  `Cargo.lock`. Every dependency they pull in (libcrux-sha3/-sha2/
  -intrinsics/-platform/-secrets/-hacl-rs/-traits, libc 0.2.191,
  rand 0.10.3) is already locked at the same version.
- **Vectors.** Allow; a flipped body byte is denied; the Ed25519 half bad
  alone is denied; the ML-DSA half bad alone is denied.
- **Native cost per boot** (SHA-256 of both slots plus verification of
  both, gx10): 33 ms at the maximum body (4.25 MB), 4 ms at one peer.
- **Deviation:** the plan's pass condition measures `policy` under TCG
  at its real priority, with the key PDs running above it. That needs the
  `policy` PD, which does not exist until slice 3. That measurement moves
  to the first boot carrying `policy` in slice 3, with the pass condition
  unchanged. The container has no qemu-user for a stand-alone TCG run.
  - Anti-Deferral: the native cost leaves a 30× margin under one second,
    so the design premise the probe guards (verification fits the boot
    budget) holds now.
  - The worst case is a TCG slowdown far beyond the usual 10–50×, found
    in slice 3. It would only re-time `CAP_BARRIER_TIMEOUT_NS` and
    `BOOT_TIMEOUT_S`, not change a contract.

### P3 — measuring and loading two `BUNDLE_MAX` slots (passed in two parts)

Run in a scratch worktree (`build/probes/p3/tree`, since removed).

- **U-Boot under TCG.** A probe variant of the boot command loads two
  random 4.5 MiB slots at `0x6f100000` and `0x6f600000` (below the
  `0x6fb00000` scratch), hashes each, extends PCR 9 with A then B,
  copies both and prints PCR 9.
  - The two hashes, two extends and two copies take **0.15 s** under TCG
    (`cortex-a72`, the shipped TF-A and U-Boot).
  - PCR 9 equals the host twin `extend(extend(0, sha256(A)), sha256(B))`.
  - The probe ran on the `measure` firmware path through
    `run.boot_uboot`, with QMP reporting `guest-shutdown`.
- **Microkit image.** The current system plus two prefill MRs of
  `0x480_000` builds. The test mapping is `r` into `inner`, outside its
  existing window.
  - The loader image grows from 8.2 MiB to 17.6 MiB, inside U-Boot's
    256 MiB `MAX_IMAGE`. U-Boot's PCR 8 hash of the image grows by the
    same 9 MiB, about 0.15 s on the figure above.
  - Two facts for C11 and C6: a prefill MR mapped without `setvar_vaddr`
    needs no symbol in the ELF, and a PD's window must avoid its
    existing maps. `inner`'s ring data already sits at `0x10_000_000`.
- **Deviation:** the plan's P3 pass condition says "boots". The enlarged
  image is not booted end to end in slice 0, because that needs the C4
  descriptor v3 and a sealed package.
  - The first C4 integration boot (slice 2) carries that check. The
    PCR 9 path and the image build, the parts slice 0 can isolate, both
    passed.
  - Anti-Deferral: the remaining risk is the Microkit loader's copy of
    9 MiB more, a memcpy that U-Boot's 0.15 s already bounds from above.
    Worst case it adds well under a second to `BOOT_TIMEOUT_S`'s budget.

### P4 — TPM command support (narrowed)

- P1 exercised every command P4 names against swtpm through tpm2-tools,
  with password sessions where needed: `NV_ReadPublic`, `NV_Read`,
  `NV_Increment`, `ReadClock` and `GetCapability`
  (`TPM_PT_PERMANENT` / `STARTUP_CLEAR`). The TPM side holds.
- **Deviation:** the `tpm2-wire` builders and parsers do not exist yet.
  Their round trip against swtpm becomes part of C3's interop tests in
  `crates/tpm2/tests` (slice 2) rather than a slice-0 probe.
  - Anti-Deferral: writing them now would be C3's implementation. The
    probe's question, whether swtpm supports these commands in this form,
    is answered.

### P5 — `make test` wall clock (passed)

- On z1mn at 7cf3f20, which has the same code as main 06b280b, a cold
  `make test` (ct, firmware, all 94 integration cases) took **2517 s**
  (42 min), rc 0.
- **Projection.** M8 adds about 40 boots: C13's 12 rows (some two-boot),
  C6, C8, the C10 capture, and the bundle-sourced re-runs of existing
  groups. At about 25 s a boot that is +17 min, so about 1 h.
- That is under the 3 h pass line, inside `CASE_TIMEOUT_S` (4 h) for
  `integration-count`.

## Slice 1

### D-1 — the Kani re-proof starts at slice 1, not slice 3

- The plan says the PD lockfile changes once, in slice 3, and that the
  ~13 h re-proof begins there. But `tools/kani-gate.sh:57` keys every
  cached proof on the root `Cargo.toml` and `Cargo.lock`. Adding
  `policy-wire` to the workspace in slice 1 already changes both, and so
  do `release-seq`, `audit-core`, `auditkey-core` and the new PDs.
- Decision:
  - During slices 1–5, new or changed crates are proved directly with
    `cargo kani -p <crate>`, one job at a time and capped at 40g.
  - `make kani` (the cached gate) runs once, after the last workspace
    change in slice 5, split across gx10 (head) and z1mn (tail).
  - Nothing is lost: until that run the existing crates' proofs are
    unchanged sources under a new key.

### D-2 — `parse` needs the `verifier` feature (C1, I1.2)

- The first `policy-wire` made `parse` public. A consumer PD could then
  build a `Bundle` without the `policy` PD's token, which C1 rules out.
- `parse` is now compiled only with the feature `verifier` (or under test
  or Kani), and `open` reaches the same parser through a private
  function. check-pins P27 lets only `crates/pds/policy` and
  `tools/policy` enable the feature.
- A `compile_fail` doctest shows a consumer cannot call `parse`, and a
  `no_run` doctest shows `open` compiles. Red-proof: built with
  `--features verifier`, the compile-fail doctest fails ("compiled
  successfully").

### D-3 — I1.1 is proved by step lemmas, not over the whole slot

- One harness over a whole slot at a small key length timed out after
  30 min with no verdict: a symbolic buffer of about 3.5 KiB, most of it
  the fixed signatures, under nested loops.
- The loop bodies are now `walk_peer` and `walk_group`, extracted without
  any behaviour change (65 unit tests unchanged).
  - Each step is proved on a small symbolic buffer from an arbitrary
    start: `Ok ⇒ start < next ≤ len`, with a `kani::cover!` that `Ok` is
    reachable.
  - The two loops (≤ `MAX_PEERS`, ≤ `MAX_GROUPS` iterations) compose the
    steps by induction.
  - The crate's lints (`indexing_slicing`, `unwrap_used`,
    `arithmetic_side_effects`, `panic` denied) rule out a panic.
  - M6 used the same shape for `http-wire` (RM6-11).
- All seven `policy-wire` harnesses verify: the two steps, three
  `select` harnesses plus their reachability harness, and the init
  machine. Every `cover!` is satisfied.
- **Red-proofs**, run on a scratch copy outside the tree:
  - `walk_peer` returning `pos + 1` makes the peer-step harness fail.
  - An ADVANCE check mutated to accept any value first stayed green.
    I5.1 asserted the machine's own `current + 1` rather than the
    TPM's reply. The property now asserts the reply itself, and the same
    mutant now fails.

### D-4 — the genesis-roster pin is compiled in, not a flag (C2, D11)

- The delegated `tools/policy` had `--pinned <file>`, which let whoever
  runs the tool replace the genesis-roster pin. That is the single-insider
  re-genesis S15 closed.
- The pin is now compiled in: `tools/policy/genesis-roster.sha256`, which
  ships all zeros, so every command fails closed until a fleet's genesis
  ceremony (C12). A build-time `KOZANE_POLICY_GENESIS_PIN` replaces it,
  and the tool tests use that. They now also assert that the unpinned
  build refuses a genesis roster.
- Four fixtures were red for the wrong reason, and now assert their own
  refusal:
  - **Restore bound to another fleet.** Both fixture contexts shared one
    fleet ID, and the fixture passed only because their rosters differed.
    It now uses a second fleet, and the restore check compares `fleet_id`
    before the head digest so the fleet binding is the one observed.
  - **Wrong approval domain (bundle and restore).** Both are refused by
    their record kind (disjoint key sets). Signature-domain separation is
    covered by `tools/policy`'s unit tests.
  - **"Second body for a signed version".** At `sign` it is the
    `version == head + 1` refusal; with that rule the separate check
    cannot be reached through `sign`.
- check-pins P28 matches the bypass flags only as quoted literals, and
  skips comment lines, because the tool's docs name them.

## Slice 2

### D-5 — five descriptor ranges now, the sixth with `auditkey` (C4)

- C4's sixth range is the audit envelope, and the `auditkey` PD that owns
  it lands in slice 5. Slice 2 builds descriptor v3 with five ranges (the
  three envelopes and the two slots), and slice 5 adds the sixth with its
  pair cases.
- Anti-Deferral: a sixth range sealed now would be a placeholder with no
  owner and no test that can fail. The cost is one more descriptor
  revision inside M8, and v3 is not released before M8 ends.

### D-6 — the cap waits for `policy` only once `policy` exists (C3)

- With the cap waiting on `policy_finished`, today's image, which has no
  `policy` PD, would never cap, and every key PD would time out.
- `layout::tpm::POLICY_PRESENT` gates that term. Slice 3 sets it to true
  in the same commit that adds the PD, and a laws/layout test ties the
  constant to the `.system` file.
- Kani I3.1 is proved for both values.

### D-7 — provisioning's TPM Clear ends the "same SRK twice" check

- `run.py`'s `read_srk` provisions a copy of the state a second time and
  requires the same SRK. With TPM2_Clear first (D5), the storage seed is
  fresh each time, so the two SRKs differ by design.
- That check becomes: the second provisioning's SRK differs from the
  first. That is S18's "the SRK Name changed", now asserted on every
  provisioning.

### D-8 — C3's forbidden pattern is scoped (check-pins P29)

- The plan's literal pattern `NV_?(UNDEFINE|WRITE|DEFINE)|Clear\b` over
  `crates/` would match three things:
  - the refused-set constants the gate needs (I3.2 lists them);
  - the attribute names `NV_WRITTEN`/`NV_WRITELOCKED`;
  - a comment ("Clear that stack").
- P29 matches the command-code constants `CC_NV_{UNDEFINE_SPACE[_SPECIAL],
  WRITE[_LOCK], DEFINE_SPACE}`, `CC_CLEAR` and `CC_HIERARCHY_CHANGE_AUTH`.
  They are allowed only where they are defined, in the gate's refused set,
  in that crate's tests and proofs, and in `crates/tpm2/tests` (the swtpm
  interop tests drive swtpm directly).
- It remains a tripwire. The control is the gate's per-client allowlist,
  proved by Kani I3.2.

### D-9 — slot ranges are exactly `BUNDLE_MAX`

- The delegated boot.cmd and measure.py accepted any slot length up to
  `BUNDLE_MAX`. U-Boot hashes the whole load slot for PCR 9, so a shorter
  range would copy fewer bytes than it measures.
- Both now require `len == BUNDLE_MAX`, as C1's "slot media is always
  exactly `BUNDLE_MAX`" does. test_measure has the shorter and longer
  denies, and its boot.cmd line check expects `-ne` for slots.

### D-10 — the slot MRs and the `bundle_slot` laws kind land in slice 2

- `tools/package` can only emit descriptor v3 when the system file has
  the slot MRs. The laws refused them (L2: prefill only on secrets MRs;
  L4: an MR not in the policy).
- So the slot-MR part of C11 moved up from slice 3:
  - the MR kind `bundle_slot` (prefill allowed, never mapped `w`/`x`,
    readers listed);
  - both slots declared with `readers = []` and mapped into no PD.
- Slice 3 adds `policy` and the barrier PDs as readers.

### Note — a delegated agent used `git stash` briefly

- During slice 2, the Rust batch ran `git stash` / `git stash pop` once
  while the provisioning batch was editing `tools/` and `tests/`. The
  stash list is empty, and every file both batches reported is present.
- The gates for this slice re-run every suite on the final tree.

## Slice 3

### D-11 — `policy`'s audit source is a write-once log page, not a ring

- An SPSC audit ring has its consumer (`audit`, tainted) write the read
  index into the shared page. That would carry taint into `policy`, from
  `policy` into `tpm` through the policy PPC, and from `tpm` into the key
  PDs, which L1 refuses.
- `audit_event::log` is a count word plus eight two-word records. `policy`
  maps it `rw` and `audit` maps it `r`, keeping its own read position.
  `policy` writes at most four lines a boot.
- The laws carry nothing into a `policy` PD from a mapper that cannot
  write the page. That is the supervisor record page's rule, extended.
  The MR keeps the name `audit_policy` (kind `plain`, `{policy = rw,
  audit = r}`).

### D-12 — `policy`'s callers are checked by role until batch B names them

- C11 says `policy`'s PPC callers are exactly the barrier set. Batch A has
  no callers yet, and its rule admits callers of role `untrusted_input`
  or `data`, which would also let `tls` in.
- Batch B replaces the role check with the named set `hs, pq, ingress,
  data, inner`, with a `tls` deny fixture.
- Batch A also adds `["data", "policy"]` to the priority order, because
  `data` is in the barrier set.

### Risk — `policy`'s verification stack and the P2 TCG timing

- With the all-zero keys of today's deployments, the verifier is compiled
  out, and `policy` refuses at STATE first.
- A scratch build with keys links no_std with 244 KiB of text and 4.7 MiB
  of `bss`. The `bss` is a static `DOMAIN ‖ body` buffer, needed because
  the libcrux verifiers take one contiguous message and the slot is
  read-only.
- ML-DSA-65's stack depth inside the PD's 256 KiB stack, and P2's TCG
  timing, are first observed in batch B, whose harness boots signed
  bundles. If either fails, it is fixed there, not carried forward.

### D-13 — `open` does not re-hash the rp keys

- `policy_wire::open` ran the gateway-rp-key check too. That check
  BLAKE2s-hashes every peer's 512 KiB key, so up to 4 MiB in each of the
  five barrier PDs, on every boot, under TCG.
- `policy` has already run the check on the same bytes, and no PD can
  write them (C11). `open` now skips it (`parse_unchecked(.., None)`).
  `parse`, the verifier side, keeps it.
- `open_does_not_rehash_the_rp_keys` pins the narrowing. policy-client
  loses its digest helper and its secret-blob dependency.

### D-14 — the key blob is v4, not "v3"

- C7 names the peerless key blob "v3", but v3 is already M6 slice 2's
  TLS-scalar format in `secret-blob`. The peerless key blob is version 4:
  `magic | 4 | reserved 0 | gateway_private@16 | boot_seed@48 |
  checksum@80`, `USED_LEN` 112.
- Versions 1–3 are refused. The offsets the harness reads are unchanged.

### D-15 — test peers come from `mksecrets --clients`

- `mksecrets --peers` is gone; the blob and config name no peer.
- mksecrets is still the only McEliece keygen, so `--clients N` writes the
  client configs and keys, plus a `clients.toml` in `tools/policy`'s
  peers.toml schema, for the harness to render into a bundle.

### Counts that fell (C7), and where the tests went

- UNIT-CONFIG 63 → 44: peer validation moved to `policy-wire`, whose
  tests cover it.
- UNIT-KEY-CORE 22 → 21: the PeerMismatch tests went, and a test that v2
  blobs are refused came in.
- UNIT-SECRET-BLOB 20 → 18: the per-peer tests went.
- CONFIG-BUILD-FIXTURES 11 → 8: the peer cases went, and a
  `[[peers]]`-refused case and a neighbour case came in.
- UNIT-POLICY-CLIENT 11 → 10: its digest helper and test went with D-13.
- UNIT-MKSECRETS rose by one (`--clients`) instead of falling as C7
  predicted.

### Gap — `rosenpass-core`'s slice API has unit tests only

- `Responder` now takes a slice of at most `MAX_PEERS` keys. The crate is
  not in `kani_crates` and has no harnesses: a symbolic Responder would
  run over BLAKE2, which is beyond a bounded harness.
- Three unit tests cover the active-peer bound, an empty slice and a
  slice over `MAX_PEERS`.

### P2 and the stack risk, observed (slice 3, batch B2)

- **Boot time.** With a real signed bundle, `policy` accepts 5.4–7.6 s
  after `audit: ready`, verifying both signatures under TCG on its own
  2 ms / 10 ms budget. QEMU start to `pq: ready` went from 2.6 s
  (batch A) to 8.0 s; the worst seen is 10.8 s, against
  `BOOT_TIMEOUT_S` 60.
  - That keeps P2's ≥ 30 % headroom. P2's TCG half is closed with these
    numbers.
- **Stack.** No `supervisor: fault pd=policy` line appeared in the full
  run, so the 0x40_000 stack held.
  - `policy` reports no stack high-water mark, so there is no depth
    figure, only "no fault". C10 (slice 5) adds the high-water record to
    `policy`'s log page.
- **A harness defect the barrier exposed.** `wait_arp_ready`'s 1 s probes
  queue in the driver ring while `ingress` waits on the barrier, and are
  all answered once it starts. The surplus replies made the raw-frames
  flood take a stale reply as its FIFO barrier, so batches overlapped and
  overran the 64-buffer link (`eth_out RxNoBuffer`, every time).
  `wait_arp_ready` now drains them. The device is unchanged.
- **`make run`.** `run_interactive` still boots zero slots, so every
  barrier PD halts with 16. It gets the fixtures in slice 6 (C13).

## Slice 4

### D-16 — the PSK residue check's false positive, and deterministic peer ids

- **Symptom.** From slice 3 on, the wireguard group's residue check failed
  about one run in three: "PskInstall message still in guest RAM". It
  failed at the same address within a build, and stayed for more than
  60 s once present.
  - Slice 2 (be80a94) was clean in 5/5 runs. HEAD 5fbc648 failed 1/3
    and 2/4, so slice 4 did not introduce it.
- **Cause.** The needle is the encoded message: `u16 peer (LE) ‖ OSK`.
  Since slice 3, peer ids follow the bundle's order of random per-run
  WireGuard keys, so client 1 is peer 0 about a third of the time.
  - The needle `0000 ‖ OSK` then matches `hs`'s live PSK table entry:
    tag `1` (`Live`), `installed_at` (e.g. `30da193306000000`, about
    26.6 s, whose top two bytes are `0000`), then the OSK.
  - Observed directly: the OSK occurs 5 times, as often as the control,
    and the match is that entry.
  - So there is no leak. The live OSK belongs there until REJECT_AFTER_TIME.
- **Fix.**
  - `mksecrets --clients` numbers its clients in bundle order (ascending
    raw `wg_pub`), so client i is always peer i, and the needle begins
    `0100` as it did before M8.
  - Test: `clients_are_numbered_in_bundle_order`. Its red-proof is only
    probabilistic (about 1/2 with two random clients), because the keys
    are random.
  - The check itself is unchanged.
- **Verified.** With the fix, the wireguard group passed 5/5 runs on z1mn
  (20 cases each).

### D-17 — I8.3 is proved one step at a time

- **Why.** The delegated I8.3 harness ran a sequence of three operations
  over a symbolic table. It ran CBMC out of memory at the 40 GB cap three
  times, at about 1.6 M steps: with full-width fields; with fields cut to
  two values each; and again with the `cfg(kani)` table at one entry a
  peer and the clock limited to its boundaries.
- **The restatement.** I8.3 is stated by induction, each step proved from
  an arbitrary table state:
  - (a) an outbound `Allow` names a live entry of that peer's share for
    the reversed tuple;
  - (b) an outbound packet makes no entry alive;
  - (c) an inbound `Deny` changes nothing.

  Only an inbound `Allow` makes an entry alive, and I8.1 says that needs a
  matching rule, so over any sequence an outbound `Allow` answers a flow
  its peer opened under its rules.
- **Bounds.** Two values per field, the clock and timestamps free.
  `cfg(kani)` `MAX_FLOWS = MAX_PEERS`, one entry a peer, so an own-share
  eviction still happens.
- **Results.** All six inner-core harnesses verify: (a) 13 s, (b) 29 s,
  (c) 18 min, I8.1 35 min, I8.2 18 min, I8.4 20 min. Every `cover!` is
  satisfied.
- **Red-proof.** On a scratch copy, an `authorize_outbound` naming the
  wrong peer (`i / QUOTA ^ 1`) makes (a) fail.

## Slice 5

### D-18 — `auditkey`'s choices (batch A)

- **ReadClock.** `tpm2::boot::unseal` takes an `Option<&mut Clock>` and
  reads the clock after a successful flow and before Done. The read stays
  inside the client's own flow, so it is never Busy, and P22's pin on
  `unseal` keeps holding. A failed read fails the unseal.
- **Gate.** `CLIENTS = 4`. `CLIENT_ONLY = [(ReadClock, auditkey)]`: once,
  no parameters, refused after Done, off both `ALLOWED` and `REFUSED`.
  I3.2 gains `read_clock_is_reachable_only_from_auditkey`.
- **Timeouts.** `BUSY_TIMEOUT_NS` 360 s. `POLICY_MAX_NS` 60 s, about 8×
  the measured 7.6 s, the margin `FLOW_MAX` keeps. So
  `CAP_BARRIER_TIMEOUT_NS = 360 + 60 + 3 × 30 = 510 s`.
- **Seq rule.**
  - A boot starts as if seq 0 had been signed, and the state advances
    only after a signature exists.
  - The one exemption is taken by the first request that is not yet due
    but is above the last signed seq. There is no "ready" flag on the
    wire.
  - `audit-core` (batch B) must therefore schedule the next checkpoint
    at least `CHECKPOINT_EVERY` (64) after the last *signed* seq.
- **Placement.**
  - Priority 120: above `audit` and every tainted PD, below `policy`,
    `tpm` and `rng`.
  - The audit envelope loads at `0x6F000000`, the free MiB below slot
    A. Descriptor order: four envelopes, then the slots. The descriptor
    is 128 bytes with 15 pair lines.
  - Error codes start at 0x80, so they never collide with key's or
    tlskey's.

### D-19 — the audit export's choices (batch B)

- **The ready checkpoint.** It fires once all nine sources (eight rings
  plus `policy`) report Ready and `auditkey` has notified. Every
  checkpoint, signed or not, moves the next due point to its own seq + 64,
  which satisfies D-18 after a refusal or a lost reply too.
  `auditkey_never_refuses_the_schedule` drives the real `SeqRule` over a
  grid of notify and ready points.
- **No ready marker on the wire.** The line format has no marker for
  "the ready checkpoint". So `--from-provisioning` requires the first
  boot to start at seq 0 (the chain from `h0`) and its first checkpoint
  line to be signed. Deny fixtures cover a mid-boot start and an
  unsigned-first boot.
- **The strip pattern** is ` seq=\d+(?=\r*$)`, not the plan's `\r?`,
  because QEMU's pty ends lines with `\r\r\n`.
- **run.py.** `Console.text` is the stripped view (append-only, so
  offsets hold) and `Console.raw` the raw text. Every existing regex
  works unchanged.
- **Fail vs note.** `audit-verify` fails on holes, a chain mismatch, a bad
  signature, another boot's checkpoint, a non-increasing checkpoint seq,
  a boot with no signed checkpoint, and a continuity gap. `lost > 0`,
  unsigned checkpoints and the unverified tail are notes, as C10's
  "reports" reads.
- **Unterminated last line.** `audit-verify` skips it: a capture killed
  mid-line would otherwise read a half-printed ` seq=12` as `seq=1` and
  report a false hole. It has its own fixture.
- **The provisioning record** gains `reset_at_provision`, and `provision
  nv` refuses a record whose value is not this TPM's resetCount.
  `audit-verify` reads the record's fields but leaves its operator
  signatures to `provision nv`.
- **`policy`'s stack** is now observable: 68,832 B of its 262,144 B.
  This closes slice 3's stack risk.
- **No `Checkpoint` event in `audit-event`.** `audit` prints checkpoints
  itself, so the event code C10 listed is not needed.
- **check-pins P31**, added on review: `audit`'s single `.pp_call(` is in
  `fn sign`, `CH_AUDITKEY` is named only there, and `ready_input` decodes
  the notification. That is T47's PD-glue pin.

## Slice 6

### D-20 — the supervisor drains for one second before it resets

- **Symptom.** With slice 5, the supervisor group failed in 2 of 4 runs.
  Inject A's fault reset QEMU while `audit` was in the middle of the ready
  checkpoint's line, so the fault record never printed.
- **Cause.**
  - The supervisor writes the record, notifies `audit` and resets at
    once. Before M8 this worked only because `audit` (priority 50, above
    the supervisor's 40) usually preempted and printed first.
  - Since slice 5, `audit` can be out of budget (500 µs per 10 ms) while
    it prints a long checkpoint line or waits on `auditkey`'s signature.
    The supervisor then runs on and resets.
  - A fault that leaves no line is lost evidence.
- **Fix.**
  - `supervisor_core::FAULT_DRAIN_NS` = 1 s. `reset::system_reset` spins
    on the generic timer for that long before the SMC.
  - Spinning at the lower priority never blocks `audit`. One second is
    about 50 ms of `audit`'s CPU, far more than a line plus a signature.
  - The counter read sits in the reset module, where the supervisor
    allowlist permits `unsafe`. Its S1–S8 still pass.
  - Rejected: an acknowledgement page that `audit` writes and the
    supervisor reads. It would carry `audit`'s taint into the supervisor,
    which is in every PD's TCB.
- **Cost.** One second more per fault reset (RM7-6's A11 amplification
  is unchanged in kind).
- **Verified.** The supervisor group passed 5/5 runs on gx10. The fix
  has no deterministic red-proof: the race it closes is timing.

### D-21 — C6's injection needle is hs becoming ready

- The plan's needle for "`hs` ignores Unavailable" is a WireGuard
  response on the wire. It cannot fire: `ingress`, another barrier PD,
  still halts and drops the initiation, and `pq` gives no PSK.
- The failure-only evidence is `hs` printing ready instead of halting
  with reason 16 in the `rolled-back` case. The injection builds its own
  token (`Verified::from_reply` of zeros) and calls `open`.

### Note — one harness timeout in the wireguard group

- One full `make test` after D-20 failed `wireguard` with a bare
  `TimeoutError`. Its `FAIL` line was printed before the rotation case's
  own `PASS`, so it came from a helper thread, not the case under test.
- It did not recur: the group passed in the C13 agent's two full runs,
  in three reruns, and in the next full `make test` (133 cases, rc 0).
- It is recorded as a harness flake of about 1 in 6. If it recurs in the
  final `make check`, it gets its own investigation rather than a retry.

### D-22 — what writing C12 against the code found

Writing the runbook and the audit map against the code found these
differences from the plan:

- **No per-peer attribution (fixed).** `HandshakeOk` and
  `SessionInstalled` were counts without a peer, and no line recorded a
  peer's outer endpoint, so the audit stream could not say who connected
  or from where, which is the owner's third add-on. Per-peer handshake
  and endpoint events are added in the next commit; the audit map cites
  them.
- **The C2 fleet digest vs the package (fixed).** `tools/package`
  recorded no NodeConfig digest, so `verify --fleet` could not compare
  one. Added in the same commit.
- **The genesis-pin tie in check-pins (superseded by D-4).** D11 said
  check-pins ties the genesis-roster pin. D-4 made the pin a
  compiled-in build input, and its shipped all-zero value fails closed.
  No separate rule is needed.
- **`approve` checks the chain without the bundle signatures.** An
  approver holds no policy public key, so `approve` runs
  `verify_chain_unsigned`. The runbook has approvers run `policy verify
  --ledger --keys-pub` first.
- **Four planned injections are covered by other tests.** The plan named
  check-selftest injections for `authorize` defaulting to Allow,
  `auditkey`'s seq rule, the ready gate, and `sign` accepting one
  approval. They are covered instead by:
  - Kani I8.1/I8.4 and slice 4's scratch-copy mutants;
  - `auditkey-core`'s Kani and unit tests;
  - `audit-core`'s red-proved unit test plus check-pins P31;
  - `tools/policy`'s fixtures.

  Each of these has failed on its own mutant. A check-selftest case per
  item would re-run the same evidence through a slower path.

## Phase 2 self-check (Step 2-5)

### D-23 — what the recurring-checklist self-check found

Three reviewers checked `main...HEAD` against R1–R57, RS and RT. These
findings were fixed:

- **Key copies left in memory (R39, Major).** `tools/policy` decoded its
  signing keys into plain `Vec`s and `String`s, and `approver_keygen`
  returned a bare array, although its manifest claims L12 as
  tools/release does. It now follows tools/release: `read_hex_file` returns
  `Zeroizing`, the key hex is wiped once written, and approver keys are
  `ApproverSigningKey` from generation on. tools/release has no check-pins
  rule for this either, so none was added.
- **A `Verified` token from any bytes (R49, Major).** `Verified::from_reply`
  is public, and `policy_client::open` maps the slot itself, so a barrier
  PD could have made its own token without tripping P27. P27 now also
  allows `from_reply` under crates/ only in policy-wire and policy-client,
  and the rustdoc calls `Verified` a witness, not a capability. A Cargo
  feature gate was considered, but it would only be the same kind of
  tripwire with more churn (D-21's injection, the doctest).
- **The slot readers and the policy callers were separate lists (R42,
  Minor).** Laws L4 now requires every bundle_slot reader other than the
  `policy` pd to be one of its named callers.
- **Refused `sign` and `approve` were checked only by their reason (RT8,
  Major).** The fixtures now also check that no slot, ledger entry,
  approval record or head change was written. Red-proved on a mutant that
  checks distinct approvers only after appending.
- **The runbook's absence checks ran on output that never contains those
  lines (R12/R29, Major).** `audit-verify` printed only the C9 lines, so
  "no `policy: rejected`" and "no `PeerHandshake` for a revoked peer"
  always held. `--events` prints every line with its verified flag, and
  the runbook and the audit map now use it.

Left open:

- **`FAULT_DRAIN_NS` (D-20) was not set from a measurement (R53, Minor).**
  The supervisor case now prints the time from the faulting frame to
  audit's record (`supervisor: the record was printed <s> s after the
  fault`). That is an upper bound on what the drain must cover. The final
  `make check` and the split self-test report it. The worst case is to be
  recorded here, and the constant raised if it exceeds 0.2 s (a margin
  under 5×).
