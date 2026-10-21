# Plan: secureos-m4-verus-mceliece (rev 5)

M4 closes two scope items:

- **SC4 (architecture plan):** re-prove with Verus, without bounds, the
  parsers and pure state machines that Kani bounds.
- **SC23 (M3 plan):** replace classic-mceliece-rust 2.0.2 ("cmr"). The C8
  spike found it leaking a secret-dependent load in Berlekamp-Massey (F1).
  - The replacement is an in-tree no_std Rust McEliece.
  - It closes on mechanical constant-time gates bound to the shipped ELFs.

Base: `feature/m3b-cookie-gate` at `22432af`. Branch:
`feature/m4-verus-mceliece`. Review IDs cite the review artifact.

## Owner decisions (2026-10-21)

| Decision | Choice |
|---|---|
| McEliece source | A pure Rust port, not FFI. The no_std pure-Rust law stands |
| SC23 close condition | Mechanical gates C8–C10, each red-proved. No third-party audit (residual R-M1) |
| SC24 Rosenpass V03 | Deferred until an upstream release contains V03 |
| SC20 release kernel | Moves to M5, with SC11 |

**Round 1 refinement of row 1 [F1].** libmceliece implements round 4, with
156-byte ciphertexts. The system, Rosenpass V02 and every peer use round 3:
188-byte ciphertexts, with confirmation `C1 = H(2,e)` and key
`K = H(1,e,C0‖C1)`. The port therefore splits as follows:

- **From libmceliece 20260622 `vec`:** the decoding core, meaning bitsliced
  field arithmetic, additive FFT, bitsliced BM, Beneš, and the cryptoint
  mask discipline.
- **Round 3:** the KEM framing and key generation.
- **Oracle:** the round-3 C code the peers run, liboqs 0.8 through
  `oqs-sys`, as `tools/rp-vectors` already builds it.

This keeps the decision's intent. The scope change is reported to the owner
with the plan.

## Project context

- **Type:** mixed. no_std Rust PDs on seL4 16 / Microkit 2.3.1 MCS, aarch64;
  host tools in Rust and Python.
- **Test infrastructure:** unit, integration (QEMU TCG), Kani, bolero, and
  the check-selftest mutation layer, all run by one `make check`. No CI.
- **Verification environment constraints:**
  - **E1:** the host and the dev container are aarch64 Linux. Verus ships
    no aarch64-linux binary, so it is built from source (see V0).
  - **E2:** QEMU TCG only; no hardware (M7).
  - **E3:** the container is capped at 40 GB. cbmc and Z3 never run
    concurrently.
  - **E4:** no CI.
- Every contract's verification is `verifiable-local`.

## Objective

- **Verus:**
  - Unbounded functional specs, totality and round trips for the
    `wg-wire`, `msgs`, `rosenpass-wire` and `wire` codecs.
  - Ring's pure index and ownership logic for every admissible ring size.
  - Kani stays: it checks the compiled code, and Verus checks the logic
    without bounds.
- **McEliece:**
  - `classic-mceliece-rust` leaves the root `Cargo.lock`.
  - On the inputs C9 runs, the replacement's encaps and decaps have no
    secret-dependent branch or address.
  - C10 proves the shipped PD code identical to the code C9 ran.
  - SC23 closes, and L2's constant-time clause for `pqkey` is amended to
    name this basis.

## Requirements

- **No behaviour change on the wire:** round 3, 188-byte ciphertexts. The
  integration suite, including 0.2.3 and master interop, passes unchanged.
- **Unchanged blob:** `secret_blob::pq` version 1.
  - Its secret key is the round-3 spec layout δ‖c‖g‖α‖s, 13608 bytes,
    with δ‖c zero. That is cmr's layout; `pq.rs` documents the mapping to
    liboqs's 13568 bytes.
  - `v02.txt`, `spkm.bin` and `spkt.bin` are not regenerated.
- **Verus's effect on the shipped PDs is measured, not assumed.** Each V
  slice records every PD ELF's `.text` hash before and after. Any change is
  reviewed [F4, T12, S-10].
- **Gates:** every gate is fail-closed or a declared tripwire (R49). Every
  gate is counted in the manifest and has check-selftest cases with
  failure-only needles.

## Technical approach

- **Verus toolchain (C1):** a `verus` Docker stage builds Verus from source
  at commit `426d8b01e7ffb910a36c15e1f870ff985bb61eef`. That is tag
  `release/0.2026.10.04.426d8b0`, the one Vest 0.2.2 pins. The build
  follows V0.
  - **Source fetch:** the GitHub archive tarball of that commit, checked
    by sha256 (the value is recorded in V0b), as the rosenpass-oracle stage
    does. Not a `git clone`, which check-pins P1 does not see
    [R2: F-N11].
  - **Rust:** Verus's own `rust-toolchain.toml` (1.98.1, `rustc-dev`,
    `llvm-tools`). rustup verifies it against the channel manifest; it is
    not sha256-pinned [S-13].
  - **Z3:** 4.16.0 aarch64, sha256-pinned. Verus's download script is not
    used.
  - **Isolation:** the stage runs `cargo fetch --locked`, then builds
    offline. It sees neither `/work` nor any secret.
- **Annotation placement:**
  - Annotations go in place, inside `verus!{}`.
  - The verified crates gain `vstd` as a normal dependency, pinned
    exactly from crates.io: `vstd = "=0.0.0-2026-10-04-0306"`, the
    release that pairs with the commit. V0b confirms its source commit
    [R2: F-N9]. V0 showed that a path dependency surfaces vstd's
    warnings.
  - Where vstd has no spec for a std API the code uses [F2], the code is
    refactored to a form vstd specifies. Otherwise it gets a trusted spec,
    which goes on the C1 allowlist.
  - A refactor may change a PD's `.text`. The before/after hash record
    makes every change visible and reviewed. The unit tests, Kani and the
    integration suite cover behaviour.
- **Vest:** not used in M4 (SC29).
- **McEliece (C7):**
  - The core comes from libmceliece `vec` and the framing is round 3.
  - Every 1-bit or mask operation goes through `barrier`, an `asm!`
    identity in one module.
  - All secret-derived integer arithmetic is `wrapping_*`, so
    `overflow-checks` emits no compare on a secret [S-4].
  - Every secret-touching step is a non-generic `#[inline(never)]`
    function. The RNG lives only in a thin generic shim outside C10's
    identity set [R2: S-N1, F-N2, T-N3].

## V0 probe (Phase 1, 2026-10-21)

The probe ran in a throwaway image (scratchpad `verus-probe/Dockerfile`),
not in the dev container.

- **Setup:** Debian trixie, glibc 2.41. The pinned commit built with
  `vargo build --release` on Rust 1.98.1, on aarch64. Z3 was
  `z3-4.16.0-arm64-glibc-2.38.zip`, sha256
  `87fcd963d3eecb0f12cf1c3ef0ad74e84a3a7bd3caed5d94445645ef94ae6274`.
  BUILD.md at that commit asks for Z3 4.16.0 [F19].
- **Allow side:** `cargo verus verify` on a no_std probe crate with `vstd`
  (`default-features = false`) reported
  `verification results:: 1 verified, 0 errors`.
- **Deny side:** an injected overflow reported `possible arithmetic
  underflow/overflow` and `0 verified, 1 errors`, with a non-zero exit.
- **Summary lines:** Verus prints one per crate, and vstd's comes first
  (`1876 verified`). C1 must read the line that follows the verified
  crate's `Checking <crate>` line.
- **Erased build:** the annotated crate builds with `nightly-2026-08-21`
  for `aarch64-unknown-none --release`.
- **New lockfile entries:** vstd's normal closure is `verus_builtin` and
  the proc-macro `verus_builtin_macros`, which pulls in `syn`, `quote`,
  `proc-macro2`, `synstructure`, `convert_case`, `verus_syn` and
  `verus_prettyplease`. These enter `Cargo.lock` and must be pre-fetched
  for `--offline`.

**V0b, the first Phase 2 slice [F3]** (also records the vstd version and
the Verus tarball sha256): add `vstd` and one annotated
function to the real `wg-wire`, then run in order:

1. `make pds lint-pds` (build-std, `clippy -D warnings`);
2. one wg-wire Kani harness, alone;
3. one bolero target;
4. `make unit`;
5. `cargo verus verify`.

Record the vstd↔Verus pairing. If a step fails in a way that cannot be
fixed locally, stop and ask the owner.

## Contracts

### C1 — the Verus gate

- **Signature:** `tools/verus-gate.sh -p <crate>` exits 0 only when all of
  these hold:
  - Verus exits 0.
  - The crate's own summary line (V0) reports `n > 0` verified and
    `0 errors`.
  - The trusted constructs in the crate equal `policy/verus-trusted.toml`
    exactly.
  - Every function that `policy/verus-required.toml` lists for the crate
    lies inside `verus!{}` and carries an `ensures`.
- **Output:**
  - `VERUS-<CRATE> <n>`, the count of verified functions, in the manifest.
  - `VERUS-ENSURES-<CRATE> <n>`, the count of `ensures` conjuncts inside
    `verus!` (top-level comma-separated clauses), in the manifest [T6b,
    R2: T-N10].
  - Residual: the count measures how many clauses exist, not how strong
    they are. That is covered by the required list and the named
    mutations.
  - `VERUS-TRUSTED-CHECKED <crates>`, which is always > 0. No zero-valued
    key exists [T4, F9].
- **Trusted constructs [S-9, F2]:** `external_body`, `external`,
  `external_fn_specification`, `external_type_specification`,
  `assume_specification`, `exec_allows_no_decreases_clause`, `assume(` and
  `admit(`, in both the `#[verifier::x]` and the `#[verifier(x)]` spelling.
  Each allowlist entry names its deviation-log line.
  - The scanner is `tools/verus_trusted.py`, shared with check-pins P12.
    It matches the `verifier::x` / `verifier(x)` tokens anywhere in an
    attribute's token stream, `cfg_attr(verus_keep_ghost, …)` included
    [R2: S-N7, T-N11].
- **Locking and cache [T8, F18]:**
  - The gate takes `build/kani.lock`, the same lock as kani-gate.
  - It caches under `build/verus-cache`.
  - The cache key covers the crate's sources and path dependencies,
    Cargo.lock (the vstd pin), `verus --version`, `z3 --version`, both
    policy files, the script and its arguments.
  - Cargo runs with `--locked`.
- **Make:** `make verus` runs every crate in `verus_crates` serially, and
  `make check` runs it after `kani`.
- **Erasure check:** `tools/verus-erasure` fails if any PD ELF contains a
  symbol whose demangled path starts with `vstd::` or `verus_builtin`
  [S-10]. It runs inside `ct-shape` (C10), after `pds`.
  - **Positive control:** the same demangler must first find each ELF's
    known entry symbol, or the check fails [R2: T-N6].
  - **Selftest `verus-erasure`:** a scratch copy of a PD crate injects a
    call to a vstd exec function, reachable from the PD's entry path behind
    `black_box`, so that the linker keeps it. The needle names the symbol
    [R3: T-P3].
  - **Constraint:** verified crates call no vstd exec function. An inlined
    vstd exec helper leaves no symbol and escapes the check; that residual
    is declared in C1's control class.
- **Image:** the `verus` stage described under Technical approach.
  `/opt/verus` holds `verus`, `cargo-verus` and their toolchain.
- **Invariants:**
  - **I1:** the decision reads the exit status and the crate's own summary
    line. A missing line, any error, or zero verified functions fails
    (R44, R50).
  - **I2:** the verified crates still build under the project nightly and
    pass `lint-pds`, unit, Kani and bolero (V0b).
- **Control class:** fail-closed verification gate. **Adjudication:**
  Verus/Z3 for the proofs; a source scan for the trusted and required
  lists.
  - **Residual:** an inlined vstd exec helper is invisible to
    `verus-erasure`. The constraint above is policy, not mechanism [R3: T-P3].
- **check-selftest [T6a, T7]:**
  - One case per verified contract, each with a clause-specific needle:
    Verus's report naming the spec function or the clause span. The cases
    are `verus-wg-wire-window`, `verus-wg-wire-roundtrip`,
    `verus-msgs-exact`, `verus-rp-wire-roundtrip`, `verus-wire-ipv4` and
    `verus-ring-mask`.
  - `verus-trusted`: an unlisted `#[verifier::external_body]`.
  - `verus-required`: a required function moved out of `verus!`.
  - `verus-cache`, with both sides as in `kani-cache`: the uninjected copy
    reports `cached pass`, and an edited source misses.
  - `run_case` seeds `build/verus-cache`, and the Makefile gains a
    `verus_crates` override.

### C2 — wg-wire [F5]

- **Codecs:**
  - For `MessageInitiation`, `MessageResponse` and `CookieReply` (the
    wg-wire types), `parse(b)` is `Ok(m)`
    iff `b.len()` equals the type's length, the type byte matches and the
    reserved bytes are zero. In that case `emit(m) == b` and
    `parse(emit(m)) == Ok(m)`.
  - `Transport::parse` accepts iff `len >= TRANSPORT_MIN_LEN`, with the
    same header rules. `emit_transport_header` round-trips the header.
- **Replay window:** `check_and_update(c)` is one function, for any
  `BITS >= 2`, with `WINDOW = BITS - 1`.
  - It accepts iff `c < REJECT_AFTER_MESSAGES` and one of these holds:
    - nothing has been accepted yet;
    - `c` is above the highest counter accepted;
    - `highest - c <= BITS - 1` and `c` is unseen.
    
    [R3: F-N14]
  - After an accept, `c` counts as seen.
- **Mutations:**
  - `verus-wg-wire-window`: `<` becomes `<=` in
    `c.saturating_add(Self::WINDOW) < self.top`, which rejects a legal
    counter exactly `WINDOW` below the top. The spec states the window
    as the literal `BITS - 1`. (`WINDOW = BITS` is an equivalent mutant,
    because the slot collides with the top's [R2: F-N6].)
  - `verus-wg-wire-roundtrip`: the reserved-byte check removed from
    `parse`.

### C3 — msgs [F6]

- **Member set:** every `pub fn decode` in `crates/msgs/src/lib.rs`, from
  `rg -n 'pub fn decode' crates/msgs/src/lib.rs`. That gives 8 sites at
  `22432af`. Phase 2 re-derives the set, and every site is on the required
  list.
- **Spec:**
  - Each decode is total.
  - At `exact()` sites, a message is accepted iff the layout's length and
    tag predicates hold, and `decode(encode(m)) == m`.
  - For the variants that take `rest` (`RpDatagram`, `ToIngress::Outbound`),
    the trailing payload round-trips.
  - `PskInstall`'s equality is stated in spec only. It has no `PartialEq`
    by design.
- **Mutation `verus-msgs-exact`:** one `exact()` dropped.

### C4 — rosenpass-wire

- **Spec:** the C3 obligations for every `parse`/`emit` pair.
  `peek_type` agrees with `parse`'s type acceptance, and the InitConf emit
  is total.
- **Mutation `verus-rp-wire-roundtrip`:** one emit field offset by one.

### C5 — wire [F7]

- **Entry points:** `parse_frame`, `parse_frame_ip`, `parse_ipv4_packet`,
  `forward_ipv4`, `emit`, `check_into` and `check_ip_into`.
- **Acceptance:** each accepts exactly the subset's frames as implemented:
  lengths, IHL, total length, the checksum rule, no fragments.
- **Round trip:** semantic, `parse(emit(f)) == f`. It is not byte equality:
  `emit` rewrites ID, TTL=64 and DF, and drops Ethernet padding.
- **`Body::Ipv4`:** emitted verbatim under its precondition.
- **`forward_ipv4`:** decrements the TTL, refuses TTL ≤ 1, and recomputes
  the full header checksum (its doc cites RFC 1812 §5.3.1).
- **Mutation `verus-wire-ipv4`:** the TTL ≤ 1 refusal removed.

### C6 — ring, pure logic [F8]

- **In scope:**
  - `slot`, `ring_len`, and the index logic of `Producer::push` and
    `Consumer::pop`;
  - `Pool::{accept, give, first_mine, mine_count}`;
  - the held-buffer state of `Receiver::{take_into, release}`.
- **Spec,** for N a power of two ≤ 2^16:
  - every index is `idx & (N-1)` and lies inside the region;
  - no buffer is owned by both sides;
  - a held receive is released exactly once.
- **Trusted models:** `SharedAccess` and `shmem::Region` are modelled as
  spec-only traits that return arbitrary values, and are on the trusted
  allowlist. The real `unsafe` accessors stay under Kani and the law
  checker (SC30).
- **Mutation `verus-ring-mask`:** mask with `N` instead of `N-1`.

### C7 — the McEliece crate

- **Crate:** `crates/mce460896`, no_std. `#![deny(unsafe_code)]` holds
  everywhere except `barrier.rs`. Its only dependencies are `zeroize` and
  `sha3`. There are no valgrind client requests here; P15 forbids them.
- **Non-generic core:** every step that touches a secret is a non-generic
  `#[inline(never)]` function [R2: S-N1, F-N2, T-N3]:
  - `decaps(sk: &[u8; SK_LEN], ct: &[u8; CT_LEN], ss_out: &mut [u8; SS_LEN])`:
    implicit rejection, never fails.
  - `encaps_attempt(pk: &[u8; PK_LEN], rand: &[u8; ENCAPS_RAND_LEN], ct_out: &mut [u8; CT_LEN], ss_out: &mut [u8; SS_LEN]) -> u8`:
    one round-3 sampling attempt from `rand`.
    - It returns the accept bit (0 or 1). That bit is the only datum
      allowed to leave as public.
    - The candidate filter, the compaction and the duplicate check are
      computed without branches or secret addresses. The duplicate check is
      OR-accumulated through `barrier`.
    - Given the same bytes, it computes the same `e` as liboqs's round-3
      `gen_e` [R2: S-N3].
  - `keypair(rng, pk_out, sk_out) -> Result<(), RngError>`: host-only
    (`mksecrets`).
- **The generic shim:** `encaps(pk, rng, ct_out, ss_out) -> Result<(),
  RngError>`, with `rng: &mut impl FnMut(&mut [u8]) -> Result<(), RngError>`.
  - It draws `rand`, calls `encaps_attempt`, and loops while the
    returned bit is 0.
  - **Its one secret is `rand`, which determines `e`** [R3: S-R3-1,
    F-N13]. `rand` lives in `Zeroizing` and is wiped after every attempt
    and on the `RngError` path.
  - **The shim's only branch is on the returned accept bit.**
  - **Invariant I8, the exclusion's precondition:** each attempt's `rand` is
    a fresh draw of the full length, and no byte of a rejected draw is
    reused. Under I8, the attempt count is geometric and independent of the
    accepted `e`. That is why the shim is excluded from C10(a) by name.
  - **Coverage:** C10(c) baselines the shim's shape in `pd-pq` as a
    tripwire. C9's residue mode runs the real shim (see C9).
- **Outputs go to caller buffers** [S-8].
- **Sizes:** `PK_LEN` 524160, `SK_LEN` 13608, `CT_LEN` **188**, `SS_LEN` 32.
  The KEM owns them. `pqkey-core` asserts `secret_blob::pq` against them.
- **Dependencies:** the resolved set must equal `{zeroize, sha3}` and their
  pinned closure. check-pins P16 enforces this from `cargo metadata`
  [R3: S-R3-4].
- **Test-support API:** the pack and transpose functions are `pub`, so
  that C9's residue mode derives its needles from the port's own code.
  Exposing them changes no body in the identity set [R3: T-P2].
- **Consumer flows:**
  - **pqkey-core `decapsulate`** calls `decaps` into a `Zeroizing` buffer
    and writes its reply words from it.
  - **rosenpass-core `McEliece460896::encaps`** calls `encaps` with a
    closure over its `Rng`, into a local `ct` and a `Zeroizing` `ss`. It
    returns `(ct, Secret::copy_from(ss))` and maps an RNG failure to
    `EncapsError::Rng`. `CmrRng` is deleted.
  - **`tools/mksecrets`** calls `keypair`, then `encaps` for the blob's KAT
    ciphertext and its `kat_shk_hash`.
- **Invariants:**
  - **I3:** every mask operation goes through one `barrier::` call. The
    member set is a committed mapping table, C site → port site, with
    its count [S-12, R2: S-N4]. It covers:
    - every `crypto_int*`/`crypto_uint*` call in the ported libmceliece
      files;
    - every mask site of the round-3 framing source: the `C1` compare,
      the merge of the confirmation failure with the decode failure, the
      `e`/`s` select, and the sampler's filter, compaction and duplicate
      check.
    
    The round-3 framing source is the round-3 reference that liboqs 0.8
    vendors, pinned by rp-vectors' `oqs-sys` lock.
  - **I4:** every array index is public.
  - **I5:** the shim's `rand`, and every secret intermediate of
    `encaps_attempt` and `decaps`, is wiped before return [R4: F-N20].
    The intermediates are `e` (bytes and `ind[]`), the syndrome, the BM
    state, `g`, the support and `ss`, bitsliced forms included. C9's
    residue scan checks this.
    - **Stack scrub** [R4: S-R4-1]: `decaps` and `encaps_attempt` are thin
      roots. Each calls its `#[inline(never)]` `_core` stage, then
      `scrub_stack()`. That is
      a safe `#[inline(never)]` function that zeroes, with volatile writes,
      a local array of `SCRUB_DEPTH` bytes, which removes what `sha3`,
      `keccak::f1600` and compiler spills leave in frames below.
    - `SCRUB_DEPTH` is asserted at or above the stack peak of the `_core`
      closures that C8's painting measures, plus a margin.
    - Residue mode asserts that the scrubbed depth covers its
      painted-depth floor.
    - The scrub is in the identity set, so it ships as tested. The keccak
      and `ss` needles stay mandatory.
  - **I6:** a failed RNG draw returns `RngError`.
  - **I7:** every secret-derived integer uses `wrapping_*`.
- **Control class:**
  - I3, I4, I6, I7 and I8 are app-enforced.
  - C9 and C10 adjudicate I3, I4 and I7. The C9 residue scan adjudicates
    I5.
  - I8 has a unit test: a recording `FnMut` RNG asserts one request of
    `ENCAPS_RAND_LEN` bytes per attempt, each attempt's buffer equal to its
    fresh bytes, and no reuse of a rejected draw. Selftest
    `mce-fresh-draw` reuses half of a rejected draw [R4: S-R4-2].

### C8 — functional equivalence

- **Oracle:** `tools/rp-vectors --mce`, which runs in rp-vectors' own
  workspace and lock [F1, T9]. It drives liboqs 0.8's round-3 McEliece
  through `OQS_randombytes_custom_algorithm`, as `main.rs` already does,
  and writes `crates/mce460896/tests/vectors/liboqs.txt` with:
  - deterministic keygen from fixed seeds;
  - encaps under a fixed stream;
  - decaps of valid and corrupted ciphertexts in four classes: valid;
    `C0` corrupt; `C0` valid with `C1` corrupt; both corrupt.
- **NIST round-3 KAT:** the first 3 entries of the published `kat_kem.rsp`,
  committed in full and checked. The rest is not claimed [R2: T-N12].
- **The existing liboqs vector** in rosenpass-core stays unchanged.
- **The cmr bridge** [T10, F11]:
  - In slice M0, a temporary `--cmr` mode writes
    `crates/mce460896/tests/vectors/cmr-2.0.2.txt`. Its header names the
    cmr version and the producing commit.
  - The file is then frozen. C11 deletes the mode and its cmr dependency,
    and the decaps test keeps running against the frozen file.
- **Encaps sampling follows liboqs** (the peer). Any divergence from cmr is
  recorded.
- **Acceptance:**
  - All vectors pass in `make unit`.
  - The integration suite passes against 0.2.3 and master.
  - `MCE-COST` holds.
  - `pq`'s and `pqkey`'s stack peaks, measured by stack painting [F14],
    are within `0x20_000`.
  - The dev profile sets `opt-level = 3` for `mce460896`.
  - Every removed cmr-specific test has a named replacement (for example
    I6's RNG-failure test), and the manifest deltas are listed [T16].

### C9 — the dynamic constant-time gate and residue scan

- **Subject:** `tools/ct-harness`, its own crate. Its client requests live
  in `tools/ct-harness/src/vg.rs` only (P15). It has at least one unit
  test, for its report parser [R2: F-N8].
- **Build:** for `aarch64-unknown-linux-gnu`, with the PD's codegen
  [S-1, S-4, R2: S-N6, F-N3, T-N3]:
  - the project nightly and the release profile;
  - `opt-level "s"`, `overflow-checks = true`, `panic = "abort"`;
  - `-C relocation-model=static`, frame pointers as the PD target;
  - `-C target-feature=+v8a,+strict-align,+neon`;
  - `debug = "line-tables-only"`.
  
  The remaining deltas from `support/targets/aarch64-sel4-microkit.json`
  (`llvm-target`, `disable-redzone`, `default-uwtable`, stack probes,
  build-std) are listed in C9, each with the probe result showing it
  leaves the identity set's code unchanged.
- **Running:** `make ct` runs the same harness binary twice, from
  `build/ct` [R3: T-P1, S-R3-2]:
  1. **CT mode** under `valgrind --tool=memcheck --error-exitcode=97`,
     with no suppressions [R2: T-N1];
  2. **residue mode** natively, outside valgrind. The scan reads stack
     memory that memcheck treats as dead or undefined, so it cannot share
     a run with the exact-one-error rule.
- **CT mode:**
  - Exits 3 when it is not `RUNNING_ON_VALGRIND`.
  - Marks `sk` and each `rand` undefined. It counts as `CT-MARKED-BYTES`
    only the bytes that `VALGRIND_GET_VBITS` confirms undefined, read
    back on the exact buffers the KEM receives.
  - Runs the canary, which branches on a marked byte.
  - Runs `decaps` on the four C8 classes plus boundary weights, and
    `encaps_attempt` on accepting and rejecting `rand` (`CT-CASES`).
  - Declassifies only at `vg::declassify(site_id, buf)`, whose site ids
    must equal `policy/ct-declassify.toml` exactly. Every entry is either a
    1-byte predicate or a harness-boundary output. The harness enforces
    the width. The member set is:
    - `encaps_attempt`'s returned accept bit;
    - `ct` and `ss` before the vector compare.
    
    That list is complete [R2: S-N3, T-N2].
  - Prints `CT-DONE <cases>` last.
- **Residue mode** [R2: S-N5, T-N7]:
  - Exits 4 when it *is* running on valgrind.
  - Each KEM call runs on a thread whose stack the harness owns: `mmap`,
    `pthread_attr_setstack`, painted before the call and still mapped
    after the join. Outputs live on the heap.
  - The scan requires a painted-depth floor.
  - It searches for each secret in every stored form: the shim's `rand`;
    byte `e`; `ind[]` as u16; bitsliced `e`, `g` and the support; the
    syndrome; the BM state; the keccak preimage and state; and `ss`.
  - The needles come from the port's own `pub` pack and transpose
    functions, and from its `pub` stage functions `syndrome` and `bm` for
    the syndrome and the BM state [R3: T-P2, R4: T-Q3].
  - The needles are computed on the main thread into the heap, never on the
    scanned stack.
  - It runs `decaps`, `encaps_attempt`, and the real generic `encaps` shim
    driven by a harness `FnMut` RNG that rejects at least once
    [R3: S-R3-1, F-N13].
  - It prints `RESIDUE-CASES <n>` and `RESIDUE-DONE`.
- **Decision:** a pass requires all of:
  - exit status exactly 97;
  - `ERROR SUMMARY: 1 errors`, the canary's report at the canary's symbol;
  - `CT-DONE`, with `CT-CASES` equal to its count;
  - `CT-MARKED-BYTES` > 0;
  - the declassify site set equal to the policy;
  - residue mode exiting 0, with `RESIDUE-DONE`, `RESIDUE-CASES` equal to
    its count, and no hit.
  
  Anything else fails. There is no function-name filter.
- **Control class:** fail-closed verification gate over the executed paths
  and inputs. **Adjudication:** memcheck's definedness tracking, on code
  that C10 proves identical to the shipped code.
- **Red-proof:**
  - **Once, recorded:** cmr 2.0.2's decaps under the same harness reports
    F1.
  - **check-selftest:**
    - `ct-barrier`: one BM select made a plain `if`. Needle: the report
      kind plus `file:line`.
    - `ct-c1-barrier`: the `C1` compare made an early exit.
    - `ct-declassify`: an unlisted site id.
    - `ct-declassify-width`: a value array declassified.
    - `ct-canary`: the canary removed.
    - `ct-early-exit`: an abort after the canary.
    - `mce-residue-<form>`, one case for each needle form: `rand`,
      `e-bytes`, `ind`, `e-bitsliced`, `g`, `support`, `syndrome`, `bm`,
      `keccak` and `ss` [R4: S-R4-3].
      - Each removes the wipe or scrub that guards that form.
      - The needle is the hit line naming the form.
      - The member set is the needle list.
      - The `keccak` and `ss` cases remove `scrub_stack()`.
    - `residue-under-valgrind`: residue mode run under valgrind. Needle:
      the exit-4 message [R4: T-Q2].
    - `ct-not-valgrind`: the scratch Makefile runs CT mode without
      valgrind. Needle: the gate's exit-3 message [R3: T-P5].
- **Image:** `valgrind` from the image's Debian snapshot.
- **Manifest:** `CT-CASES`, `CT-MARKED-BYTES`, `CT-DECLASSIFY`,
  `RESIDUE-CASES`.
- **Pass record:** `make ct` writes it only when both modes pass
  [R3: S-R3-3].
  - It is keyed by the sha256 of the harness binary,
    `policy/ct-declassify.toml`, the vector files, and
    `valgrind --version`.
  - One function, `tools/ct_record.py`, derives the key for both `make ct`
    and `tools/package`. A fixture shows that a record written under an
    old policy refuses after a policy edit [R4: T-Q1].
  - It holds the `CT-CASES`, `CT-MARKED-BYTES` and `RESIDUE-CASES` lines,
    and package checks them.
  - It is a plain file under `build/`, so anyone who can write the tree can
    forge it. That is the same bypass class as editing `waivers.toml`, and
    it is declared under R49 (b) [R3: S-R3-3].

### C10 — identity and shape of the shipped code

- **Signature:** `tools/ct-shape`. Its make prerequisites are `pds` and
  `ct-harness`; it is a gate with prerequisites, not two gates [R2: T-N5,
  F-N7].
  - **(a) Identity, per ELF** [R2: F-N1, S-N1]:
    - The expected roots are `mce460896::decaps` for `pd-pqkey.elf` and
      `mce460896::encaps_attempt` for `pd-pq.elf`.
    - For each, the full call-graph closure from the root is derived from
      the PD ELF (hash suffixes stripped), following `bl` and tail-call
      `b <sym>` edges [R3: F-N12].
    - The closure stops at panic entries, defined by property: any `core::`
      function whose name ends in `_fail` or `_failed`, or that never
      returns (no `ret`, ends in a `core::panicking::*` call). These are
      public cold edges, and C9 decides whether any branch to them is
      secret. The stop set's unit test includes
      `copy_from_slice`'s `len_mismatch_fail` [R4: F-N18].
    - `memcpy`, `memset` and `memmove` are allowlisted by name on both
      sides. This is sound because the call site, where length and
      pointer are computed, is identity-bound. Under memcheck, valgrind's
      replacement `mem*` reports a secret length or offset. Given public
      arguments, the aarch64 `mem*` branches only on length and alignment.
    - `memcmp` and `bcmp` are not allowlisted: they exit early, and (b)
      forbids them.
    - Both builds use `-Z share-generics=no`, so each generic instantiation
      sits in the crate that instantiates it.
    - That closure must equal the same root's closure in the harness, and
      each function's normalised disassembly must be identical.
    - The normaliser masks only immediate address operands and relocation
      targets, never opcodes or registers. Its own unit test shows that a
      one-instruction difference is caught [R2: S-N6].
    - A missing or extra function fails.
  - **(b) Forbidden in those closures:** `udiv`/`sdiv`, `br`/`blr`,
    calls to `memcmp`/`bcmp`, and the valgrind client-request instruction
    preamble. (b) reads the compiled code [R3: S-R3-4].
  - **(c) Shape baseline:**
    - Per function, the multiset of conditional instructions and
      register-offset or non-immediate-offset memory operands equals
      `policy/ct-shape.toml`, and every entry is justified.
    - There is no write mode reachable from make.
  - **Erasure:** runs `verus-erasure` (C1).
  - **Output:** each ELF's sha256, and `CT-SHAPE-SYMBOLS <n>`.
- **Control class:** (a) and (b) are a fail-closed gate that carries C9's
  verdict to the shipped code; (c) is a tripwire, whose recovery path is
  C9.
- **Identity probe (slice M-1, before the port)** [R2: T-N3, F-N3]:
  - compare `sha3`'s keccak functions, which `pd-pq` already ships, between
    a harness-target build and `pd-pq.elf`;
  - also compare a probe `#[inline(never)]` function containing a
    bounds-checked index, an overflow-checked public add and a
    `copy_from_slice` [R3: F-N12].
  
  If identity cannot be reached by codegen flags, stop and ask the owner
  before porting. SC23 never closes on (c) alone.
- **check-selftest:**
  - `ct-shape`: the `ct-barrier` mutation. Needle: the multiset-diff line.
  - `ct-identity`: the scratch Makefile's `build_pd` gives `pd-pq` alone
    `RUSTFLAGS=-C opt-level=3`. Needle: the identity-diff line naming
    `pd-pq` and a `mce460896::` function [R2: T-N4]. The uninjected copy
    is proven green.

### C11 — cut-over, waiver close, L2 amendment

- **Cut-over:**
  - `pqkey-core`, `rosenpass-core` and `tools/mksecrets` use `mce460896`.
  - `classic-mceliece-rust` leaves the root `Cargo.lock`, the `--cmr` mode
    and `tools/rp-vectors`' lock. Then `cargo metadata --offline`, and the
    gates with `--locked`.
  - The profile override moves to `mce460896`.
- **SC23 closes in `policy/waivers.toml`.** `tools/package`'s binding
  [S-2, R2: S-N2, F-N4]:
  - `package:` depends on `image` and `ct-harness`, and gets the harness
    path explicitly.
  - For every kernel config, `tools/package` runs `tools/ct-shape` (a)
    and (b) on the ELFs it packages. A missing harness refuses
    [R3: F-N16].
  - For every non-debug kernel config, it also requires a C9 pass record,
    `build/ct/pass-<harness sha256>`, written by `make ct`, which binds
    C9's verdict to that harness. Debug images are dev-only and already
    run C9 in `make check`. Release kernels remain refused by SC20 until M5.
  - **Fixtures:**
    - closed with ct-shape red → refuse;
    - closed with identity green but no C9 record on a release config →
      refuse. This fixture stubs SC20 (`stub_sc20=True`), so that the
      missing record decides [R3: T-P4];
    - closed with everything green → allow;
    - cmr locked while closed → refuse;
    - harness missing → refuse.
    
    At least one fixture runs the real `tools/ct-shape` on a mutated ELF
    through `tools/package` [R2: T-N8].
  - `tools/waivers.py` and the `waivers.toml` comments state this binding.
- **L2 is amended** [S-3]. It names pqkey's basis: `mce460896` under C9
  and C10, unaudited (R-M1), DIT unchecked (R-M2).
- **check-pins rules,** each with deny and allow fixtures:
  - **P12:** C1's trusted constructs inside `verus_crates`, outside the
    allowlist. The scanner is `tools/verus_trusted.py`, which the Verus
    gate shares. It matches `verifier::x` / `verifier(x)` tokens anywhere
    in an attribute's token stream, `cfg_attr` included, and has a
    `cfg_attr` deny fixture [R2: S-N7, T-N11].
  - **P13:** cmr as a Cargo dependency key in any tracked (`git ls-files`)
    `Cargo.toml` or `Cargo.lock`, including `tools/rp-vectors` [R3: F-N15],
    or as a Rust
    `use`, `extern crate` or `classic_mceliece_rust::` path in `.rs`.
    - Comments and the Python binding (`tools/waivers.py` `BOUND`,
      `tools/check-pins`) are out of P13's reach by construction, with an
      allow fixture over `waivers.py` [R2: F-N5, T-N9].
    - Deny fixture: cmr re-added to rp-vectors' lock.
  - **P14:** `unsafe` in `crates/mce460896` outside `barrier.rs`.
  - **P15:** the valgrind client-request instruction sequence outside
    `tools/ct-harness/src/vg.rs` [R2: T-N2].
  - **P16:** `crates/mce460896`'s resolved normal-dependency set (edges
    with `kind == null` from `cargo metadata`) equals `{zeroize, sha3}`
    and their pinned closure. Dev-dependencies are out of scope
    [R3: S-R3-4, R4: F-N19].
  - **P9/P10:** the secret-crate lists gain `mce460896`.
- **Selftests:**
  - `package-waiver` injects an open waiver.
  - A new allow case, `package-waiver-closed`, runs `make package` on
    the debug config with SC23 closed. Its inputs are a scratch copy whose
    `SECRETS`/`PQ_SECRETS` blobs come from `mksecrets` inside that copy.
    Its `OUT` is also inside the copy, and the case asserts that the
    package exists there [R4: T-Q4].
    Both cases are in `EXPECT_SUCCESS`/`ABSENT` as applicable [R2: T-N13,
    R3: T-P4].
- **Member set:** derived by
  `git grep -n -E 'SC23|classic.mceliece|\bcmr\b|CmrRng|rand_core|constant.time|\bL2\b|waiver' -- ':!docs/archive'`,
  plus the L2 rows of the architecture plan and the M3 plan. Each hit is
  updated or classified as historical in the deviation log.
- **Acceptance:**
  - `make check` passes.
  - The debug package still builds.
  - The release refusal names only SC20 (owner M5).

## Files to update [F17]

- **`Makefile`:**
  - `check:` runs `pins audit lint lint-pds unit kani verus ct ct-shape
    bolero laws test`. `ct-shape` depends on `pds` and `ct-harness`, and
    `package` depends on `ct-harness`.
  - Add `.PHONY` entries and the `verus_crates` variable.
  - `build_pd` and `clippy_pd` `RUSTFLAGS` gain `-Zshare-generics=no`. This
    re-codegens every PD, and slice M-1 records the per-PD `.text` hashes
    before and after this change. The `ct-identity` injection keeps the
    flag, so its diff comes from opt-level alone [R4: F-N21].
  - `host_crates` gains `mce460896` and `ct-harness`, so `LINT-CRATES`
    goes up by 2.
- **`tools/check-selftest`:**
  - all new cases and the `CASES_FOR_GATE` rows for `verus`, `ct` and
    `ct-shape`;
  - `verus-cache` seeding and its allow pre-run;
  - the `EXPECT_SUCCESS`/`ABSENT` entries for `verus-cache` and
    `package-waiver-closed`.
- **`tests/manifest.txt`:** the `VERUS-*`, `CT-*` and `CT-SHAPE-SYMBOLS`
  keys, `UNIT-MCE460896`, `UNIT-CT-HARNESS`, the unit deltas, `LINT-CRATES`,
  `CHECK-PINS-*`, `CHECK-SELFTEST-FIXTURES` and `PACKAGE-FIXTURES`.
- **`tools/check-pins`, `tests/tools/test_check_pins.py`:** P9/P10 and
  P12–P16.
- **New:** `tools/verus_trusted.py`.
- **`tools/package`, `tests/tools/test_package.py`.**
- **`tools/waivers.py`, `policy/waivers.toml`.**
- **New policy files:** `policy/verus-trusted.toml`,
  `policy/verus-required.toml`, `policy/ct-declassify.toml`,
  `policy/ct-shape.toml`.
- **`docker/Dockerfile`:** the `verus` stage and `valgrind`.
- **Rust sources:**
  - `Cargo.toml`;
  - `crates/secret-blob/src/pq.rs` comments;
  - `crates/rosenpass-core/{Cargo.toml,src/kem.rs}`;
  - `crates/pqkey-core`;
  - `tools/mksecrets`;
  - `tools/rp-vectors` (`--mce`, and the temporary `--cmr`).
- **Docs:** the architecture plan (L2, SC4), `docs/PLAN.md`, and the
  deviation log.

## Testing strategy

- **Slices:** fast gates during each slice, then one solo `make check`
  at the end.
  - **V0b**, then V1 (C1, C2), V2 (C3, C4), V3 (C5), V4 (C6). Each V slice
    records per-PD `.text` hashes before and after.
  - **M-1:** the identity probe (C10).
  - **M0:** the rp-vectors `--mce`/`--cmr` modes and their vectors.
  - **M1:** C7 and C8.
  - **M2:** C9 and C10, including the recorded cmr F1 run.
  - **M3:** C11.
- Every new gate has selftest cases, and mutations replace re-review.
- Kani and Verus share one lock and run alone.

## Considerations & constraints

- **R-M1:** the port has no third-party audit. C8 binds its behaviour to
  the peers' code. C9 and C10 bind its compiled code on the executed paths.
- **R-M2:** whether seL4/Microkit sets PSTATE.DIT is not checked. The
  multiplier's timing is assumed data-independent on the target core. This
  is revisited in M7.
- **R-M3 [S-10]:** Verus's proc macros and vstd are in the build path of
  every verified PD, and their output ships.
  - **Mitigations:** the per-PD `.text` hash record, `verus-erasure`, and
    the unit, Kani, bolero and integration runs on the expanded code.
  - **Residual:** an unaudited macro could change semantics in a way these
    tests miss.
- **R-M4:** vstd's own trusted specs are part of every proof's base. This is
  accepted, with the version pinned.
- **R-M5 [S-14]:** keygen in `mksecrets` (offline, on the operator host) has
  no C9/C10 gate and no residue test. Owner: unscheduled (SC31). It is a
  one-time offline operation.
- **R-M6:** C9 sees only the paths its inputs reach.
- **R-M7:** secret values left in registers after return (general-purpose
  and NEON, bitsliced data included) are not scrubbed. Only the same PD and
  the kernel, which saves the registers on a context switch, can reach
  them [R5: S note].

### Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC20 | Release-kernel images | M5, with SC11 |
| SC24 | Rosenpass V03 alongside V02, configured per peer, with the version identified by envelope mac before decapsulation | the first upstream release containing V03 |
| SC28 | A dedicated InitConf ring, if needed | M7 measurement |
| SC29 | Vest-generated parsers | unscheduled |
| SC30 | Verus proofs of ring's unsafe accessors and of ingress-core's gate state machines | unscheduled; Kani keeps them bounded |
| SC31 | A constant-time gate for McEliece keygen (R-M5) | unscheduled |

## User operation scenarios

1. `make check` runs Verus, valgrind and the identity/shape gate together
   with the other gates.
2. A toolchain bump changes `pd-pqkey.elf`'s codegen. If the harness
   changes in step, identity stays green and C9 re-decides on the new code.
   A shape change fails `ct-shape` until a reviewed baseline edit.
3. An operator regenerates dev secrets with `mksecrets`, and the gateway
   still interoperates with 0.2.3 and master clients.
4. A contributor adds `assume(` or `#[verifier(external_body)]`. P12 and
   the Verus gate's allowlist comparison both fail it.
5. Packaging a tree on which `ct-shape` fails is refused, even with SC23
   closed.

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Verus gate, erasure check, image stage | locked |
| C2 | wg-wire specs and replay window | locked |
| C3 | msgs specs | locked |
| C4 | rosenpass-wire specs | locked |
| C5 | wire specs | locked |
| C6 | ring pure logic | locked |
| C7 | mce460896 crate | locked |
| C8 | functional equivalence and residue | locked |
| C9 | dynamic CT gate | locked |
| C10 | identity and shape of shipped code | locked |
| C11 | cut-over, waiver close, L2 amendment | locked |

## Implementation Checklist

Files to modify are listed in "Files to update". Each slice adds the files
it touches to its commit.

### Shared utilities to reuse (no reimplementation)

| Utility | Location | Reused for |
|---|---|---|
| Cache key, flock and count line | `tools/kani-gate.sh` | the `verus-gate.sh` pattern; the lock file itself (`build/kani.lock`) is shared |
| Count comparison | `tools/check-manifest` | every new count goes through it; there is no second comparator |
| Selftest cases | `tools/check-selftest`: `edit()`, `copy_repo`, `run_case`, `EXPECT_SUCCESS`/`ABSENT`, `CASES_FOR_GATE` | all new selftest cases |
| Deterministic liboqs RNG | `tools/rp-vectors/src/main.rs`, `OQS_randombytes_custom_algorithm` | the `--mce` mode |
| Blob sizes and layout | `crates/secret-blob/src/pq.rs` | asserted against `mce460896`; not duplicated |
| Constant-time compare | `crates/pqkey-core` `ct_eq` | unchanged; the port's internal compares go through `barrier` |
| `Secret` and the RNG trait | `crates/rosenpass-core` `Secret`, `Rng` | the kem.rs adapter wraps the port's caller buffers |
| Stack painting | the M3 deviation log's method, `tests/integration` | C8's stack peaks |
| Shared lists for the secret-crate rules | `tools/check-pins` P9/P10 | extended, not forked |

### Patterns to follow consistently

- Every downloaded artifact is pinned by sha256 in `docker/Dockerfile`, and
  each build stage runs offline after `cargo fetch --locked`.
- Every gate prints a non-zero count line into `build/counts`, and the
  manifest lists that count.
- Every selftest needle is failure-only (memory: `selftest-red-proof-pitfalls`).
- Kani and Verus runs are serialised through `build/kani.lock`.

### CI gate parity

There is no CI configuration (E4). `make check` is the only aggregate
gate, so there is no parity gap.
