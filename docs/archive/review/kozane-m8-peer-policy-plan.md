# Plan: kozane-m8-peer-policy

M8: identity that an enterprise can run safely. Identity decisions leave the
gateway. The gateway only verifies and enforces a signed peer-policy bundle
with a fixed upper bound (8 peers), applied at reboot.

The scope was fixed by the owner on 2026-10-28 and is not re-opened here.
On 2026-10-29 the owner added three items (after the RSUPPORT VPN-ransomware
report):

- code patches roll out under the same 15-minute procedure as peer policy;
- release anti-rollback (SC33) is investigated on M8's NV counter, and
  deferred to M9 only if too heavy (it is not: D5);
- an audit mapping (who / from where / when / record → mechanism + test).

Laws L1–L14 are in
[secureos-pq-vpn-architecture-plan.md](secureos-pq-vpn-architecture-plan.md);
this plan amends L6 and adds role rules (C11). "M7 Cn" cites
[kozane-m7-qemu-platform-plan.md](kozane-m7-qemu-platform-plan.md). Finding
IDs in brackets (F functionality, S security, T testing; rounds 1–10) point to
[kozane-m8-peer-policy-review.md](kozane-m8-peer-policy-review.md).

Process: contract-first, risk-tiered review, vertical slices with fast
gates, one solo `make check` at the end, then the split self-test.

## Project context

- **Type:** `mixed`. seL4/Microkit image (no_std Rust PDs), host tools,
  firmware, libraries.
- **Test infrastructure:** unit, Kani, Verus, bolero, laws, ct/ct-shape,
  MIR, repro, QEMU integration and the gate self-test, all behind a local
  `make check`. No CI (SC9).
- **Verification environment constraints.** New IDs continue from VE16.
  - **VE2, VE5, VE7, VE14, VE15, VE16** (existing) unchanged.
  - **VE17: no HSM.** M-of-N custody of the policy signing key cannot be
    exercised. `tools/policy` enforces two approvals in software and holds
    a dev key in a file (as RM5-1 for releases). `blocked-deferred` →
    RM8-1.
  - **VE18: no IdP, MDM or SIEM.** Approver identities are stand-in
    Ed25519 keys. SIEM ingestion is replaced by `tools/audit-verify` over
    the captured UART. The identity/factor binding is `blocked-deferred` →
    RM8-2; the gateway-side record, chain and checkpoint contracts are
    `verifiable-local`.
  - **VE19: no load balancer or fleet.** The 15-minute SLA is operational
    (D6). The gateway half (boot-time version lines) is
    `verifiable-local`; drain / evict is `blocked-deferred` (tabletop
    only) → RM8-3.
  - **VE20: swtpm has no platform firmware.** Platform auth is empty under
    QEMU, so provisioning can create platform indices (C3). The TPM
    semantics are `verifiable-local`; the board's platform-auth ownership
    is `blocked-deferred` → RM8-4 [T19].

## Objective

1. A peer-policy bundle — peers, their keys, allowed IPs and group
   memberships, and group rules — is signed by two-person-approved
   tooling, loaded at boot from A/B slots, measured into PCR 9, verified
   by a `policy` PD, and every parsing PD stays closed until it is.
2. A rolled-back bundle is refused. A TPM NV counter only moves forward,
   and only after a newer slot was written and verified.
3. Group authorization is enforced in `inner`, in both directions.
4. The gateway states at boot which release and which policy it runs, and
   its audit stream is exportable with integrity (boot ID, sequence, hash
   chain, signed checkpoints, `lost`).
5. A signed older release that contains `policy` keeps its parsing PDs
   closed when the current bundle sets a higher release floor (SC33).

## Threat model additions

| ID | Adversary | Capability |
|---|---|---|
| A12 | Revoked peer | Holds valid keys from an earlier bundle. Loses access at a node once that node accepted the newer bundle (C5). Until then, revocation at that node is the runbook's (detection + RM8-3) [S10]. |
| A13 | Media attacker on the bundle slots | Writes any bytes to either slot, including older signed bundles, or withholds an update. The bundle is not in PCRs 0–8, so the secrets still unseal: the bundle is untrusted input to `policy`. |
| A14 | Single insider at the PDP | Drafts any bundle, approves once, runs the signer, supplies files to it. Must not obtain a signature alone, swap the payload, fork a version, or rebase onto a stale `prev` (C2). |
| A15 | Rollback to an older signed release | Reflashes a signed older image with its envelopes. Pre-M8 releases: closed by provisioning's TPM Clear (D5). ≥ M8 releases: the release floor (C9). |
| A16 | Single operator with TPM access | Tries to redefine the NV indices or re-provision to an older version. Needs two operator authorizations (C3) [S1]. |
| A10 | (existing) Firmware-media attacker | Unchanged; may also issue TPM NV commands from replaced code: at most DoS (D2). |

## Feasibility probes (slice 0)

Each probe runs on the real toolchain before its contracts are built; the
observations go to the deviation log. A refuting probe sends only the
named contracts back to `pending`. No silent fallback.

| ID | Question | Pass condition | Refutes |
|---|---|---|---|
| P1 | swtpm NV semantics for the C3 attribute sets: platform-created counter and base; `NV_Increment`; `NV_WriteLock` permanence; owner `NV_UndefineSpace` refused; `NV_UndefineSpaceSpecial` needs the two-signature delete policy (`PolicyCommandCode` ∧ two `PolicySigned`); `TPM2_Clear` keeps both; Names (after WRITTEN, and WRITELOCKED for the base) reproduced by the host twin; the counter survives SIGKILL of swtpm and a QMP reset [S4, T3]; `resetCount` read at the end of provisioning is one below the next boot's (the C10 `reset_at_provision + 1` rule) [T58] | All as stated | C3 |
| P2 | `libcrux-ml-dsa` and `libcrux-ed25519` at `tools/release`'s pins build `no_std` for the PD target and pass its vectors; time for `policy` to hash both `BUNDLE_MAX` slots and verify two max-size bundles at its real priority while `key`, `pqkey`, `tlskey` run above it, under TCG `cortex-a72` [F7] | Builds; vectors pass; full boot to `pq: ready` stays under `BOOT_TIMEOUT_S` with ≥ 30 % headroom [T11] | C1, C5 |
| P3 | U-Boot `hash sha256` + `tpm2 pcr_extend 9` over two `BUNDLE_MAX` slots; Microkit loader with two `BUNDLE_MAX` prefill MRs; load addresses below `0x6fb00000` [F9] | Boots; PCR 9 equals the twin; boot-time delta within P2's headroom | C4 |
| P4 | `tpm2-wire` builders/parsers for `NV_ReadPublic`, `NV_Read`, `NV_Increment`, `ReadClock`, `GetCapability(TPM_PT_STARTUP_CLEAR)` against swtpm | Round-trip OK | C3, C10 |
| P5 | Baseline wall-clock of today's `make test` and `integration-count`; projection with C13's boots [T11] | Projection < 3 h (`CASE_TIMEOUT_S` 4 h) | Testing schedule |

## Decisions (recorded)

- **D1: one hybrid signature on the device.** The device verifies one
  bundle signature: Ed25519 **and** ML-DSA-65 (both must verify), domain
  `kozane-peer-policy-v1\0`, keys separate from release signing. The
  owner's "dual signature" is this pair. Two-person approval is enforced
  before signing (C2) and by M-of-N custody (RM8-1); two device-visible
  approver signatures would add nothing the device can judge.
- **D2: TPM counter plus write-once base.** The owner's "fixed NV index"
  is the counter `NV_POLICY_CTR` with its write-locked companion
  `NV_POLICY_BASE`.
  - A `TPM_NT_COUNTER` cannot decrease, even under a compromised `tpm`
    PD. A "+1 only" rule on an ordinary index would be app-enforced.
  - The logical version is `counter.wrapping_sub(base)`, required
    `≤ u32::MAX`. Provisioning sets `base = counter.wrapping_sub(v0)`
    with no increments, so any fleet version is reachable [F11].
  - Write authorization is not PCR-bound (that needs PolicyAuthorize, out
    of scope). Integrity does not need it: an unauthorized increment only
    moves the node forward, which is DoS until re-provisioned (RM8-6).
  - Owner auth stays empty because every boot recreates the SRK under the
    owner hierarchy. So the indices are platform-created with
    `POLICY_DELETE`, under a delete policy that needs two operator
    signatures [S1]. The anti-rollback boundary is the counter **and**
    that delete policy together.
- **D3: both slots are measured; `policy` selects.** U-Boot cannot verify
  signatures, so it extends PCR 9 with `sha256(slot A)`, then
  `sha256(slot B)`, over the full `BUNDLE_MAX` ranges, and copies both.
  PCR 9 is not in the seal policy (owner scope): "measured, quotable in
  future".
- **D4: peers leave the build-time config.** `[[peers]]` moves from
  `config/gateway.toml` to the bundle. The node's own keys, addresses,
  neighbours, `fleet_id`, the policy public keys and the NV Names stay
  compiled in (C7). L6 is amended (C11).
- **D5: SC33 lands in M8 without a second counter or a firmware check.**
  - Each release compiles in `RELEASE_SEQ` (u32, leaf crate
    `release-seq`, read only by `policy` [F16]) and signs it in the
    release manifest. Each bundle carries `min_release`. `policy` refuses
    a bundle with `min_release > RELEASE_SEQ`, so a signed older ≥ M8
    release keeps every parsing PD closed (C6).
  - The floor rides on the bundle's anti-rollback, so it cannot be rolled
    back either.
  - The drivers `eth_in`/`eth_out` do not parse (L7) and stay outside the
    barrier: a bug in an older driver's copy path stays reachable under
    the floor (RM8-8) [S5].
  - Pre-M8 releases have no `policy`. `tools/provision` always runs
    `TPM2_Clear` before creating the SRK, so no pre-M8 envelope unseals
    after M8 provisioning; it is not a runbook step that can be skipped
    [S5].
  - Bad-release recovery is fix-forward, or a two-person-approved bundle
    lowering `min_release`: rollback becomes a signed decision.
  - Cost: one constant, one manifest key, one comparison. A firmware-side
    check would add signature or NV policy code to firmware for no
    property the floor lacks beyond RM8-8.
- **D6: the 15-minute SLA is an operational control.** Gateway class:
  `detection or audit only` — it prints `release_seq` and the accepted
  policy version at boot. Drain → update/reboot → version check → rejoin,
  eviction at 15 min, and cutting direct access to non-compliant nodes
  [S10] are the runbook's (C12), for bundles and code patches alike.
- **D7: a dedicated `auditkey` PD signs checkpoints** [F1, F2, S6].
  - The laws allow one PPC caller per key PD, and `audit` is tainted. So
    the audit key gets its own key-role PD, `auditkey`, with `audit` as
    its only caller and its own sealed envelope (kind `audit`): the fourth
    raw `tpm` client (C3). Like the other key PDs it maps only its secrets
    MR and has no audit ring; it reports status in its PPC replies and
    `audit` prints them as source `auditkey` [F19]. `key` and its blob are
    untouched by C10.
  - `auditkey` draws the boot ID from `rng` and reads `resetCount` /
    `restartCount` with `ReadClock`, allowed for its client only, before
    its Done [F18, S19]. The signer, not `audit`, fixes boot identity
    [S6, S11].
  - It signs only the fixed-width tuple `domain ‖ srk_name ‖ boot_id ‖
    reset ‖ restart ‖ seq ‖ chain ‖ lost` (`srk_name` from its envelope's
    pinned SRK, so a capture names the TPM a provisioning record binds)
    [S26] (domain `kozane-audit-checkpoint-v1\0`),
    and refuses unless `seq ≥ last_seq + CHECKPOINT_EVERY` (one "ready"
    checkpoint exempt, which still needs `seq > last_seq`) and `seq` has
    not overflowed [S25]. The request parser
    lives in a Kani-proved `auditkey-core` [S20, F30]. A compromised
    `audit` can still get signatures over chains it fabricates in the
    current boot (RM8-9).
  - Ed25519 only; ML-DSA signing in a PD is not justified for evidence
    the SIEM receives within seconds (RM8-5). The host zeroizes the audit
    key after `tools/package` exports its public half.
- **D8: the HTTPS proxy path carries no peer identity.** Group
  authorization applies to tunnelled traffic only (SC42).
- **D9: return traffic needs a peer-opened flow** [S7]. `inner` keeps a
  bounded flow table; LAN → tunnel is allowed only on a flow a peer
  opened under its rules. Stateless return rules would let a LAN host
  reach any port on a peer's device. A LAN host that spoofs the backend's
  tuple inside a live flow is not stopped: that is the 5-tuple limit
  (RM8-10) [S16].
- **D11: the ledger is the signed history** [S15]. The ledger holds every
  signed bundle and its approval records; `sign` and `approve` re-verify
  the whole chain (signatures, `prev` links, each step's approvals under
  the roster then in force). The genesis roster digest is pinned per
  fleet in `tools/policy` (check-pins ties it), and each approver's
  `approve` keeps its own last-seen head, so truncation, roster swap and
  re-genesis are refused. Every approver keeps a full replica. A lost
  ledger is recovered by `ledger restore`: a copy is accepted only if its
  chain verifies and it contains or extends every reachable approver's
  head (version and digest), with two restore approvals under their own
  domain `kozane-ledger-restore-v1\0` binding the restored head's version,
  digest and `fleet_id`, from two distinct approvers verified under the
  roster in force at the restored head [S30]; each approver's tool refuses a copy below any
  head it has ever recorded; no flag. A wiped approver re-initialises its
  head from that restored copy [S22, S27]. The
  device's `prev_sha256` check (C5) only proves that the two slots link;
  forks need signing power, which RM8-1/RM8-7 cover [S24].
- **D10: verification and parsing are split.** `policy-wire` (depends only
  on `limits`): format, `parse`, `select`, `open`. Verification (libcrux)
  lives in the `policy` PD only, so consumers and their Kani keys do not
  depend on libcrux or `rosenpass-core` [T7].

## Contracts

Control classes follow R49. "Gate" means a fail-closed verification gate.
Forbidden patterns are enforced by `check-pins` `check_forbidden`, each
with a deny and an allow fixture, and are tripwires unless stated
[T10, S12].

### C1 — Bundle format, `policy-wire` (Critical tier)

- Bounds in `limits` (dependency-free): `MAX_PEERS = 8`, `MAX_ALLOWED`,
  `MAX_GROUPS = 8`, `MAX_RULES`, `BUNDLE_MAX`, `SPK_LEN`. `config`,
  `ingress-core`, `secret-blob`, `rosenpass-core` and `policy-wire` import
  them [T7].
- Layout: `magic "KZPP" ‖ format u16 ‖ fleet_id [16] ‖ version u32 ‖
  min_release u32 ‖ prev_sha256 [32] ‖ roster_sha256 [32] ‖ peer_count
  (1..=8) ‖ group_count (0..=8) ‖ peers ‖ groups ‖ sig_ed25519 [64] ‖
  sig_mldsa65 [3309] ‖ zero tail to BUNDLE_MAX`.
  - peer: `wg_pub [32] ‖ rp_pub [SPK_LEN] ‖ groups u8 ‖ allowed_count ‖
    prefixes`; group: `rule_count ‖ rules`; rule: `dst prefix ‖ proto
    (TCP|UDP|ICMP) ‖ port_lo ‖ port_hi`.
  - Canonical: peers ascending by raw `wg_pub` bytes, rules ascending by
    encoded bytes; exact length from the counts; the tail up to
    `BUNDLE_MAX` all zero. Anything else is `Malformed`. Slot media is
    always exactly `BUNDLE_MAX` bytes, produced by `tools/policy` [F8].
- Signed message: `"kozane-peer-policy-v1\0" ‖ body`.
- `policy-wire` API: `parse(body, node: &NodeConfig) -> Result<Bundle,
  Reject>`, called by `policy` after verification; `open(token:
  &Verified, slot: &[u8], node) -> Result<Bundle, Reject>` for consumers
  (a failure is `halt::POLICY_UNAVAILABLE`). `Bundle` is constructible
  only through these two. `NodeConfig` is a `policy-wire` type that
  `config` renders. Consumers do not re-hash the slot: no PD maps it
  writable (C11), so the bytes cannot change between `parse` and `open`,
  modulo VE3/R2 (no DMA isolation; a compromised driver could rewrite any
  frame, code included, so a re-hash would not close it) [S9, S17, F26].
- Validation: no duplicate `wg_pub`/`rp_pub`; allowed IPs non-empty,
  pairwise disjoint, not overlapping the node's inside prefix, gateway or
  neighbours (`NodeConfig`, compiled); `fleet_id` equals the node's.
- **Control class:** fail-closed gate. Adjudication: the libcrux
  verifiers (in `policy`) and this parser, over one buffer.
- **Invariants:**
  - I1.1 `parse` is total and in bounds (Kani). The harness is generic
    over the key length: proved at a small `SPK_LEN` under `cfg(kani)`,
    with a const assert that the shipped instance is the same generic
    code. Unwind bounds: `MAX_PEERS`, `MAX_ALLOWED`, `MAX_GROUPS ×
    MAX_RULES` [T5].
  - I1.2 `Bundle` has private fields; compile-fail tests for direct
    construction and for `open` without a token.
  - I1.3 `render → parse` round-trips byte-identically (bolero).
- **Forbidden pattern:** `pattern: memory_region_symbol!\(policy_[ab] —
  reason: only policy and policy-wire::open read a slot` (outside the
  `policy` PD and `policy-wire`).
- **Acceptance:** Kani I1.1; known-answer bundles from `tools/policy`;
  one fixture per `Reject` reason; Ed25519-only-bad and ML-DSA-only-bad
  fixtures [T13].

### C2 — Signing toolchain, approvals, ledger (Critical tier)

- `tools/policy`, Rust, its own workspace (libcrux out of the PD lock,
  as `tools/release`), covered by `audit` and `pins`. Subcommands:
  `render`, `diff`, `approve`, `sign`, `verify`, `ledger`.
- **Inputs:** a vendor-neutral `peers.toml` (peers, keys, allowed IPs,
  groups, rules, `min_release`); the fleet file; the ledger (D11).
- **Fleet file** [F13, F25]: generated by `tools/policy fleet` from the
  nodes' `gateway.toml` through the same `config` renderer the image
  build uses; each entry carries its `NodeConfig` digest, which
  `tools/package` also records for the node, and `verify --fleet`
  compares the two.
- **Ledger** (D11): `sign` refuses unless `prev` is the verified head and
  `version == head.version + 1`; a second body for a signed version is
  refused [S2]. The device's Equivocation and `prev_sha256` checks (C5)
  catch only forks that reach both slots.
- **Genesis:** version 0, `prev_sha256 = 0`, refused whenever the ledger
  is non-empty; still two approvals [F12].
- **Roster:** approver IDs and Ed25519 keys, distinct by ID **and** key.
  Its digest is in every bundle. A roster change is a bundle whose
  approvals verify under the previous roster. The genesis roster's digest
  is pinned per fleet (D11). `sign` takes the roster only from the
  verified ledger, never from a flag [S3].
- **Diff:** a total function of the body — every field, including
  `min_release`, rules and the roster digest; a property test asserts
  that any body change changes the diff [S8].
- **Approval record** (canonical `key=value`): `approver_id,
  body_sha256, version, fleet_id, prev_sha256, diff_sha256,
  roster_sha256, ts`, Ed25519 under `kozane-policy-approval-v1\0`. `ts`
  is informational only.
- `sign` recomputes every bound field from the bytes it signs (one
  buffer) and refuses unless ≥ 2 records from distinct roster entries
  each bind all of them. No bypass flag exists.
- **Control class:** fail-closed gate on the signer; the HSM M-of-N that
  makes it a boundary is RM8-1.
- **Forbidden pattern:** `pattern: --force|--single|skip_approval|--roster
  — reason: no single-person bypass, no caller-supplied roster`
  (`tools/policy/src`).
- **Acceptance** (each fixture red-proved): payload swapped after
  approval; same approver twice; one key under two IDs; approver not in
  roster; forged approval signature; wrong approval domain; record for
  another version / fleet / prev / diff / roster; one approval only;
  `prev` not the ledger head; second body for a signed version; version
  equal to / below / skipping prev; genesis with a non-empty ledger;
  tampered roster; truncated ledger; re-genesis; a broken chain link;
  approver head ahead of the ledger; overlap with one node of the fleet
  file; fleet digest differing from the package's; restore from a replica
  missing an approver's head; an approver head at the same version with
  a different digest; a restore approval signed under the bundle-approval
  domain; a restore below a recorded head; a single restore approval;
  the same approver twice; an approver not in the roster; an approver
  removed by a roster change before the restored head [T53]; an approval
  bound to another head version, digest or `fleet_id`; allow case [T13,
  S15, S22, S27, S30, T49].
  `POLICY-FIXTURES` in the manifest.

### C3 — NV anti-rollback state (Critical tier)

- **Index attributes** (P1 confirms) [S4, F10]:
  - `NV_POLICY_CTR`: `TPM_NT_COUNTER`, `PLATFORMCREATE`, `POLICY_DELETE`,
    `AUTHWRITE`, `AUTHREAD`, `NO_DA`, empty authValue; not `ORDERLY`, not
    `CLEAR_STCLEAR`; authPolicy = the delete policy.
  - `NV_POLICY_BASE`: ordinary, 8 bytes, the same set plus `WRITEDEFINE`.
  - Delete policy: `PolicyCommandCode(NV_UndefineSpaceSpecial) ∧
    PolicySigned(op1) ∧ PolicySigned(op2)`, two distinct operator keys
    (by key and Name) used for nothing else, fixed `policyRef` label. The
    operator signing tool signs only with the session's own non-empty
    `nonceTPM`, `expiration = 0` (no ticket), and `cpHashA = H(TPM_CC_NV_
    UndefineSpaceSpecial ‖ Name(index) ‖ Name(TPM_RH_PLATFORM))` [S13].
    The TPM binds only the key Names and `policyRef`; nonce and cpHash
    binding are a gate in that tool, which refuses an empty nonce (test),
    while the TPM refuses a cpHash computed for the other index (test)
    [S23].
  - The expected Names (with WRITTEN, and WRITELOCKED for the base) are
    computed by `tools/provision` and compiled into `[policy]` in
    `gateway.toml`; `tpm` and `tools/measure.py` read that one source.
- **Provisioning** (`tools/provision`, Python): `TPM2_Clear` (abort if it
  fails; check the SRK Name changed) [S18]; define both indices;
  increment once; `base = counter.wrapping_sub(v0)`; write and
  write-lock the base; write the `v0` bundle into slot A [F31]. `v0` is
  the verified ledger head, checked through `tools/policy verify
  --ledger`, and every provisioning needs a provisioning record
  `(fleet_id, node, srk_name, v0, body_sha256)` under
  `kozane-reprovision-v1\0`, signed **after** the Clear by two operator
  record keys (pinned per fleet like the genesis roster, distinct from the
  delete keys) and bound to this TPM's new SRK Name, so it cannot be
  replayed on another or a fresh TPM [S1, S14, S21, F29]. The record tool
  reads `srk_name` from the TPM itself and re-runs `verify --ledger`,
  refusing unless `v0` and `body_sha256` equal the head; every signer
  trusts the host's TPM read (RM8-11) [S26, S29]. If the indices
  already exist, provisioning also needs the two delete authorizations,
  then deletes and redefines them. Fixtures: replayed record; record
  bound to another SRK; one signature; the same key twice; signed by a
  delete key; wrong `fleet_id`; wrong domain; `v0`/body not the ledger
  head [T46].
- **`tpm` PD: high-level IPC on a new `policy` channel** (no
  `REQ_COMMAND` for it):
  - `REQ_POLICY_STATE` → `{current, pcr9}`: `NV_ReadPublic` both and
    compare Names; read both; `PCR_Read(9)`. Any mismatch, a logical
    version above `u32::MAX`, or `phEnableNV` clear → `RSP_REFUSED`.
  - `REQ_POLICY_ADVANCE{expected}` → re-read; increment iff `current ==
    expected`; re-read; reply the new value.
  - `REQ_POLICY_DONE` / `REQ_POLICY_FAILED`.
  - Raw clients become four (`key`, `pqkey`, `tlskey`, `auditkey`):
    `CLIENTS = 4` in the gate, `pds/tpm` and `tpm2::boot`;
    `BUSY_TIMEOUT_NS = FLOW_MAX_NS × (CLIENTS − 1)` = 360 s and its const
    assert. The allowlist gains a per-client row: `ReadClock` for
    `auditkey` only, before its Done [F18, S19].
  - `policy` is not a raw client: its requests are single bounded PPCs
    that use no handle slots and no flow ownership, so they interleave
    with raw flows; the cap barrier adds `policy`'s TPM time [F33]. The
    gate tracks it with its own `policy_finished` flag, and the cap requires every raw client
    finished **and** `policy_finished`. One STATE, at most one ADVANCE,
    then DONE/FAILED; every policy request after the cap is refused [F7].
  - `CAP_BARRIER_TIMEOUT_NS` is re-derived from the four-client busy
    bound plus P2's `policy` bound, and P2 measures with it.
- **Control class:** enforceable boundary for monotonicity (the TPM
  counter plus the two-signature delete policy); fail-closed gate for the
  Names and the flow. The grep below is a tripwire; the control is the
  gate's per-client command allowlist [S12].
- **Invariants (Kani, extending `tpm2-wire/src/proofs.rs`):**
  - I3.1 no policy operation after the cap; at most one increment per
    boot; the cap never precedes `policy_finished`.
  - I3.2 the `policy` channel reaches no raw command; `ReadClock` is
    reachable only from `auditkey`; the refused set explicitly includes `NV_UndefineSpace(Special)`, `NV_Write`,
    `NV_WriteLock`, `NV_DefineSpace`, `Clear`, `HierarchyChangeAuth`, and
    for raw clients `NV_Increment` and `NV_Read` of the two policy indices
    (each with a Kani case) [S28].
- **Forbidden pattern:** `pattern: NV_?(UNDEFINE|WRITE|DEFINE)|Clear\b
  — reason: the device never defines, writes or deletes` (`crates/`).
- **Acceptance:** Kani I3.1/I3.2; P1 facts as interop tests in
  `crates/tpm2/tests`; provisioning fixtures (Clear performed, `v0` from
  an unverified bundle refused, missing approval refused); a test-only
  fixture that, on a copy of the provisioned state and without a Clear
  (so the SRK and seals survive), deletes the counter with the two
  operator authorizations and redefines it without `POLICY_DELETE` →
  Name mismatch → `policy` Unavailable [T14, T42].

### C4 — Boot measurement of the slots (Major tier)

- Descriptor v3: six ranges (four envelopes, slot A, slot B), each
  within its kind's room (`ENVELOPE_ROOM`, `BUNDLE_MAX`), pairwise
  disjoint. Slot load addresses fixed below `0x6fb00000` (P3).
- U-Boot: validate v3 as v2 (magic, version, count, rooms, disjoint, in
  bounds); extend PCR 8 with the descriptor and image as today; extend
  PCR 9 with `sha256(A)` then `sha256(B)`; copy all six ranges; run.
- Files [F9]: `support/u-boot/boot.cmd`, `tools/uboot-config`,
  `tools/measure.py` (`COUNT`, `DESC_LEN`, pair list, per-kind room,
  `expected_pcr9`), `tools/package`, `tools/release.py`
  (`check_placeholder`, manifest), `tests/integration/run.py`
  (`Package.media()`, loader addresses, `read_pcrs` with PCR 9).
- `POLICY_PCRS` stays 9 (PCRs 0–8); a test fails if PCR 9 enters the
  selection.
- **Control class:** measurement (detection); the seal is unchanged.
- **Acceptance:** PCR 9 after boot equals the twin; a v2 descriptor is
  refused. Self-test: re-target `measure-version`, `measure-wrap`,
  `measure-range2-wrap`; one `measure-pair-*` case per new disjoint pair
  (C(6,2) − C(3,2) = 12: nine with a slot, three with the audit
  envelope) [F20]; `measure-pcr9-twin` (drop `pcr_extend 9`) [T8].

### C5 — `policy` PD (Critical tier)

- Passive PPC callee, priority 125. Never boot-stops (M7 D4); on failure
  it answers `Unavailable{reason}` for the boot. It sends DONE on success
  and FAILED on **every** other exit [F7]. Its own audit ring
  `audit_policy` (C10).
- `init`:
  1. `STATE` → `current`, `pcr9`.
  2. `pcr9 == extend(extend(0, sha256(A)), sha256(B))`, else
     `MeasureMismatch`.
  3. Per slot: verify (D1), then `parse`; candidate iff `version ∈
     {current, current+1}` (`checked_add`) and `min_release ≤
     RELEASE_SEQ`.
  4. `select(current, a, b) -> Decision` (pure, in `policy-wire`):
     - two candidates with the same version and different bodies →
       `Equivocation`; identical bodies → slot A [F14];
     - a `current+1` candidate whose `prev_sha256` equals the body digest
       of the anchor — the other slot's signature-verified bundle with
       `version == current`, whatever its floor — → `Advance{slot}`; a
       `current+1` candidate without that → `PrevMismatch`, refused like
       Equivocation rather than falling back, because the slots disagree
       about history [F24, F31, S24];
     - else a `current` candidate → `Use{slot}`;
     - else `Refuse{reason}`, by fixed precedence `BelowFloor > Skipped
       > PrevMismatch > RolledBack > BadSignature > Malformed > Empty`
       [F14].
  5. On `Advance`: `ADVANCE{current}`; the reply must equal `current+1`,
     else `Unavailable(AdvanceFailed)`, with no fallback to the older slot
     (it may carry a revoked peer).
  6. DONE; audit `PolicyAccepted{version, slot}` and
     `ReleaseSeq{RELEASE_SEQ}`, or `PolicyUnavailable{reason}`; a
     non-selected rejected slot gives `PolicyRejected{slot, reason}`.
- Serves `Await` → `Verified{slot, version, body_sha256}` or
  `Unavailable{reason}`.
- **Central invariant I5.1:** the counter advances only after the newer
  slot is present (written) and fully verified in this boot, and
  `current+1` is used only after the advance is confirmed. A crash between
  advance and use leaves `current+1` current, which the same slot
  satisfies next boot (no wedge).
- **Control class:** fail-closed gate.
- **Invariants:** I5.2 no `Verified` before step 6. I5.3 `select` is
  correct over all `(current, slot states)` combinations (Kani). I5.1 is
  proved on the init state machine with the STATE and ADVANCE replies as
  nondeterministic inputs: `Verified{version = current+1}` ⇒ an ADVANCE
  reply equal to `current+1` was received; the PD glue is a single match
  over the machine's output, pinned by check-pins [T6].
- **Acceptance:** Kani I5.1/I5.3; unit fixtures for ADVANCE refused,
  ADVANCE returning a wrong value, counter below base; C13.

### C6 — Boot barrier (Critical tier)

- **Member set (R42).** Derivation at 06b280b:
  `grep -rlE 'config::(PEERS|MAX_PEERS)|peer_rp_publics|gateway_rp_public|PEERS\.len\(\)|use config::' crates tools | grep '\.rs$'`
  → `pds/{hs,pq,ingress,data,key}`, `ingress-core`, `config`,
  `tools/mksecrets`. Plus every PD that parses traffic: `inner` (LAN);
  `tls`, whose client input comes only through `ingress` and whose
  `inner` link carries backend traffic that `inner` withholds until
  verified [S5]. Barrier set: `hs, pq, ingress, data, inner`. `key` stops
  reading peers (C7). Drivers are outside (L7, RM8-8).
- Each barrier PD calls `Await` in `init`; on `Verified` it builds its
  view with `policy_wire::open`; on `Unavailable` it boot-stops with the
  shared `halt::POLICY_UNAVAILABLE` code (a value no PD uses today) [F4].
  Frames that arrive before `Verified` queue in the driver rings, which
  drop when full; they are processed only after `Verified` [F17].
- **Control class:** enforceable boundary for "no writer" (laws over the
  `.system`); fail-closed gate for "no use before Verified" (`open` needs
  the token); the C1 forbidden pattern is a tripwire.
- **Acceptance (deny with a live control)** [T1, T30]: C13 `rolled-back`
  — both slots hold validly signed bundles refused as `RolledBack`; its
  allow twin boots the same slot bytes one version lower, where peer R
  handshakes. In the deny boot R's initiation gets no reply, a LAN frame
  reaches no backend (counted), and each barrier PD prints its `Halted`.
  Self-test injection: `hs` ignores `Unavailable` and parses slot A
  without a token; the needle is `hs` answering the initiation (a WG
  response on the wire) [T24].

### C7 — Consumers move to the bundle (Major tier)

- `config`: drop `[[peers]]`, `PEERS`, `peer_rp_publics!`; add `[policy]
  { fleet_id, ed25519_pub, mldsa65_pub, nv_ctr_name, nv_base_name }`.
  `NodeConfig` (inside prefix, gateway, neighbours) is rendered for
  `policy-wire`.
- `rosenpass-core`: `Responder::new(spkm, spkts: &[&[u8; SPK_LEN]])`
  with `len ≤ MAX_PEERS`, replacing the const-generic peer count; its
  tests and proofs follow [F6].
- `hs`: peer table from `wg_pub`. `pq`: `Responder` over references into
  the slot MR (up to 8 × ~0.5 MB; today's config has one peer, ~0.5 MB,
  compiled into `pq`) [F17]; its `GATEWAY_RP_HASH` check stays,
  `PEER_RP_HASH` goes. `data`: allowed IPs. `ingress`: `peer_count`.
- Secrets blob v3: `gateway_private, boot_seed` (per-peer hashes
  removed, so a policy update never needs a re-seal). `key` drops its
  `config::PEERS` read and `PeerMismatch` (`key-core`); `mksecrets`
  drops `--peers`; `crates/tpm2/src/envelope.rs` (`KEY_MAX_PEERS`,
  `KEY_BLOB_PER_PEER`, the size assert) and `tools/package`'s blob
  parser follow [F15].
- Harness [T9, F15]: `check_harness_matches_config` and the gateway.toml
  peer checks in `run.py` read the bundle; deployments B and C
  (`test_peer_binding`, the PeerMismatch and rp-swap cases) are rebuilt on
  bundles; `tests/tools/test_config_build.py`; the self-test needles
  `key-wipe`, `integration-pq-residue`, `c7-rndr-fault` and
  `integration-residue` are re-anchored and re-proved.
- Manifest: UNIT-CONFIG, UNIT-KEY-CORE, UNIT-MKSECRETS and
  UNIT-SECRET-BLOB fall; each decrease is recorded in the deviation log
  with the crate that takes the moved tests (`policy-wire`,
  `tools/policy`).

### C8 — Group authorization in `inner` (Critical tier)

- The `data → inner` ring carries a `msgs` record `TunnelPacket{peer:
  u8, packet}` instead of raw IPv4 (run.py reads the msgs source) [F5].
- Inbound (tunnel → LAN): `authorize(rules, peer, pkt)`: default deny;
  allow iff a group in `peer.groups` has a rule matching `(dst, proto,
  dst port)`; on allow, record the flow.
- Outbound (LAN → tunnel): allow only if the packet's reverse 5-tuple (or
  ICMP echo id) matches a live flow; the flow names the peer. Routing
  stays in `data` (D9) [S7].
- Flow table [F22, F23, S16]: `MAX_FLOWS` and `FLOW_IDLE_NS` in `limits`;
  each peer owns `MAX_FLOWS / MAX_PEERS` entries and evicts only its own
  oldest; a flow ends on idle timeout (`cpu::now_ns`), on RST seen in a
  valid direction, or after FIN in both directions plus `FLOW_LINGER_NS`.
  ICMP: rules name echo only (ports must be 0); ICMP errors are dropped
  and counted. Static storage, sized against `inner`'s stack. Const
  asserts: `MAX_FLOWS % MAX_PEERS == 0` and a quota ≥ 1, for the
  `cfg(kani)` instance too [F36].
- A peer with no groups reaches nothing.
- **Control class:** enforceable boundary within `inner`, the only PD
  that delivers to the LAN NIC (L3/L5), up to the 5-tuple limit (RM8-10).
- **Invariants (Kani, `inner-core`):** I8.1 inbound `Allow` ⇒ a matching
  rule exists; I8.2 an unknown peer id is `Deny`; I8.3 outbound `Allow` ⇒
  a live flow opened by an inbound `Allow`; I8.4 no matching rule ⇒
  `Deny`. I8.3 is over a bounded operation sequence with a small
  `MAX_FLOWS` under `cfg(kani)`; the `inner-core` re-proof time is
  measured (it is the `kani-cache` case) [T26].
- **Unit tests** [T26]: eviction at quota (only the same peer's flows),
  FIN half-close, RST from each direction, idle expiry with the clock as
  input, ICMP echo id, a reply on X's flow never leaving as peer Y.
- **Acceptance** [T15]: peer X (group G; tunnel shown up by an allowed
  request) reaches backend port P; X → port Q (listener present) is
  dropped; peer Y (no G; tunnel shown up by a request to Y's own allowed
  rule) → P is dropped; an unsolicited LAN → X packet is dropped while X's
  reply traffic passes; each drop gives `InnerDenied{peer, reason}`, and
  the backend counts frames.

### C9 — Release sequence and version lines (Major tier)

- `release-seq` crate: `RELEASE_SEQ: u32`. `tools/release` manifest
  gains `release_seq`; check-pins ties the two.
- Boot lines: `policy: accepted version=<v> slot=<A|B>` and `policy:
  release_seq=<n>`, or `policy: unavailable reason=<r> current=<n>`
  (the runbook reads it) [F4, F38].
- Encoding [F41]: `Record.b` stays the producer's lost count. Reasons and
  slots ride in code ranges, as `FRAME_DROPPED_BASE + reason` does:
  `POLICY_ACCEPTED_BASE + slot` with `a = version`; `RELEASE_SEQ` with
  `a = RELEASE_SEQ`; `POLICY_UNAVAILABLE_BASE + reason` with `a =
  current`; `POLICY_REJECTED_BASE + slot × REASONS + reason` with `a =
  version`. A refused STATE is its own reason code
  (`StateRefused`), printed as `current=unknown`; no sentinel value.
  `InnerDenied` is coalesced: `INNER_DENIED_BASE + peer × INNER_REASONS
  + reason`, `a` = running total, `b` = lost [F43]. Every range reserves
  its last code as that range's `Unknown` (a reason count + 1), and a
  peer id ≥ `MAX_PEERS` maps to one `INNER_DENIED_UNKNOWN` code outside
  the range, so clamping never lands on a real reason [F45]. Cases in
  `audit-event` [T50, T56, F47]: per slot and per peer, the last real
  reason decodes as itself and the reserved last code decodes as
  `Unknown`; an out-of-range reason encodes to that reserved code; an
  out-of-range peer encodes to `INNER_DENIED_UNKNOWN`; every range and
  `INNER_DENIED_UNKNOWN` join the disjointness test; `StateRefused`
  prints `current=unknown` whatever `a` holds; Kani over the
  encode/decode pair.
- **Control class:** floor: fail-closed gate (C5 step 3); lines:
  detection.
- **Acceptance:** release verify rejects a manifest whose `release_seq`
  differs from the source; unit boundary triple for `min_release` below /
  equal / above `RELEASE_SEQ` [T17]; the `BelowFloor` integration row is
  C13's only.

### C10 — SIEM export, `auditkey` (Major tier)

- New audit source `policy` (ring, channel, name in `layout::audit`, the
  `Source` array); `auditkey` status comes through its PPC replies
  [F19]. New events with code ranges,
  names, decode, printer and Kani count in `audit-event`:
  `PolicyAccepted`, `PolicyRejected`, `PolicyUnavailable`, `ReleaseSeq`,
  `InnerDenied`, `Checkpoint` [F4].
- `auditkey`: passive key-role PD, caller `audit` only, envelope kind
  `audit` (`mksecrets`, `tools/package`, a fourth raw `tpm` client), `rng`
  client (D7).
- Every printed line ends in the trailer ` seq=<n>` before CRLF. `audit`
  keeps `h = SHA-256(h ‖ line)` (line without CRLF) from the constant
  `h0 = SHA-256("kozane-audit-v1\0")`; boot ID, reset and restart are
  bound only in signed checkpoints [F21]; the signed `seq` is the
  checkpoint line's own trailer value. run.py's UART reader and the
  check-selftest needles strip the trailer (anchored at `/ seq=\d+\r?$/`)
  in one function that returns a derived view; the raw text is kept for
  `audit-verify` and for one self-test case whose needle reads it
  [T41, S25]. Existing regexes (`READY_LINE`, `Halted reason=`, `src=`) keep their form; the
  file list includes run.py, check-selftest and audit-verify [F27, T28].
- `auditkey` notifies `audit` on their channel at the end of its init;
  `audit` sends no PPC to `auditkey` before that notification [F32].
  Before that, or if it is unavailable, it prints `audit: checkpoint
  boot=unavailable chain=<h> lost=<total> sig=unavailable reason=<r>`
  [F2].
- Every `CHECKPOINT_EVERY` lines (a `layout` constant) and once all PDs
  are ready: `audit: checkpoint srk=<name> boot=<id> reset=<r>
  restart=<s> chain=<h> lost=<total> sig=<hex>` (its trailer carries the
  signed `seq`). `lost` is the running sum of every
  source's `lost`.
- `tools/audit-verify`: recomputes the chain; verifies checkpoints with
  the device's audit public key (exported by `tools/package`); reports
  sequence holes, `lost > 0`, "N unverified lines after the last
  checkpoint", and `reset/restart` gaps across boots under the
  continuity rule below [T12, S11, S18, S26, T57];
  a boot with no signed checkpoint, or two checkpoints whose `seq` does
  not strictly increase, fails [S20, S25]; extracts the C9 lines.
- **Control class:** detection or audit only.
- **Acceptance:** fixtures: deleted, reordered and edited lines; forged
  checkpoint; checkpoint from another boot; wrong device key; `lost > 0`;
  unsigned checkpoint; unverified tail; a missing boot (reset jump); a
  clean capture; the continuity fixtures below.
  One integration capture, from a single boot started at 0, verified end
  to end with the packaged key and the run's provisioning record.
  Continuity rule [S31, S32, F46, T54]: every capture needs `--after
  <last signed checkpoint of the previous capture>`, except the first
  capture after provisioning, which needs `--from-provisioning
  <record>`. The record carries `reset_at_provision`, the `resetCount`
  `tools/provision` reads as its last TPM act; the capture is accepted
  only if the record's `srk_name` matches, its first boot has `reset =
  reset_at_provision + 1` and `restart = 0`, and its first signed
  checkpoint is the ready one [S34]. P1 confirms the "+1"; if it does
  not hold, the reset check and the S34 later-cold-boot fixture are
  dropped and the flag rests on the custodian alone (RM8-12) [T58]. The `--after` anchor is itself verified
  (signature under the device key, matching `srk_name`), and the
  capture's first checkpoint must be its successor [F48], exactly one
  of:
  - the same `boot_id`, `reset` and `restart`, the first line's `seq` =
    the anchor's `seq + 1`, and the chain resumed from
    `SHA-256(anchor.chain ‖ anchor line)` — a checkpoint's printed
    `chain` precedes its own line (a capture split inside one boot)
    [F50, F51, S35];
  - a new `boot_id`, `reset + 1`, `restart = 0` (a TPM Reset: cold boot);
  - a new `boot_id`, the same `reset`, `restart + 1` (a TPM Restart).
  Anything else is a gap. The baseline is always printed (`baseline
  srk=… reset=… restart=… seq=…`). Fixtures: matching record with the
  flag (allow); record without the flag; mismatched `srk_name` [T52];
  the flag on a later cold boot (`reset` above the expected value,
  `restart = 0`, ready first checkpoint) [S34]; the flag on a mid-boot
  or post-Restart start (`restart ≠ 0`, or a first checkpoint that is not
  the ready one) [F49]; forged and wrong-key `--after`; each successor
  case (allow), a reset jump (deny), and a split capture with a line
  deleted just after the anchor (deny) [F48, F50]; the printed baseline line
  asserted [T55].
  Cross-boot reset continuity is asserted on fixtures only, because
  harness TPM inspections are TPM Resets [T12, T45, F39, T48].
- `auditkey` [T27]: unit tests for the seq rule, overflow and the
  ready exemption (`auditkey-core`, Kani over the parser); an integration
  boot with the audit envelope sealed to other PCRs (the unsigned form);
  two boots give distinct boot IDs; ready-gating: `audit`'s checkpoint
  scheduling is a host-testable state machine in a new crate
  `audit-core`, used only by `pds/audit` [F42]. Its only "call
  `auditkey`" action follows the ready input, and
  `ready_input(channels) -> bool` decodes that input from the
  `layout` auditkey→audit channel alone. Unit tests: a fake `auditkey`
  sees no call before ready (red-proved by removing the gate);
  `ready_input` is true for that channel only and false for every other.
  check-pins requires that the PD passes channels only through
  `ready_input` and has a single PPC site, the machine's action, with
  deny fixtures (a `pp_call` outside the arm; a helper wrapping it) and an
  allow fixture, plus a deny fixture where the PD compares the auditkey
  channel directly instead of calling `ready_input` [T37, T44, T47, T51].

### C11 — Laws amendments (Critical tier; other contracts lean on it)

Each rule gets a deny and an allow fixture with an exact rule ID [F3]:

- **L6** as D4: configuration enters at build, or as a signed, measured,
  read-only boot MR that no PD uses before `policy` has verified it.
- Key role: `auditkey` is a key PD with one PPC caller (`audit`) and only
  its own secrets MR (no audit ring), plus a notify to `audit` at the end
  of init; the key rules are otherwise unchanged [F19, F32].
- Role `Policy`: passive; PPC callers exactly the barrier set; channels
  to `tpm` (policy channel) and `audit` only. Its callers are tainted, so
  it gets the callee-exemption shape the key PDs have
  (`channel_is_exempt`); its parser is under Kani (C1).
- `tpm` role: channels to key PDs (raw) and `policy` (high-level) only.
- Priority: `untrusted_input < policy < tpm`; `audit < auditkey`.
- MR kind `bundle_slot`: `prefill`, no `w` mapping anywhere, `r` for
  `policy` and the barrier set only; the "prefill only on secrets MRs"
  rule admits this kind.
- Registration: `supervisor-core` `CHILDREN` (+`policy`, `auditkey`),
  the PD ids, `tools/supervisor-allowlist`, `layout` channel ids and
  their tests [F15].

### C12 — Operations documents (Major tier)

- `docs/operations/peer-policy-runbook.md`: issue → two approvals →
  sign → write the slot **not** named in the node's last `accepted
  slot=` line (for an Unavailable node: slot A gets v(current) from its
  `current=` line, slot B
  the new version), exactly `BUNDLE_MAX` → drain → reboot
  → version check (C9 lines via SIEM) → rejoin. At 15 min, nodes not on
  the new version leave the LB and lose direct reachability, no
  exceptions; HA is a prerequisite. The same procedure for code patches
  (`release_seq`). Recovery: replay skipped versions one reboot each;
  on `PrevMismatch`, restore v(current) from the ledger into the other
  slot; on `StateRefused` (`current=unknown`) write no slot, diagnose the
  TPM/NV state, and re-provision if the indices are wrong [F44]; or
  re-provision (two operator signatures). Genesis,
  roster-change and ledger-restore ceremonies.
- `docs/operations/audit-map.md`: who / from where / when / record → the
  contract and the test ID; ZTA roles: PEP = gateway (`policy`,
  `ingress`/`hs`, `inner`), PDP = management service + two-person
  signer, PIP = IdP, MDM, SIEM.
- **Acceptance:** a check-pins rule fails on a test ID the tree does not
  contain.

### C13 — End-to-end policy update (Major tier)

- **Fixtures** [T14]: per run, in tmp: policy keys, approver keys,
  roster, ledger, operator delete keys; bundles made through `render` /
  `approve` / `sign` (no test signer). A second body for a signed
  version is signed from a ledger forked one version below it: v1′ (the
  floor-raised v1) and v1″ (floor within `RELEASE_SEQ`, a different peer
  set) from forks at head v0; the `prev-mismatch` v2 from v1′'s fork
  [T20, F28, F34, T40, F37, T43]. Operator delete and record keys are
  per-run fixtures too [F40]. Public keys and NV Names
  compile into that run's image, as fresh deployments already do. Slots
  are written into per-boot copies, never into the shared `Package`.
- **Swtpm lifecycle** [T4, T21, T35]: provisioning runs once, at v0 = 0,
  and every package seals once to that SRK. Each case starts from a copy;
  a higher starting version is made by a named helper,
  `tpm_start_at(copy, k)`: start swtpm on the copy, `CMD_INIT`,
  `CMD_SET_DATAFD`, `TPM2_Startup(CLEAR)`, `NV_ReadPublic` with the Name
  check, `NV_Increment` k times (password session), read back and assert
  the logical value, `Shutdown(CLEAR)`, stop, hand the permall over. P1
  covers the same sequence [T36]. Between the boots of one case `Swtpm.close()`
  keeps `tpm2-00.permall` in a case-scoped directory, removed in
  `finally`; the "no surviving state" check runs there too.
- **Counter check** [T2, T25]: after every boot, once QEMU is killed and
  before `close()`, the harness reads `NV_POLICY_CTR` (password session,
  Name checked) and asserts the expected logical value.
- Cases, each named so `KOZANE_IT_BOOTS` selects one:

| Case | Start | Slot A | Slot B | Expect | Counter |
|---|---|---|---|---|---|
| advance-revoke | 0 | v0 (P, R) | boot 1: empty; boot 2: v1 (R only) | boot 1: accepted 0, A; P and R handshake. Boot 2: accepted 1, B; P refused, R handshakes | 0, then 1 |
| restore-old | 1 | v1 | v0 | accepted 1, A; `PolicyRejected{B, RolledBack}`; R handshakes | 1 |
| rolled-back (C6 deny) | 2 | v0 | v1 | unavailable `RolledBack`; R's initiation unanswered. Allow twin: the same slots at start 1 → accepted 1, B; R handshakes | 2 |
| skipped | 1 | v1 | v3 | accepted 1, A; `PolicyRejected{B, Skipped}`. Then A empty: unavailable `Skipped` | 1 |
| equivocation | 1 | v1 | v1″ | unavailable `Equivocation`; allow twin `restore-old` [F35, T40] | 1 |
| prev-mismatch | 1 | v1 | v2 whose `prev` is v1′ | unavailable `PrevMismatch`; allow twin `crash-after-advance`'s second boot | 1 |
| no-anchor | 1 | empty | v2 | unavailable `PrevMismatch`; recovery: write v1 into A → accepted 2, B [F31] | 1, then 2 |
| floor-lowering | 1 | v1′ (floor raised) | v2 (`prev` v1′, floor lowered) | accepted 2, B: the anchor counts whatever its floor [F31] | 1 → 2 |
| half-bad | 1 | v1 | v2, bad ML-DSA; second boot: v2, bad Ed25519 | each boot: accepted 1, A; `PolicyRejected{B, BadSignature}` [T38] | 1 |
| below-floor | 1 | v1′ (`min_release = RELEASE_SEQ+1`) | empty | unavailable `BelowFloor`; allow twin `restore-old` | 1 |
| crash-after-advance | 1 | v1 | v2 | `fi_policy` image: marker after confirmed ADVANCE, no `accepted` line, harness kills QEMU (counter 2); then the normal image on the same state: accepted 2, B | 1 → 2 |
| measure-mismatch | 1 | v1 | empty | `TpmProxy` swallows the second PCR 9 extend with success: unavailable `MeasureMismatch`; secrets still unseal (PCR 9 is not sealed) [T22] | 1 |

  - `fi_policy` is a fault-inject package variant (the
    `FAULT_INJECT_VARIANTS` precedent) with its own sealed envelopes. It
    prints a marker after a confirmed ADVANCE and stops before selecting;
    it sends no DONE, so the harness kills QEMU at the marker.
    `test_release_boot` checks every `FAULT_INJECT_VARIANTS` image hash
    against the manifest, not only `fi_net`'s [T3, T23].
  - Every deny row asserts the counter unchanged and has a live control
    in the same case or its allow twin (a peer that handshakes) [T2].

## Consumer-flow walkthroughs

- **`Bundle` → `hs`** reads `{peers[].wg_pub}` and builds `Peers`; the
  index is the peer id that `data`, `ingress` and `inner` use.
- **→ `pq`** reads `{peers[].rp_pub}` as `&[u8; SPK_LEN]` into the MR, a
  slice of `peer_count` for `Responder::new`.
- **→ `data`** reads `{peers[].allowed}` for `classify` and routing, and
  writes the peer id into `TunnelPacket`.
- **→ `ingress`** reads `{peer_count}` to bound endpoints.
- **→ `inner`** reads `{peers[].groups, groups[].rules}` and
  `TunnelPacket.peer` for C8.
- **`Verified{slot, version, body_sha256}` → barrier PDs:** `slot` picks
  the MR; `version` and `body_sha256` are for audit.
- **STATE → `policy`:** `current` for `select`, `pcr9` for step 2.
- **Checkpoint line → `tools/audit-verify`:** `{boot, reset, restart,
  seq, chain, lost, sig}` and the preceding lines; the key from
  `tools/package`.
- **C9 lines → runbook version check:** `{version, release_seq}`.
- **Ledger → `sign`:** `{head version, head body_sha256, roster}`.

## Testing strategy

| Layer | What | Classification |
|---|---|---|
| Unit / bolero | `policy-wire` parse/render/select, `inner-core` authorize and flows, `release-seq`, secret-blob v3, the rosenpass `Responder` slice API | verifiable-local |
| Kani | I1.1, I3.1, I3.2, I5.1, I5.3, I8.1–I8.4 | verifiable-local |
| Compile-fail | `Bundle` and token construction | verifiable-local |
| Tool fixtures | `tools/policy` (C2), `tools/audit-verify` (C10), `tools/provision` (C3), measure/release | verifiable-local |
| Laws | C11 fixtures | verifiable-local |
| Integration | C6, C8, the C10 capture, C13; existing groups on bundle-sourced peers | verifiable-local |
| Self-test | listed below | verifiable-local |
| HSM, IdP/MDM, LB/SIEM | RM8-1…RM8-3 | blocked-deferred (VE17–VE19) |

New self-test injections, each with a failure-only needle and the case
that catches it [T18, T29]:

| Injection | Caught by |
|---|---|
| PCR 9 check removed | `measure-mismatch` |
| ADVANCE on the parsed version before verification | `half-bad`; needle: the counter assertion's failure text ("logical 2, want 1") [T39] |
| Ed25519 check skipped; ML-DSA check skipped | `half-bad` second / first boot [T38] |
| anchor floor check added (anchor must pass the floor) | `floor-lowering` |
| Name check skipped | C3 wrong-Name integration case |
| cap not waiting for `policy_finished`; policy request after the cap accepted | Kani I3.1 (deterministic, no ordering) |
| `authorize` defaulting to Allow; outbound without a flow | C8 integration denies, Kani I8.1/I8.3 |
| Equivocation branch removed | `equivocation` |
| `prev` check removed | `prev-mismatch` |
| `hs` ignoring `Unavailable` | C6 (`rolled-back`) |
| `auditkey` seq rule removed | `auditkey-core` unit/Kani |
| ready gate removed; `ready_input` on any channel; a second PPC site | `audit-core` units; check-pins fixtures [T47] |
| `sign` accepting one approval; ledger chain check removed | C2 fixtures |
| each new forbidden pattern | check-pins fixtures |
| C4 `measure-*` | C4 |

The `cap-barrier-skipped` needle is re-checked.

Manifest and wiring [T16, T32]: totals KANI-HARNESSES and UNIT-TESTS;
KANI- and UNIT-POLICY-WIRE, -AUDITKEY-CORE, -INNER-CORE, -TPM2-WIRE,
-AUDIT-EVENT, -ROSENPASS-CORE; UNIT-AUDIT-CORE, UNIT-RELEASE-SEQ, -LAWS, -LAYOUT, -TPM2,
-SWTPM-INTEROP, -SUPERVISOR-CORE, -SUPERVISOR-ALLOWLIST; LINT-PDS 16 →
18; `host_crates` + `policy-wire`, `auditkey-core`, `release-seq`
+ `audit-core` (LINT-CRATES 35 → 39); MIR-CRATES, REPRO-ARTIFACTS, BOLERO-TARGETS,
INTEGRATION-CASES; POLICY-, AUDIT-VERIFY-, PROVISION-, PACKAGE-,
CONFIG-BUILD-, RELEASE-, MEASURE- and CHECK-PINS-FIXTURES,
CHECK-PINS-RULES; the fixture regex in Makefile `pins`; `audit` over
`tools/policy`'s lock; `policy-wire` and `auditkey-core` in
`kani_crates`; `CASES_FOR_GATE` for every new gate. The I5.1 state
machine lives in `policy-wire` [T33].

Scheduling (owner rules):

- `policy-wire` and `limits` add no libcrux; the `policy` PD does. The
  PD lockfile changes once (slice 3), which invalidates every Kani key
  (~13 h). The tail of `kani_crates` (`tpm2-wire tls-wire http-wire`
  onward) runs on z1mn from the start; never two Kani jobs on one host.
- New QEMU cases run on the host not running solvers. During the
  re-proof, slice 3's boots wait for z1mn's (shorter) tail to finish, then
  run on z1mn while gx10 completes the head [T34]. Each self-test case
  stays under `CASE_TIMEOUT_S` (P5).
- Gates → boots → red-proofs, then commit.

## Residuals (RM8)

- **RM8-1.** No HSM (VE17): whoever holds the dev policy key signs alone.
  Close: HSM with M-of-N.
- **RM8-2.** Approver identity is a key, not a corporate identity with a
  factor (VE18). Close: IdP-bound approval.
- **RM8-3.** SLA eviction is a runbook (VE19), and a media attacker can
  withhold an update (A13). Worst case: a non-compliant node serves a
  revoked peer until it is evicted and cut off.
- **RM8-4.** Platform auth is empty on QEMU (VE20): replaced boot code
  can `TPM2_Clear` (DoS: the SRK changes, envelopes die) but cannot
  delete the indices without two operator signatures. On a board the
  platform firmware must keep `phEnableNV` set and own platform auth,
  and the operator holds lockout auth for provisioning's Clear [S18].
- **RM8-5.** Checkpoints are Ed25519 only (D7); mitigated by SIEM receipt
  timestamps.
- **RM8-6.** An unauthorized counter increment (A10 or a compromised
  `tpm`) wedges the node forward. DoS; recover by re-provisioning.
- **RM8-7.** Collusion of two approvers, HSM compromise, or two approval
  devices compromised at once (owner-listed); likewise for the two
  operator delete keys.
- **RM8-8.** The drivers stay outside the barrier: a bug in an older
  release's driver copy path is reachable under the release floor.
- **RM8-9.** A compromised `audit` can obtain the current boot's
  checkpoints over chains it fabricates; it cannot sign for another boot.
- **RM8-10.** A LAN host spoofing a backend's tuple can inject into a
  live flow (the 5-tuple limit, D9).
- **RM8-11.** Every record-key holder trusts the provisioning host's
  unauthenticated TPM read of `srk_name` (no EK certify or Quote while
  SC31 is deferred), present at the host or not; a compromised
  provisioning host can bind an SRK Name of its choosing [S29].
- **RM8-12.** The first capture after provisioning is trusted to start
  at the first boot on its custodian's word (`--from-provisioning`);
  later captures chain by signed checkpoints.

## Scope contract

| ID | Deferred | Owner |
|---|---|---|
| SC31 | TPM2_Quote (PCR 9 is quotable input) | unscheduled |
| SC33 | Closed by D5 / C9 | M8 |
| SC42 | Identity on the HTTPS proxy path (D8) | unscheduled |
| SC43 | PolicyAuthorize, calendar expiry, more than 8 peers (owner exclusions) | out of M8 |
| SC44 | The management service (PDP); M8 ships the signer, ledger and verifiers | unscheduled |

## User operation scenarios

1. **Revoke a stolen laptop.** Draft v(n+1) without the peer; two
   approvers on separate devices approve the diff; `sign` checks the
   ledger head; the update tool writes the inactive slot fleet-wide; nodes
   drain, reboot, print `accepted version=n+1` and rejoin. At 15 min the
   rest leave the LB and are cut off.
2. **A single insider** edits the draft after approvals, approves twice,
   passes a roster, rebases on v(n−1), or truncates the ledger: `sign` or
   `approve` refuses each. With the dev key in a file (RM8-1) the insider
   holding it can still sign alone; the HSM closes that.
3. **A media attacker restores last month's bundle:** the node keeps the
   current one, or prints `unavailable reason=RolledBack` if both slots
   are old.
4. **Emergency patch for a VPN bug.** A new release with
   `release_seq+1`, then a bundle raising `min_release`; same 15-min
   procedure. A node reflashed with the old release stays closed
   (`BelowFloor`).
5. **Bad release.** Fix forward, or a two-person-approved bundle lowering
   `min_release`.
6. **Audit.** The SIEM verifies chain, checkpoints and boot continuity;
   the auditor reads `audit-map.md`.

## Go/No-Go Gate

| ID | Subject | Status |
|---|---|---|
| C1 | Bundle format, `policy-wire` | locked |
| C2 | Signing toolchain, approvals, ledger | locked |
| C3 | NV anti-rollback state | locked |
| C4 | Boot measurement of the slots | locked |
| C5 | `policy` PD and selection | locked |
| C6 | Boot barrier | locked |
| C7 | Consumers move to the bundle | locked |
| C8 | Group authorization in `inner` | locked |
| C9 | Release sequence and version lines | locked |
| C10 | SIEM export, `auditkey` | locked |
| C11 | Laws amendments | locked |
| C12 | Operations documents | locked |
| C13 | End-to-end policy update | locked |

Slice order:

0. Probes P1–P5.
1. C1 (`limits`, `policy-wire`), C2 (host only; no PD lock change).
2. C3, C4.
3. The PD lockfile change (libcrux into `policy`), C5, C11, C6, C7; the
   Kani re-proof split across gx10/z1mn starts here.
4. C8, C9.
5. C10.
6. C12, C13, the solo `make check`, then the split self-test.

## Implementation Checklist

Appended slice by slice (Step 2-1); each slice's list is written before its
code.

### Slice 1 (C1, C2)

- `crates/limits`: add `MAX_PEERS` (8), `MAX_ALLOWED` (8), `MAX_GROUPS`
  (8), `MAX_RULES` (16), `SPK_LEN` (524 160), `BUNDLE_MAX` (`0x480_000`),
  each with the reason it has that value; unit tests.
- New `crates/policy-wire` (no_std, depends on `limits` only): format,
  `parse`, `render` (host feature), `select`, the init step machine (I5.1),
  `open`, `NodeConfig`, `Reject`; `proofs.rs` (I1.1 generic over the key
  length, I5.1, I5.3), `tests.rs`, compile-fail tests (I1.2), one bolero
  target (I1.3).
- Reuse, do not re-implement:
  - `config::Prefix::contains` and `validate.rs`'s `range()` overlap rule
    (`crates/config/src/validate.rs:86`) move into `policy-wire`'s
    `Prefix`, and `config` re-uses it;
  - `config::MAX_PEERS` (`validate.rs:279`), `ingress_core::RP_MAX_PEERS`
    (`ingress-core/src/lib.rs:955`) and `rosenpass_core::SPK_LEN`
    (`rosenpass-core/src/kem.rs:9`) become imports of, or const asserts
    against, `limits` (R2).
- `NodeConfig` fields, from `config`'s current checks
  (`validate.rs:286-…`): inside prefix, inside IP, outside IP, neighbour
  IPs, the gateway's WireGuard public key (a peer may not use it), and the
  gateway's rp digest. The digest is BLAKE2s, already rendered as
  `rp_hash`, and the caller supplies it as a digest function so that
  `policy-wire` takes no hash dependency.
- Root `Cargo.toml` `members`, `Makefile` `host_crates` and
  `kani_crates`, and `tests/manifest.txt` (UNIT-/KANI-POLICY-WIRE,
  UNIT-LIMITS, LINT-CRATES, BOLERO-TARGETS).
- New `tools/policy` (own workspace, `libcrux-ml-dsa =0.0.11` with
  `std, mldsa65`, `libcrux-ed25519 =0.0.10`, as `tools/release`):
  `render, diff, approve, sign, verify, ledger, fleet`;
  `tests/tools/test_policy.py` (POLICY-FIXTURES); `Makefile` `pins` and
  `audit` wiring; check-pins forbidden patterns for C1 and C2.
