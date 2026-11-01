# Peer-policy runbook

For the gateway fleet's operators and its two approvers. It covers who
holds which key, how a fleet and a node are set up, how a policy change or
a code patch reaches every node within 15 minutes, and how to recover from
each refusal the gateway prints. Contract IDs (C1–C13, D1–D11, RM8-n) are
those of [the M8 plan](../archive/review/kozane-m8-peer-policy-plan.md), as
amended by [its deviation log](../archive/review/kozane-m8-peer-policy-deviation.md).
Auditors start from [the audit map](audit-map.md).

`policy` below is the binary `make policy-tool` builds
(`build/policy/target/release/policy`). Console lines are shown without the
` seq=<n>` trailer every `audit` line carries.

## Roles and keys

The gateway is the policy enforcement point (PEP): it verifies and enforces
a signed bundle and decides nothing itself. The decision point (PDP) is the
management service (not part of M8, SC44) and the two-person signer
`tools/policy`. The information points (PIP) are the IdP, the MDM and the
SIEM.

| Who | Holds | Where | Used for |
|---|---|---|---|
| Signing operator | the bundle signing key pair, Ed25519 and ML-DSA-65 (`policy keygen`) | target: an HSM with M-of-N custody. Today: dev key files outside the repository (RM8-1) | `policy sign`; its public halves are compiled into every node's image (`[policy]` in `gateway.toml`) |
| Approver 1, approver 2 (and any further roster members) | one Ed25519 approval key each (`policy approver-keygen`), a full ledger replica, and a head file | each on their own device; never on the signing host | `policy approve`, `policy ledger approve-restore` |
| Record operator 1, record operator 2 | one Ed25519 provisioning-record key each (PEM) | each on their own device; public halves pinned per fleet in `tools/provision-record-keys` | `tools/provision record-sign` |
| Delete operator 1, delete operator 2 | one ECC P-256 NV delete key each (PEM) | each on their own device; never a record key, never used for anything else | the indices' delete policy; `tools/provision nv --delete-keys` at re-provisioning |
| Release operator | the release signing keys (`make release-keys`), separate from the bundle keys (D1) | as today (RM5-1) | `make release` |
| SIEM | each node's `audit.pub` (from `make package`) and provisioning record | the SIEM | `tools/audit-verify` |

No person holds two of these roles for the same fleet. The two approvers,
the two record operators and the two delete operators are distinct people
on distinct devices: every collusion of a pair is residual RM8-7.

## Genesis ceremony (once per fleet)

1. Each approver, on their own device:
   `policy approver-keygen --dir <new dir> --forbid <repository>`. They hand
   over `ed25519.pub` only.
2. The roster, `roster.toml`, one entry per approver (IDs and keys
   distinct):

   ```toml
   [[approver]]
   id = "alice"
   ed25519_pub = "<64 hex>"
   ```

3. `policy roster-digest roster.toml` prints the digest. Each approver
   recomputes it on their own copy and confirms it aloud. The digest goes
   into `tools/policy/genesis-roster.sha256` in the fleet's build, and
   `make policy-tool` rebuilds the tool. The pin is compiled in (D-4): the
   shipped all-zero file makes every command fail closed, and no flag
   replaces it.
4. The signing operator: `policy keygen --dir <new dir> --forbid
   <repository>` (dev keys; on an HSM, the HSM's ceremony instead).
5. The fleet file, from every node's `gateway.toml` (the file stem is the
   node's name):
   `policy fleet --out fleet.toml --fleet-id <32 hex> <gateway.toml>...`.
   Each node's `gateway.toml` comes from `mksecrets --template
   config/gateway.toml --out <dir>`.
6. `policy ledger init --dir <ledger> --genesis-roster roster.toml`.
7. Version 0 follows "Issuing a policy change" below: it is genesis
   (`prev_sha256` zero) and still needs two approvals.
8. Record keys: each record operator creates an Ed25519 key
   (`openssl genpkey -algorithm ed25519 -out record.pem`) and hands over
   its raw public key, the last 32 bytes of
   `openssl pkey -in record.pem -pubout -outform DER`, in hex. One line per
   key goes into `tools/provision-record-keys`:
   `<fleet_id> <ed25519 public key>`. With no line for a fleet,
   `tools/provision` refuses every record.
9. Delete keys: each delete operator creates a P-256 key
   (`openssl ecparam -name prime256v1 -genkey -noout -out delete.pem`) and
   hands over `openssl ec -in delete.pem -pubout -out delete.pub.pem`.
10. Every approver takes a full replica of the ledger.

## Provisioning a node

Provisioning always starts with `TPM2_Clear`: the SRK changes, so no
envelope sealed before it unseals afterwards. That is what keeps every
pre-M8 release closed (SC33, D5), and it is not a step that can be
skipped: steps 2 and 4 refuse a TPM whose resetCount or restartCount is
not 0, which only that Clear leaves, so steps 1 to 4 run in one TPM
session with no reboot in between. It also means the node's package must
be re-made after every provisioning.

1. Clear, EK certificate check, SRK:
   `tools/provision --tcti TCTI --ek-root CERT --ek-intermediates CERTS --out srk.pub`.
2. The record, read from this TPM after the Clear:
   `tools/provision record --tcti TCTI --ledger <ledger> --keys-pub <keys> --node <name> --out <name>.record`.
   It holds `body_sha256`, `fleet_id`, `node`, `reset_at_provision`,
   `srk_name` and `v0`; `v0` and `body_sha256` are the head of a ledger
   `policy verify --ledger` accepts.
3. Each record operator checks the record (this fleet, this node, `v0` the
   ledger head) and signs it:
   `tools/provision record-sign --record <name>.record --key record.pem --out <name>.record.sig<N>`.
   Both signers trust the host's TPM read of `srk_name` (RM8-11).
4. The NV state and slot A:
   `tools/provision nv --tcti TCTI --ledger <ledger> --keys-pub <keys> --node <name> --record <name>.record --record-sigs SIG SIG --delete-pub delete1.pub.pem delete2.pub.pem --slot-a slot-a.bin`.
   It refuses unless both signatures are by two distinct pinned record keys
   and every field matches this TPM and the ledger head. It defines
   `NV_POLICY_CTR` and `NV_POLICY_BASE` under the platform hierarchy with
   the two-key delete policy, sets the logical version to `v0`, writes
   the head bundle into `slot-a.bin` (exactly `BUNDLE_MAX` bytes), and
   prints `nv_ctr_name`, `nv_base_name` and `reset_at_provision`. If the
   indices already exist it needs both delete operators' keys,
   `--delete-keys delete1.pem delete2.pem` (in `--delete-pub`'s order), and
   refuses without them.
5. `[policy]` in the node's `gateway.toml`: `fleet_id`, `ed25519_pub`,
   `mldsa65_pub`, and the two Names it printed. Then `make image` with
   `KOZANE_CONFIG` naming that file, and `make package` with
   `SRK_PUBLIC=srk.pub` and the node's four secrets blobs. Zeroize the
   audit blob once the package has exported `audit.pub`. The package also
   holds `node.sha256`, the digest of the node's `NodeConfig` as the image
   compiles it (C2). Check it against the fleet file:
   `policy verify --fleet fleet.toml --package-node <package>/node.sha256`
   names the node, or refuses when the fleet file does not describe this
   image (a stale fleet file, a `gateway.toml` edited after `policy fleet`,
   or another `fleet_id`). Regenerate the fleet file and re-render before
   signing anything for the node.
6. Slot B starts as `BUNDLE_MAX` zero bytes.
7. The SIEM gets `audit.pub` and `<name>.record`. Its first capture of the
   node is checked with `--from-provisioning` (below).

Under QEMU the node is booted with
`make run PKG=<package> TPM_STATE=<swtpm state> SLOT_A=<slot A> SLOT_B=<slot B>`.

## Issuing a policy change

Every change, revocation included, goes through the same steps. There is
no bypass: `sign` refuses fewer than two approvals from distinct roster
entries, an approval bound to any other body, version, fleet, `prev`, diff
or roster, and a version other than the ledger head + 1 (C2). A revocation
is "a bundle without that peer", nothing faster.

1. Draft `peers.toml` (peers with `wg_pub`, `rp_pub_path`, `allowed_ips`,
   `groups`; groups with rules; `min_release`; `fleet_id`) and render it:
   `policy render --input peers.toml --fleet fleet.toml --ledger <ledger> --out draft.bin`.
   `render` checks the draft against every node of the fleet file as the
   device would.
2. Each approver, on their own device and their own replica:
   `policy verify --ledger <replica> --keys-pub <keys>`, then
   `policy diff --ledger <replica> --draft draft.bin`. (`approve` re-checks
   the chain, the roster and the approvals but not the bundle signatures,
   because an approver need not hold the public keys; `verify --ledger`
   does.)
3. Each approver checks, independently:
   - the diff line by line: every peer line (`peer <wg_pub> rp=<digest>
     groups=<indices> allowed=<prefixes>`) and rule line (`rule
     group=<index> <dst> <proto> <ports>`) marked `+` (added) or `-`
     (removed; a changed peer is its old line removed and its new one
     added), `min_release`, and `roster_sha256`. Group indices are the
     order of `[[groups]]` in `peers.toml`. Check each new `rp=` against
     the peer's own key file with `policy rp-digest <file>`;
   - when `roster_sha256` changes: get the new `roster.toml` from the
     drafter, check that `policy roster-digest <roster.toml>` prints the
     new `roster_sha256`, and check every entry (id and key) against the
     IdP. The diff shows only the digest;
   - that each change matches a request they can trace to the IdP and MDM
     (a peer's device and owner), not just to the person who drafted it;
   - that the version is the ledger head + 1.
4. Each approver approves:
   `policy approve --ledger <replica> --draft draft.bin --diff-sha256 <the diff_sha256 line they reviewed> --approver-key <key> --approver-id <id> --head <own head file> --out <id>.approval`.
   `approve` prints the diff again and refuses unless it is the one
   reviewed.
   The head file is the approver's own record of the newest ledger head
   they have verified and of the last version and body they approved.
   `approve` refuses a ledger that is behind that head or disagrees with
   it, and a ledger that does not hold the version they last approved, or
   holds another body at it: that version was either signed and cut off
   this ledger (truncation), signed in a fork, or abandoned (another draft
   was signed instead). Only the approver can say it was abandoned, by
   passing that approval back with `--supersede <file>`, so each approver
   keeps every approval file they make. Approving the same draft again
   (a lost approval file) needs nothing. `--supersede` verifies under the
   ledger's current roster: an approver whose key was rotated since
   cannot hand back an older approval (D-24).
5. The signing operator:
   `policy sign --ledger <ledger> --draft draft.bin --approvals A B --keys <keys> --out v<n>.bin`,
   then `policy verify --keys-pub <keys> --slot v<n>.bin --fleet fleet.toml`,
   with `--package-node <package>/node.sha256` for each node's package.
6. The new ledger is replicated to every approver.

## Rolling out under the 15-minute SLA

The SLA is a hard operational control (D6, RM8-3): the gateway reports what
it runs, and the operators remove what is not compliant. HA is a
prerequisite: the fleet must carry its load with any node drained or
evicted, or the SLA cannot be kept without an outage.

For each node, from its last verified `policy:` line in the SIEM:

| Last line | Write |
|---|---|
| `policy: accepted version=<v> slot=A` | the new bundle into slot B |
| `policy: accepted version=<v> slot=B` | the new bundle into slot A |
| `policy: unavailable reason=<r> current=<n>` | slot A: version `n` from the ledger (`entries/<n, ten digits>.bin`); slot B: the new bundle, if it is version `n + 1` (otherwise see Skipped) |
| `policy: unavailable reason=StateRefused current=unknown` | nothing; see StateRefused |

Never overwrite the slot the node last accepted: the newer bundle is used
only if the other slot holds the version it chains from (`prev_sha256`),
and without it the node refuses as `PrevMismatch`. Slot media is always
exactly `BUNDLE_MAX` (4 718 592) bytes, the size `sign` writes; never trim
or pad it.

Then, node by node or in HA-sized batches:

1. Drain the node from the load balancer.
2. Write the slot, then reboot. The counter advances only at boot, after
   the new slot verified (C5); until then the node enforces the old
   bundle, revoked peers included (A12).
3. Version check from the SIEM, on `tools/audit-verify --events` output
   with `verified=yes` (an absence counts only over verified lines; wait
   for the next signed checkpoint if the boot's lines are still
   `verified=no`): `policy: accepted version=<new> slot=<the slot written>`
   and `policy: release_seq=<expected>`, no `policy: rejected` line for
   the written slot, and no `Halted reason=16` from a barrier PD. For a
   revocation, also check that no `PeerHandshake` line follows for the
   revoked peer: peer ids are indices in the bundle in force (ascending
   raw `wg_pub`), so map them through the new version's `peers.toml`, not
   the old one's (see "Peer attribution" below).
4. Rejoin.

At 15 minutes after the signed bundle was released, every node not
verified on the new version leaves the load balancer and loses direct
reachability (its outside address is cut off), with no exceptions, until it
passes the version check.

A node that rebooted between the advance and its `accepted` line (power
loss) needs only another reboot: the counter is already at the new version
and the same slot satisfies it (I5.1). Do not rewrite its slots.

### Code patches

A code patch uses the same procedure, with `release_seq` as the version:

1. Raise `RELEASE_SEQ` in `crates/release-seq/src/lib.rs`, build, package
   each node, `make release KEYS=<dir> PKG=<package> OUT=<dir>` and
   `make release-verify PUB=<dir> REL=<dir>`. `release.py` signs the
   source's value; check-pins P30 keeps it the only source.
2. Roll the release out as above; the version check is
   `policy: release_seq=<new>`.
3. To fence the old release (D5): issue a bundle whose `min_release` is the
   new `release_seq`, after every node runs the new release. A node
   reflashed with an older release then keeps its parsing PDs closed
   (`unavailable reason=BelowFloor`), and the floor cannot be rolled back
   because it rides on the bundle's counter. The NIC drivers stay outside
   that barrier (RM8-8).

A bad release is recovered by fixing forward (`release_seq + 1`), or by a
two-person-approved bundle that lowers `min_release` so the older release
may run again: rolling back is a signed decision, never a reflash alone.
The older release still needs a package sealed to its own PCRs.

## Recovery

Each case starts from the node's `policy:` lines. Every bundle written to a
slot comes from the ledger (`entries/`) and is checked with
`policy verify --keys-pub <keys> --slot <file> --fleet fleet.toml` first.

- **Skipped** (`rejected slot=<s> reason=Skipped`, or
  `unavailable reason=Skipped current=<n>`): the slot holds a version
  beyond `n + 1`. Replay the intermediate versions one at a time, each
  into the slot not last accepted, with one reboot and one version check
  each. If neither slot holds `n`, start by writing `n` into slot A.
- **PrevMismatch** (`unavailable reason=PrevMismatch current=<n>`): a
  version `n + 1` sits in one slot without its anchor, version `n`, in the
  other. Compare the `n + 1` slot with the ledger's entry. If they are
  identical, restore version `n` from the ledger into the other slot and
  reboot. If they differ, the node holds a version `n + 1` the ledger never
  signed: treat it as Equivocation.
- **RolledBack** (`unavailable reason=RolledBack current=<n>`): both slots
  are older than the counter (a media attacker restored old bundles, A13).
  Write version `n` from the ledger into slot A. If `n` is above the
  ledger head, the counter was advanced without authority (RM8-6):
  re-provision.
- **BadSignature, Malformed, WrongFleet** in a `rejected` or `unavailable`
  line: the slot bytes are not the ledger's. Rewrite them from the ledger
  and find out how the media changed.
- **BelowFloor**: the node runs a release older than the bundle's
  `min_release`. Update the node's release.
- **MeasureMismatch**: PCR 9 is not the measurement of the two slots as
  read. Suspect the boot path or the media; do not rewrite slots until
  the firmware and descriptor are verified (`make release-verify`).
- **AdvanceFailed**: the TPM did not confirm the increment. The node did
  not use the newer slot. Diagnose the TPM as for StateRefused.
- **StateRefused** (`unavailable reason=StateRefused current=unknown`):
  `tpm` refused the NV state: an index Name differs from the `[policy]`
  Names compiled into the image, the logical version is out of range,
  `phEnableNV` is clear, or the TPM did not answer. Write no slot. On the
  node's TPM, read both indices' public areas and compare their Names with
  `nv_ctr_name` and `nv_base_name`, and check `phEnableNV` (RM8-4). If the
  indices are wrong or missing, re-provision (two record signatures; both
  delete keys if the indices exist), which clears the TPM, so the node
  needs a new package and, if the printed Names changed, a new image.
- **Equivocation** (`unavailable reason=Equivocation`): two
  signature-verified bodies for one version. The ledger refuses a second
  body, so this means the signing key, or two approvers, are compromised
  (RM8-1, RM8-7). Stop: keep the node closed, preserve both slots, the
  ledger and every approval record, and escalate to incident response.
  Recovery needs a new signing key, which is compiled into every image.
- **Lost ledger.** Each restore approver, on their own device, runs
  `policy ledger approve-restore --from <copy> --keys-pub <keys> --approver-key <key> --approver-id <id> --head <own head file> --out R<N>.approval`.
  It refuses a copy behind or diverging from their head, and a copy that
  lacks, or holds another body at, the version they last approved: if that
  version was signed, the copy is truncated or forked. If they abandoned
  it, they say so by passing their own approval of it with
  `--supersede <file>`; nobody else's approval stands in for it, and the
  handed-back approval is then cleared from their head. It verifies the
  copy with the bundle public keys (`--keys-pub`, the approver's own
  trusted copy), as `restore` does. A restore approval is good for 24
  hours: `restore` refuses older ones, and ones dated more than 5 minutes
  ahead of the restore host's clock, so approve right before the restore
  and keep the clocks in sync. That clock is the restore host's, so the
  window limits replay but does not prevent it. What catches a cut-back
  ledger is each approver's own head at their next `approve`. Superseding a genesis approval records the
  copy's v0 in the head; if that was a copy of the wrong ledger, the
  approver removes their head file and starts it again at their next
  `approve`. An
  approver without a head file (a wiped device) cannot approve a restore,
  so a restore needs two approvers whose head files survived: on a
  two-member roster that has lost one, the fleet starts a new ledger at a
  new genesis (D-24). Then
  `policy ledger restore --from <copy> --dir <new dir> --approvals R1 R2 --keys-pub <keys> --head <file>...`,
  with the head file of every approver that can be reached, the newest
  version's approvers above all. It refuses a copy whose chain does not
  verify, one behind or diverging from any given head, one that lacks or
  forks the last approval a given head records, and fewer than two
  distinct approvers under the roster in force at the restored head.
  Which heads reach it is the operator's choice (D-24). An approver whose
  device was wiped starts a new head file at their next `approve`.
- **Roster change.** A roster change is a bundle:
  `policy render --input peers.toml --fleet fleet.toml --ledger <ledger> --out draft.bin --set-roster new-roster.toml`
  (it saves the new roster next to the draft), two approvals under the
  current roster, then
  `policy sign --ledger <ledger> --draft draft.bin --approvals A B --keys <keys> --out v<n>.bin --new-roster new-roster.toml`.
  The genesis pin does not change. A new approver receives a ledger
  replica and starts a head file; a removed approver's later approvals are
  refused.

## SIEM operations

Every capture of a node's console is checked, and every capture is
anchored:

- The first capture after provisioning:
  `tools/audit-verify --pub audit.pub --from-provisioning <name>.record <capture>`.
  Its first boot must be the first boot after provisioning (reset =
  `reset_at_provision + 1`, restart 0, starting at seq 0, its first
  checkpoint signed). The custodian vouches that it is (RM8-12).
- Every later capture:
  `tools/audit-verify --pub audit.pub --after '<anchor line>' <capture>`,
  where the anchor line is the `anchor:` line of the previous capture's
  output. Each capture starts at the line right after that anchor, so it
  repeats the previous capture's unverified tail: a capture that starts
  where the previous one ended fails "does not resume at the anchor"
  whenever the previous one ended after its last signed checkpoint.
  Capture without gaps: a reboot (TPM Reset) or a TPM Restart is a
  successor, anything else is a gap. When the next capture starts with a
  new boot, the previous boot's lines after the anchor are not verifiable
  (`audit-verify` notes it): keep that tail from the previous capture.
- After a re-provisioning, the next capture starts again with
  `--from-provisioning` and the new record.

Output: a `FAIL:` line means `audit-verify: FAILED` and exit 1: a sequence
hole (deleted, reordered or inserted lines), a chain mismatch (an edited
line), a checkpoint whose signature does not verify, a checkpoint from
another boot, checkpoint seqs that do not increase, a boot with no signed
checkpoint, or a continuity gap. Each is an incident: the record is
incomplete or altered. A `note:` line does not fail: `lost > 0` (the
device dropped events; investigate load), an unsigned checkpoint (`auditkey`
unavailable; its reason code says why), the unverified tail (lines after
the last signed checkpoint; they become evidence only once a later
checkpoint covers them), and an unterminated last line. Exit 2 is a usage
error. Version checks read only `c9 … verified=yes` lines. The gateway has
no wall clock: event time is the SIEM's receipt time (RM8-5).

### Peer attribution

Who connected, from where, and when (C12):

- `audit: src=hs PeerHandshake peer=<i> index=<0x…> lost=<n>`: `hs`
  completed a handshake with peer `i` and handed the session to `data`.
  `index` is the receiver index the gateway chose; it is in clear on the
  wire (the response's sender index, every transport packet's receiver
  index), so a packet capture at the load balancer can be matched to the
  line. One line per handshake: a client rekeys about every two minutes,
  and `hs` accepts at most one per peer per 1/50 s.
- `audit: src=ingress PeerEndpoint peer=<i> ip=<a.b.c.d> lost=<n>`, then
  `audit: src=ingress PeerEndpoint peer=<i> port=<p> lost=<n>`: the outer
  address and UDP port the gateway now sends peer `i`'s traffic to, on the
  first authenticated packet and on every roam after it, never per packet.
  The two lines are one change; behind a NAT or load balancer they name
  its address, not the client's.
- Peer `i` is the `i`-th peer of the bundle the node accepted (its
  `policy: accepted version=<v>` line), in ascending raw `wg_pub` order:
  take the peer's key and owner from that version's ledger entry and
  `peers.toml`. After an update the same index may name another peer.
- Time: the lines carry no clock. The SIEM's receipt time is the time
  evidence, and the signed chain fixes the order (RM8-5).
- Refusals stay counted, not attributed: `HandshakeUnknownPeer` (a key not
  in the bundle, including a revoked peer), `HandshakePskMissing`,
  `HandshakePskStale`. `InnerDenied(<reason>) peer=<i>` attributes what a
  connected peer was refused inside the tunnel.

## Residual risks the operators own

- **RM8-1** No HSM: whoever holds the dev signing key signs alone; keep
  the key files with one custodian, outside the repository, until the HSM.
- **RM8-2** Approvers are keys, not IdP identities: tie each approval to
  an IdP-authenticated request outside the tool.
- **RM8-3** The SLA and eviction are this runbook; a withheld update
  leaves a node on the old bundle until it is evicted and cut off.
- **RM8-4** On a board, platform firmware must own platform auth and keep
  `phEnableNV` set, and the operators hold lockout auth for the Clear.
- **RM8-5** Checkpoints are Ed25519 only; keep SIEM receipt timestamps.
- **RM8-6** An unauthorized counter increment wedges a node forward:
  re-provision it.
- **RM8-7** Two colluding approvers, two colluding delete operators, or an
  HSM compromise defeat the two-person rules: keep the pairs independent.
- **RM8-8** The NIC drivers are outside the barrier: an older release's
  driver bug stays reachable under the floor; keep releases current.
- **RM8-9** A compromised `audit` can get its fabricated chains signed
  within one boot; cross-check unexpected lines against other sources.
- **RM8-10** A LAN host spoofing a backend's 5-tuple can inject into a
  live flow: keep the LAN segment trusted.
- **RM8-11** Record signers trust the provisioning host's TPM read of
  `srk_name`: provision on a controlled host.
- **RM8-12** The first capture after provisioning rests on its
  custodian's word: capture from the first power-on.
