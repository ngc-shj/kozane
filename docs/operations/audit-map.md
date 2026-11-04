# Audit map

For auditors. Each question an audit of the gateway fleet asks is mapped to
the mechanism that answers it (M8 plan contract and component), the
evidence it leaves (a console line the SIEM receives, or an artifact the
operators keep), and the tests that prove the mechanism holds. Contract IDs
(C1–C13, D1–D11) are those of
[the M8 plan](../archive/review/kozane-m8-peer-policy-plan.md); the
deviations (D-1…D-21) in
[its log](../archive/review/kozane-m8-peer-policy-deviation.md) are already
reflected here. Operators follow
[the runbook](peer-policy-runbook.md).

Every console line `audit` prints ends in ` seq=<n>`; that trailer is
omitted below. The SIEM's checker is `tools/audit-verify` (C10).

## Test IDs

A test ID is written in backticks as `<kind>:<name>`, and `tools/check-pins`
rule P32 fails when one does not exist in the tree:

| Kind | Names |
|---|---|
| `it:` | an integration boot or group that `KOZANE_IT_BOOTS` selects, or a literal `PASS [<name>]` in `tests/integration/run.py` |
| `selftest:` | a `tools/check-selftest` case (an injected fault the gates must catch) |
| `rust:` | a `#[test]` function under `crates/` or `tools/` |
| `kani:` | a `#[kani::proof]` harness under `crates/` |
| `fixture:` | `<file>:<name>`: a tool fixture in `tests/tools/<file>`, by its case function or its quoted name |

## Questions

| Question | Mechanism | Evidence | Test |
|---|---|---|---|
| Who may connect: which peers and keys were in force? | C1 bundle (`policy-wire`), verified and selected by the `policy` PD (C5); `hs`, `pq`, `data`, `ingress` and `inner` read peers only from the verified bundle (C6, C7) | `policy: accepted version=<v> slot=<A\|B> lost=<n>`; the ledger entry `entries/<v>.bin` holds that version's signed body | `it:policy advance-revoke`, `it:wireguard`, `rust:a_valid_bundle_parses`, `rust:open_accepts_a_token_matching_the_slots_version`, `rust:open_refuses_a_token_at_the_wrong_version`, `kani:select_never_uses_or_advances_a_non_candidate_slot` |
| Who was refused at the handshake? | `hs` answers only static keys in the bundle (C7); a revoked peer loses access once the node accepted the newer bundle (A12) | `audit: src=hs HandshakeUnknownPeer total=<n> lost=<n>` | `it:unknown peer rejected`, `it:policy advance-revoke` |
| Who connected? | `hs` completes a handshake only for a bundle peer and records each one with the peer's bundle index and the session's receiver index (C12); a refused initiation records none | `audit: src=hs PeerHandshake peer=<i> index=<0x…> lost=<n>`, one per handshake; `audit: src=hs HandshakeOk total=<n> lost=<n>`; `audit: src=data SessionInstalled total=<n> lost=<n>` | `it:C12: PeerHandshake and PeerEndpoint name wireguard-go's peer and its endpoint`, `it:L8 pair: peer 1 refused without a PSK while peer 0 works, accepted after Rosenpass`, `it:policy advance-revoke`, `rust:accepted_reports_the_sessions_receiver_index`, `rust:peer_kinds_decode_each_peer_as_itself`, `rust:peer_kinds_are_never_coalesced_and_carry_their_value`, `kani:peer_kinds_encode_and_decode_exactly` |
| From where (outside the tunnel)? | `ingress` records a peer's outer endpoint when it is first set and on each change (a roam), from `data`'s `EndpointUpdate`, which needs an authenticated packet with a new highest counter (C12) | `audit: src=ingress PeerEndpoint peer=<i> ip=<a.b.c.d> lost=<n>` followed by `audit: src=ingress PeerEndpoint peer=<i> port=<p> lost=<n>` | `it:C12: PeerHandshake and PeerEndpoint name wireguard-go's peer and its endpoint`, `it:spoofed inner source dropped, install scrubbed`, `rust:peer_kinds_with_an_out_of_range_peer_encode_to_their_unknown`, `kani:peer_kinds_encode_and_decode_exactly` |
| Was the bundle checked against the node that runs it? | C2: `tools/package` records the node's `NodeConfig` digest (`node.sha256`, by `policy node-digest` from the `gateway.toml` the image compiles); `policy verify --fleet --package-node` refuses a fleet file with no node of that digest | `node.sha256` in each package; the `verify` output naming the node | `fixture:test_policy.py:case_package_node_in_fleet`, `fixture:test_policy.py:case_package_node_differs`, `fixture:test_policy.py:case_node_digest_without_policy`, `fixture:test_package.py:a missing node.sha256 is refused`, `rust:a_package_node_digest_matches_only_its_own_fleet_node`, `it:wireguard` |
| Who approved the policy, and on what? | C2 `tools/policy`: two approval records from distinct roster entries, each binding the body, version, fleet, `prev`, diff and roster digests; the ledger keeps them (D11) | the ledger's `approvals/<v>/`; `policy verify --ledger` re-verifies the chain | `fixture:test_policy.py:case_one_approval_only`, `fixture:test_policy.py:case_same_approver_twice`, `fixture:test_policy.py:case_payload_swapped_after_approval`, `fixture:test_policy.py:case_approver_not_in_roster`, `fixture:test_policy.py:case_forged_approval_signature`, `fixture:test_policy.py:case_record_for_another_diff`, `rust:diff_is_total_and_sensitive_to_every_field`, `rust:a_forged_approval_signature_is_refused` |
| Can the history be rewritten? | C2/D11: the ledger chain, the compiled-in genesis-roster pin, each approver's recorded head, two-approval restore | `policy verify --ledger` output; each approver's head file | `fixture:test_policy.py:case_truncated_ledger`, `fixture:test_policy.py:case_re_genesis`, `fixture:test_policy.py:case_tampered_roster`, `fixture:test_policy.py:case_broken_chain_link`, `fixture:test_policy.py:case_second_body_for_signed_version`, `fixture:test_policy.py:case_approver_head_same_version_different_digest`, `fixture:test_policy.py:case_restore_missing_approver_head`, `fixture:test_policy.py:case_single_restore_approval` |
| From where (inside the tunnel)? | C1 allowed IPs per peer, pairwise disjoint and clear of the node's own prefix; `data` drops a decrypted packet whose source is outside its peer's allowed IPs | `audit: src=data SpoofedSource total=<n> lost=<n>` | `it:spoofed inner source dropped, install scrubbed`, `rust:allowed_ips_overlapping_across_distinct_peers_are_malformed`, `rust:an_allowed_ip_overlapping_inside_prefix_is_malformed` |
| What could a peer reach, and what was denied? | C8 `inner-core`: inbound allowed only by a rule of one of the peer's groups; LAN → tunnel only on a flow that peer opened (D9) | `audit: src=inner InnerDenied(<NoRule\|UnknownPeer\|NoFlow\|IcmpError>) peer=<i> total=<n> lost=<n>` | `it:C8: peer X (group web) connects to the inside host's port P`, `it:wireguard`, `kani:i8_1_inbound_allow_has_a_matching_rule`, `kani:i8_2_unknown_peer_is_denied`, `kani:i8_3_outbound_allow_answers_a_live_peer_opened_flow`, `kani:i8_4_no_matching_rule_is_denied`, `rust:a_peer_with_no_groups_reaches_nothing`, `rust:a_reply_on_xs_flow_never_leaves_as_peer_y`, `rust:an_unsolicited_lan_packet_is_denied_and_a_reply_passes`, `rust:inner_denied_is_coalesced_per_peer_and_reason` |
| When? | C10/D7: `auditkey` signs each checkpoint over the TPM's SRK Name, a boot ID it draws, `resetCount`/`restartCount` (ReadClock), the line's `seq`, the chain and `lost`. The gateway has no wall clock, and no line, the per-peer ones included, carries a time: time is the SIEM's receipt time, and the signed chain fixes the order (RM8-5) | `audit: checkpoint srk=<name> boot=<id> reset=<r> restart=<s> chain=<h> lost=<n> sig=<hex>` | `it:audit export`, `fixture:test_audit_verify.py:deny: a checkpoint from another boot`, `fixture:test_audit_verify.py:allow: a second boot after a TPM Reset`, `fixture:test_audit_verify.py:deny: a missing boot (reset jump)`, `rust:every_field_changes_the_message`, `kani:read_clock_is_reachable_only_from_auditkey` |
| Under which policy version? | C5 selection, the C3 NV counter (moves only forward, only after the newer slot verified: I5.1), C9 version lines | `policy: accepted version=<v> slot=<s>`, `policy: rejected slot=<s> reason=<r> version=<v\|->` (the version where the slot held a verified bundle: RolledBack, Skipped, BelowFloor), `policy: unavailable reason=<r> current=<n\|unknown>`; `audit-verify` prints the accepted, release_seq and unavailable lines as `c9 boot=<i> seq=<n> verified=<yes\|no>: <line>`, and with `--events` every line (rejected included) as `event boot=<i> seq=<n> verified=<yes\|no>: <line>` | `it:policy advance-revoke`, `it:policy restore-old`, `it:policy crash-after-advance`, `kani:verified_next_version_needs_a_matching_advance_reply`, `kani:the_policy_client_sends_only_its_reads_and_at_most_one_increment`, `rust:the_gate_reads_the_logical_version_and_pcr9_and_advances_once`, `fixture:test_audit_verify.py:allow: the C9 lines are extracted, verified`, `fixture:test_audit_verify.py:allow: --events prints a policy rejection, verified`, `kani:policy_unavailable_accepted_and_release_seq_encode_and_decode_exactly` |
| Could an older or forked policy have been used? | C3 counter and two-signature delete policy; C5 refusals (RolledBack, Skipped, PrevMismatch, Equivocation, BadSignature, MeasureMismatch, StateRefused); C4 PCR 9 over both slots | the `rejected` and `unavailable` lines above | `it:policy rolled-back`, `it:policy skipped`, `it:policy equivocation`, `it:policy prev-mismatch`, `it:policy no-anchor`, `it:policy half-bad`, `it:policy measure-mismatch`, `it:policy wrong-name`, `selftest:policy-equivocation-removed`, `selftest:policy-prev-removed`, `selftest:policy-pcr9-check`, `selftest:policy-name-skipped`, `selftest:policy-advance-unverified`, `selftest:policy-ed25519-skipped`, `selftest:policy-mldsa-skipped`, `kani:no_policy_operation_succeeds_after_the_cap`, `kani:the_refused_set_is_refused_for_every_raw_client`, `fixture:test_provision.py:deny: existing indices without the two delete authorizations` |
| Did anything serve traffic without a verified policy? | C6 barrier: `hs`, `pq`, `ingress`, `data` and `inner` wait for `Verified` and otherwise halt with `POLICY_UNAVAILABLE` (16) | `audit: src=<pd> Halted reason=16 lost=<n>` for each barrier PD | `it:policy rolled-back`, `selftest:policy-hs-barrier` |
| Under which release (code)? | C9/D5: `RELEASE_SEQ` compiled into `policy` and signed in the release manifest; a bundle's `min_release` above it keeps the parsing PDs closed (`BelowFloor`) | `policy: release_seq=<n> lost=<n>`; the release `manifest` field `release_seq`; PCRs 0–8 in the manifest (M7) | `it:wireguard`, `it:policy below-floor`, `it:policy floor-lowering`, `it:release boot`, `fixture:test_release.py:case_release_seq_other`, `fixture:test_release.py:case_release_seq_missing`, `rust:min_release_below_equal_and_above_the_release_seq`, `rust:the_first_release_is_one_above_the_open_floor`, `selftest:policy-anchor-floor` |
| Which device and TPM? | C3 provisioning record, signed after `TPM2_Clear` by two record keys and bound to the new SRK Name and `reset_at_provision`; checkpoints carry the SRK Name | the provisioning record and its two signatures; `baseline srk=… reset=… restart=… seq=…` from `audit-verify` | `fixture:test_provision.py:allow: each provisioning clears the TPM, so the SRK changes`, `fixture:test_provision.py:deny: a record bound to another TPM's SRK`, `fixture:test_provision.py:deny: a record replayed from an earlier provisioning`, `fixture:test_provision.py:deny: a record signed by a delete key`, `fixture:test_audit_verify.py:deny: a record for another TPM`, `fixture:test_audit_verify.py:deny: the device key is another device's` |
| Was the record complete and unaltered? | C10: per-line `seq`, hash chain from `h0`, signed checkpoints every 64 lines and at ready, the summed `lost`, capture continuity (`--after` / `--from-provisioning`) | `audit-verify` prints `FAIL:` lines and `audit-verify: FAILED`, or `audit-verify: ok`; `note:` lines report `lost > 0`, unsigned checkpoints and the unverified tail | `it:audit export`, `fixture:test_audit_verify.py:deny: a deleted line`, `fixture:test_audit_verify.py:deny: two lines reordered`, `fixture:test_audit_verify.py:deny: an edited line (trailer intact)`, `fixture:test_audit_verify.py:deny: a forged checkpoint (lost changed)`, `fixture:test_audit_verify.py:deny: a boot with no signed checkpoint`, `fixture:test_audit_verify.py:deny: --after, a line deleted just after the anchor`, `fixture:test_audit_verify.py:deny: the flag on a later cold boot`, `fixture:test_audit_verify.py:report: lost > 0`, `selftest:audit-trailer-raw`, `rust:the_chain_matches_known_answers_trailer_included` |
| Could the logging path sign what it should not? | D7: `auditkey` signs only the fixed tuple and only at `seq ≥ last + 64` (one exemption); `audit` calls it from one site, after the ready notification (audit-core's Kani; P31 a tripwire) | the checkpoint lines; an unsigned one reads `audit: checkpoint boot=unavailable … sig=unavailable reason=<code>` | `kani:signatures_strictly_increase_with_at_most_one_exemption`, `kani:the_parser_is_total_and_exact`, `kani:no_call_without_the_ready_input`, `kani:ready_input_is_the_auditkey_bit_alone`, `rust:a_fake_auditkey_sees_no_call_before_the_ready_input`, `rust:auditkey_never_refuses_the_schedule` |
| Was the node alive, and when did it stop? | M9 plan C3: `timer` notifies `audit` once a second on its own channel; every `HEARTBEAT_S` (60) ticks `audit` prints a heartbeat, chained and signed like every line. The count can only undercount (ticks coalesce while `audit` is not scheduled); no ring record can print it | `audit: Heartbeat ticks=<n>`; a missing one in the SIEM's receipt times marks a stopped timer, `audit` or console | `rust:a_heartbeat_is_due_every_heartbeat_s_ticks`, `rust:the_timer_channel_is_not_the_ready_input`, `rust:no_ring_code_is_named_heartbeat`, `rust:channel_ids_match_layout`, `kani:a_heartbeat_is_due_exactly_every_heartbeat_s_ticks`, `kani:no_code_decodes_as_the_heartbeat`, `fixture:test_audit_verify.py:allow: --events prints a heartbeat, verified`, `fixture:test_audit_verify.py:deny: an edited heartbeat (ticks changed)` |

## Not recorded

- **Peer identity is an index.** `peer=<i>` is the peer's position in the
  bundle in force (ascending raw `wg_pub`); its key and owner come from
  that version's ledger entry and `peers.toml`, and the same index can
  name another peer after an update.
- **No session end or volume.** A session's expiry and its bytes are not
  attributed (`SessionExpired` is a count), and refused initiations stay
  counts (`HandshakeUnknownPeer`, `HandshakePskMissing`,
  `HandshakePskStale`) without the key they presented.
- **The endpoint is the gateway's view.** Behind a NAT or load balancer
  `PeerEndpoint` names that hop (under QEMU user-net, `10.0.2.2` with the
  client's port); the client's own address is in that hop's logs.
- **No timestamps.** Time comes from the SIEM's receipt and the chain
  order only.

`PeerHandshake` and `PeerEndpoint` are edges, never coalesced: the first is
bounded by `hs`'s 1/50 s per-peer flood limit and needs the peer's static
key and current PSK, the second by the peer's own authenticated packets
(an on-path attacker racing them can make each one a roam). A full ring
drops records and counts them in `lost`.

## Zero-trust roles

| Role | Here | What it does |
|---|---|---|
| PEP (enforcement) | the gateway: `policy` (verify and select, C5), `ingress` and `hs` (only bundle peers handshake, C7), `inner` (group rules and peer-opened flows, C8), behind the C6 barrier | enforces the last bundle it verified; it decides nothing on its own |
| PDP (decision) | the management service (not shipped, SC44) and the two-person signer `tools/policy` with its ledger (C2, D11) | turns approved intent into a signed bundle; nothing is signed without two approvals |
| PIP (information) | the IdP (approver identity, RM8-2), the MDM (device posture behind each peer's entry in `peers.toml`), the SIEM (receives and verifies the stream with `tools/audit-verify`, C10) | supplies the facts a decision rests on and keeps the evidence |

## Out of scope and residual

| ID | What it leaves to the auditor |
|---|---|
| SC31 | No TPM2_Quote: PCR 9 is measured but not attested remotely |
| SC42 | The HTTPS proxy path carries no peer identity; group authorization covers tunnelled traffic only (D8) |
| SC43 | No PolicyAuthorize, no calendar expiry of a bundle, at most 8 peers |
| SC44 | The management service (PDP) is not part of M8 |
| RM8-1 | No HSM: whoever holds the dev policy key signs alone |
| RM8-2 | An approver is a key, not an IdP identity with a second factor |
| RM8-3 | The 15-minute SLA and eviction are a runbook, not a device control; a withheld update leaves a node on the old bundle until evicted |
| RM8-4 | Platform auth is empty under QEMU; a board's firmware must own it and keep `phEnableNV` set |
| RM8-5 | Checkpoints are Ed25519 only; mitigated by SIEM receipt timestamps |
| RM8-6 | An unauthorized counter increment wedges a node forward (DoS) until re-provisioned |
| RM8-7 | Collusion of two approvers, or of the two delete-key holders, or an HSM compromise |
| RM8-8 | The NIC drivers are outside the barrier: an older release's driver bug stays reachable under the floor |
| RM8-9 | A compromised `audit` can get the current boot's checkpoints signed over chains it fabricates |
| RM8-10 | A LAN host spoofing a backend's 5-tuple can inject into a live flow |
| RM8-11 | Record-key holders trust the provisioning host's TPM read of `srk_name` |
| RM8-12 | The first capture after provisioning starts at the first boot on its custodian's word |
