# Plan Review: secureos-m6-https-proxy
Date: 2026-10-24
Review round: 1

## Changes from Previous Round

Initial review. Local LLM pre-screening raised three Minors (MAX_BODY as
configuration, inner's config source, the audit-event crate), applied before
the experts ran.

## Merged findings and dispositions

Converging findings (same root cause from several experts) are merged; the
severity floor is the highest filed. Every finding below is reflected in the
plan (v2) unless its row says otherwise.

| ID(s) | Sev | Subject | Resolution in plan v2 |
|---|---|---|---|
| F1 | Major | TCP admission past Verus-specified `parse_frame`; `parse_tcp` cannot checksum from the payload | C2: fallback via `parse_frame_ip` on `NotUdp`, `parse_tcp(&Ip4Packet)`; `parse_frame` spec untouched |
| F2, S2, S3, S16 | Major | `tli` egress unchecked, no ARP cache exists, no TX tier; TCP branch lacks the self-source check | C2: `tls_egress` with field checks, `router_mac`, `TLS_TX_SHARE` tier above `Unsolicited`; self-source check |
| F3, S12 | Major | Role `tls` does not exist; L13 priority rows | C1/L13: role `untrusted_input`; selftest at priority 140 |
| F4 | Major | Server-first close leaves TIME-WAIT, starving slots | C10 close rules: bounded wait then abort; sequential-connections case |
| F5 | Major | Two interfaces need two SocketSets | C3 |
| F6 | Major | 1 Hz timer vs delayed ACK/retransmit | C3: ack delay off, Nagle off, ≥ 1 s granularity accepted and recorded |
| F7 | Major | close_notify on abnormal termination hides truncation | C10 close rules; D4 wording fixed |
| F8 | Major | CertificateVerify needs DER ECDSA-Sig-Value | C5 reply byte order; C6 DER encoder |
| F9, S6, T2 | Major | L14 sole constructor vs RFC 8448 KAT; 8448 is AES-GCM; record keys uncovered | C7: `#[cfg(test)]` `schedule_from_ikm`; 8448 scoped to secrets/Finished; keylog fixture via Python for keys/IVs/records/KeyUpdate |
| F10 | Major | TlsKeyMismatch takes `key` and the VPN down | D5: TLS-only unavailability; codes 17/18; `tls` audits and halts; VPN case |
| F11, S4, T11 | Major | SYN flood fills listeners; shared bucket; case 9 vacuous | C2 separate SYN/data buckets; C3 SYN-RECEIVED timeout; RM6-7 + SC38; case 9 narrowed to the VPN half with a drop-count precondition |
| F12, S14 | Major/Minor | TlsSign bucket invariant ill-defined, sized upward; boot-seed once | C5 invariants against the global SYN bucket (abuse bound); seed repeats allowed, counted |
| S1 | Major | TlsSign on `tls`'s SC holds passive `key`, stalls `hs` | C5 interference invariant with measured `SIGN_COST_NS`; case 12; stop rule |
| F13 | Major | Cert generation order; SPKI parser | C11 order; fixed-prefix SPKI check, no DER parser; scenario 1 fixed |
| F14 | Major | File list incomplete | Files per contract; D3 lists the changed VPN-side code |
| F15, S18 | Major/Minor | Consumer walkthroughs missing; member-set greps | Acceptance appendix; widened greps; pqkey `MAX_WORDS` excluded |
| F16 | Major | inner routing gaps | C4: neighbour/prefix validation, `parse_tcp`, no TTL on local delivery, exact checks both directions |
| S5 | Major | Header rewrite spoofing and `Connection` desync | C9 |
| S7, T5, F22 | Major/Minor | Hand-written RFC 6979; k' untested; wipes; ECDSA API | C5: `libcrux_p256::ecdsa_sign_p256_sha2` takes the nonce as bytes (verified in the fetched crate source; libcrux-ecdsa's `Nonce` has no byte constructor); differential test vs RustCrypto `rfc6979` incl. k'; rejection branch; RNDR failure; secret types and stack scrub |
| S8 | Major | Unconstrained dev CA | C11 |
| S9, T4 | Major | P9/P10/P11 not extended; Finished ct compare ungated | Testing strategy enrolment; C7 `ct_eq` |
| S10, T6, T7 | Critical (T6) | Wipe points untested; past plaintext in buffers; scan barrier and control | C8: buffers wiped, `TlsClosed` barrier, three integration residue cases, unit tests for alert/timeout, one selftest per wipe |
| S11, F23 | Major/Minor | TLS 1.3 profile gaps | C6/C7 |
| T1 | Critical | Post-ServerHello refusal paths untestable | C7 host test client |
| T3 | Major | L14 type property ungated | C7 `compile_fail` doctests; check-pins constructor rule; code-point ban declared a tripwire with spelling fixtures |
| T8, F21 | Major/Minor | Scalar exact count unimplementable; garbled sentence | Testing strategy: count helper, both byte orders, after a handshake, selftest |
| T9 | Major | Two integration acceptances unproducible | Moved to unit/Kani (C4, C5); old case 11 removed |
| T10 | Major | Backend "receives nothing" unobservable | Raw-capture backend, barrier request, `ip_forward=0` |
| T12 | Major | Slowloris cannot catch a resetting timer | Case 11 trickle; C10 "activity does not reset" |
| T13, F19 | Major/Minor | Timeout headroom unmeasured; probe too narrow | C10 probes in slices 1 and 3 with a stated margin |
| T14 | Major | NotUdp fixtures, Verus spec, READY_LINE | C2 fixture move to protocol 47; spec untouched; `tls` prints no ready line (audit only, M5 C6) |
| T15 | Major | Kani invalidation per slice; harness bounds | All crates and deps in slice 1; bounds listed |
| T16 | Major | Gate enrolment; host-testable conn core | Testing strategy; C10 `tls-core::conn` |
| T17 | Major | Deny-only bound tests | Allow/deny pairs in C6, C9 |
| T18 | Major | Mutation list incomplete; "recorded" undefined | Mutation list extended; each a selftest case with gate and needle in the Phase 2 checklist |
| F17, S15, T20 | Minor | HTTP statuses, duplicate Host, CTLs, rewrite bound | C9 |
| F18 | Minor | Memory estimate | C10 recount and compile-time assert |
| F20 | Minor | TLS_PORTS sizing | C3 |
| S13 | Minor | Amendment text vs checker | Law amendments restated against the code |
| S17 | Minor | Per-source cap, lifetime, panic residual | C10 cap 2 per source, 120 s lifetime; RM6-2 |
| T19 | Minor | Bolero corpora | C2, C6, C9 seeds |
| T21 | Minor | Preflight, group assert, verification negative control | Integration preflight and case 1 |
| T22 | Minor | Integration cost; mismatched cert image | C11 blob-only variant; cost stated after slice 3 |

No finding was skipped or accepted without change.

## Functionality Findings

F1–F23 as indexed above (expert output retained in the session record).
Verified without finding: KEY_MAX_PEERS arithmetic, budget sum, memory
arithmetic, key-share sizes and order, the RFC 8446/6979/8448 and FIPS 203
citations, the two-envelope descriptor, `MAX_WORDS` 4 → 8 for `hs`, IP
packets on the existing rings, port routing in `inner`.

## Security Findings

S1–S18 as indexed above. Checked correct: 0x11EC, ML-KEM ‖ X25519 order,
1216/1120, 0x1303, 0x0403, 0x0304, the 0x0301 first-record allowance, the
2^14(+256) limits, the FIPS 203 modulus check, the X25519 zero check, the
CertificateVerify content; no downgrade sentinel needed (TLS 1.2 is never
negotiated). No Critical; no escalation.

## Testing Findings

T1–T22 as indexed above.

## Adjacent Findings

- F2 (egress checks) and F16d → merged with S2.
- F5 adjacent: smoltcp ISN seed from the hedged RNG → C3/C7.
- F17 adjacent: curl sends `Expect: 100-continue` above 1 MiB → C9 refuses
  `Expect` with 417; case 2 uses `-H 'Expect:'` for the `MAX_BODY` + 1 case.
- F21 adjacent → T8.
- T3 adjacent (R47 code-point spellings) → C7/L14 tripwire fixtures.
- T11 adjacent (spoofed SYNs hold listeners) → merged with F11/S4.
- S18 adjacent → F15.

## Quality Warnings

None: every finding carried file/line evidence or a stated derivation.

## Recurring Issue Check

### Functionality expert
- R1 applicable: F13 (DER/SPKI parser absent; Buckets reuse correct)
- R2 applicable: F14/F15 (blob layout constants in Rust/Python/tpm2)
- R3 applicable: F14
- R4 applicable: F10, F15
- R5–R9 N/A
- R10 checked, no finding
- R11 N/A
- R12 applicable: F15
- R13–R15 N/A
- R16 checked, no finding
- R17 applicable: F2
- R18 applicable: F3
- R19–R21 N/A
- R22 applicable: F10
- R23, R24 N/A
- R25 applicable: F15
- R26–R28 N/A
- R29 applicable: figures and citations verified; F9, F12, F2
- R30, R31 N/A
- R32 checked, no finding
- R33 N/A (no CI)
- R34 checked, no finding
- R35 checked, no finding (F13 fixes scenario 1)
- R36, R37 N/A
- R38 applicable: F4, F7, F11
- R39 [Adjacent] F21, backend socket plaintext
- R40 applicable: F8
- R41 applicable: F5, F6
- R42 applicable: F15 (L2 callers {hs}→{hs, tls} correct)
- R43 [Adjacent] F2, F16(d)
- R44–R48 N/A
- R49 applicable: F11
- R50 applicable: F22
- R51 N/A
- R52 applicable: F10
- R53 applicable: F19
- R54–R57 N/A

### Security expert
- R1: N/A except RFC 6979 (S7)
- R2: checked, OK
- R3: S2, S3, S9, S16
- R4–R11: N/A
- R12: checked, OK
- R13: N/A
- R14: N/A (capability analogue in S2/S12)
- R15, R16: N/A
- R17: S9
- R18: S9
- R19, R20: N/A
- R21: N/A for plan review
- R22: checked; Buckets reuse is S18
- R23–R28: N/A
- R29: S6, S11, S13, S18; other citations correct; none Critical
- R30, R31: N/A
- R32: checked, OK
- R33: N/A
- R34: S17
- R35: checked, OK
- R36, R37: N/A
- R38: checked; KeyUpdate gaps in S11
- R39: S10, S7
- R40: checked; FIXED grep gap in S18
- R41: S6
- R42: S9, S12, S18 (C1 member set recomputed, correct)
- R43: S1
- R44–R46: N/A
- R47: S5, S6
- R48: S2
- R49: S1, S2, S4, S6, S10, S12, S14
- R50: S7
- R51: N/A
- R52: S1, S3
- R53: checked (0.95 ceiling, D3 re-plan rule)
- R54–R57: N/A
- RS1: S9, S11
- RS2: S4, S14
- RS3: S5, S11, S15, S16
- RS4: checked, OK
- RS5: S8
- RS6: S5

### Testing expert
- R1 N/A
- R2 watch (constants via `rust_const`: T11, T12)
- R3 finding (T14)
- R4 partial (T7)
- R5, R6 N/A
- R7 watch (T14)
- R8–R11 N/A
- R12 finding (T14)
- R13–R15 N/A
- R16 partial (T21)
- R17 watch (`start_without_stop_signals` for new threads)
- R18 partial (T16)
- R19–R28 N/A
- R29 finding (T15, T2)
- R30, R31 N/A
- R32 OK
- R33 N/A
- R34 N/A
- R35 OK
- R36, R37 N/A
- R38 partial (T1)
- R39 finding (T6, T7, T8)
- R40 watch (r ‖ s vs DER)
- R41 finding (T9)
- R42 partial (T18)
- R43 N/A
- R44 OK
- R45 watch (T22)
- R46 N/A
- R47 [Adjacent] (T3)
- R48 N/A
- R49 OK
- R50 partial (T15, T19)
- R51, R52 N/A
- R53 finding (T13)
- R54–R57 N/A
- RT1 finding (T10)
- RT2 finding (T9)
- RT3 watch (T12)
- RT4 finding (T11)
- RT5 partial (T2)
- RT6 finding (T16)
- RT7 finding (T1, T3, T4, T5, T18)
- RT8 partial (T10, T6)
- RT9 watch (Python HKDF is an independent oracle)
- RT10 finding (T17)
- RT11 watch (second tap and backend thread teardown)

# Review round 2
Date: 2026-10-24

## Changes from Previous Round

Plan v2 (76fe9fa) answered every round-1 finding. Round 2 confirmed most
of them: functionality F1–F23 resolved except F15 (partly), security S1–S18
resolved except S1 (partly) and S10, testing T1–T22 resolved except T4, T7
(not) and T11 (partly). The new findings are numbered N1… by each expert
and are prefixed here F-N, S-N and T-N.

## Merged findings and dispositions (plan v3)

| ID(s) | Sev | Subject | Resolution |
|---|---|---|---|
| F-N1 | Major (prose, R29) | secret-blob `FIXED` is 80 → 112, not 112 → 144 | C5 corrected; mirror test asserts Rust body length = `_key_body` |
| F-N2, T-N2 | Major | Attacker-driven audit kinds are coalesced, so `TlsClosed`/`TlsTimeout` lines cannot be barriers | C10 audit shape: per-value code bases, `a` = running total, value events for high-waters; no barrier depends on an audit line; residue cases in a dedicated boot |
| S-N2, T-N3 | Major | Rewrite/tx buffers unlisted; inside-path cleartext makes the marker scan fail and RM6-1 overclaim; control on the head timer | C8 wipe list extended; scope stated (tls-owned memory; backend link cleartext by design); marker = dropped `Keep-Alive` value; control held in response streaming; RM6-1 restated |
| T-N4 | Major | Residue cases 1–2 without a server-side barrier; case 2 ambiguous | Backend log of a request head as barrier; client handshake secret kept until the client Finished is verified; case 2 client secrets, `K` variant |
| T-N1 | Major | P11 name tripwire cannot see the Finished compare | P11 `tls-core` name set anchored on the Finished file, fixtures |
| T-N5 | Major | Case 9 precondition event missing; no red-proof; recovery | `TcpLimited` coalesced ingress kind; case 9 declared a positive availability check whose controls are red-proved by unit cases; run last |
| T-N6 | Major | Case 10 tests the cap for the wrong cause; wall-clock leg | Cap tested with free slots and an allow pair; recycling by counting |
| T-N7, S-N1, F-N7 | Major/Minor | Interference invariant mis-modelled; red-proof cannot redden; copied constant; generator unspecified | Per-call wait formula with +1 period; `TLS_BUDGET_NS` in `layout` checked against `.system`; `SIGN_COST_NS` max of 20 × 2 with a lock-entry re-measure rule; `KeyWaitHighWater` observable; red-proof by lowering the budget; replayed-ClientHello generator |
| T-N8 | Major | Close rules untested | Case 13 + conn-core unit tests |
| T-N9 | Major | Kani accept path vacuous within 96 bytes | `kani::cover!` per harness; ClientHello accept side by bolero/unit, stated |
| T-N10 | Major | mkcert untested | test_mkcert.py, MKCERT-FIXTURES, selftest |
| S-N3, F-N8 | Minor | Rejected TLS scalar stays in `key`; code typing; borrow | TLS check before the long borrow, bytes wiped, status stored; `TlsKeyError` separate; count 0 in case 8 |
| S-N4, F-N6 | Minor | RFC 6979 loop unbounded; h ≥ n vectors | Cap 8 candidates → `ERR_CRYPTO`, seam test; h ≥ n vectors in the differential test (carried into the Phase 2 checklist with the C5 tests) |
| S-N5 | Minor | `tls_egress` admits bare SYN | Refused; Kani clause; SYN-ACK/RST allowed |
| S-N6, F-N11 | Minor | RM6-7 omits ACK floods and ISN predictability | Verified smoltcp 0.14 ISNs are PCG32 (`src/rand.rs`); RM6-7 and SC38 extended; data bucket constants recorded in slice 1 |
| S-N7, F-N12 | Minor | IP SANs unconstrained; CA key custody; negative-test leaf | iPAddress subtree; key never serialized; `--test-negative`; 30-day re-issue in scenario 1 |
| S-N8 | Minor | early_data rationale wrong; curl `Expect` | early_data ignored per §4.2.10 with a 16 KiB skip cap; curl `-H 'Expect:'` |
| F-N3, F-N4 | Minor | Refusal close; 2 s wait start | Close rules extended; wait starts when the send buffer drains |
| F-N5 | Minor | `set_timeout` socket-wide | 5 s on listen, 30 s on Established |
| F-N9 | Minor | TCP branch lacks the Ethernet destination check | Added |
| F-N10 | Minor | D3 vs C5 on `pds/hs` | `hs` changes only for `KeyWaitHighWater`, now in both |
| F-N13 | Minor | Config shapes | Walkthrough row gives the Rust types |
| T-N11 | Minor | Mutation gaps | Added to the mutation list |
| T-N12 | Minor | Manifest keys | Listed |
| T-N13 | Minor | Keylog fixture source | `openssl s_server` capture with the script committed |
| T-N14 | Minor | Probe margin per host | run.py canary "probe margin exceeded" |
| T-N15 | Minor | Slot-wipe observable | `Slot::is_zeroized()` `cfg(test)` accessor |

## Recurring Issue Check (round 2)

### Functionality expert
R1 no finding; R2 N7, N1; R3 no new finding; R4 N2; R5–R9 N/A; R10 checked;
R11 N/A; R12 N2; R13–R15 N/A; R16 checked; R17 no finding; R18 no finding;
R19–R21 N/A; R22 no finding; R23, R24 N/A; R25 N1, N8; R26–R28 N/A; R29 N1,
N7 (other figures re-verified); R30, R31 N/A; R32 checked; R33 N/A; R34, R35
checked; R36, R37 N/A; R38 N3, N4, N5; R39 [Adjacent] N8; R40 N2; R41 N2; R42
no finding beyond N1; R43 checked; R44–R48 N/A; R49 N11; R50 resolved; R51
N/A; R52 checked; R53 no finding; R54–R57 N/A.

### Security expert
R1 N/A; R2 OK; R3 resolved; R4–R11 N/A; R12 OK; R13–R16 N/A; R17, R18 OK;
R19–R28 N/A; R29 N1, N8 (other citations verified); R30, R31 N/A; R32 OK; R33
N/A; R34, R35 OK; R36, R37 N/A; R38 OK; R39 N2, N3; R40, R41, R42 OK; R43 N1;
R44–R46 N/A; R47 OK; R48 OK; R49 N2, N6; R50 resolved; R51, R52 OK; R53 N1;
R54–R57 N/A; RS1 OK; RS2 N6; RS3 OK; RS4 OK; RS5 N7; RS6 OK.

### Testing expert
R1 N/A; R2 watch; R3 resolved; R4 N2, N5; R5, R6 N/A; R7 resolved; R8–R11
N/A; R12 resolved; R13–R15 N/A; R16 resolved (watch N14); R17 watch; R18
partial (N12); R19–R28 N/A; R29 N1, N2; R30, R31 N/A; R32 OK; R33–R37 N/A
except R35 OK; R38 partial (N8); R39 N3, N4; R40 OK; R41 resolved; R42
partial (N11); R43 N/A; R44 OK; R45 watch; R46 N/A; R47 resolved (N1 same
class); R48 N/A; R49 OK; R50 N9; R51, R52 N/A; R53 resolved (N14); R54–R57
N/A; RT1 resolved; RT2 resolved; RT3 watch; RT4 N5, N6; RT5 OK; RT6 N10; RT7
N1, N5, N7, N9, N11; RT8 OK; RT9 watch; RT10 resolved; RT11 watch.

# Review round 3
Date: 2026-10-24

## Changes from Previous Round

Plan v3 (ec0df65, 954bd1f). Functionality: F-N1–F-N13 and F15 resolved;
four Minors (N-a, N-c prose; N-b execution-reachable; N-d design).
Security: all tracked findings resolved except S-N7 (partly); three Minors
(R3-1, R3-2 design; R3-3 prose); no Critical or Major. Testing: six Majors
and four Minors, all on test design (barriers, vacuity, red-proof reach).
Saturation is not met (open Majors, design findings); round 4 follows.

## Merged findings and dispositions (plan v4)

| ID(s) | Sev | Subject | Resolution |
|---|---|---|---|
| T-R3-1 | Major | Coalesced totals asserted where no line prints | Case 11 first in `https-residue`, asserts `total=1`; case 9 crosses a printed point (≥ 64) |
| T-R3-2 | Major | Case 2 barrier vs one request per connection | Cases 1→2 one connection: head + partial body, `k`, more body; the backend logging post-KeyUpdate body bytes is the barrier |
| T-R3-3 | Major | Client EOF precedes the socket wipe | Wipe order stated; barrier = sniffer sees the abort RST |
| T-R3-4 | Major | Recycling count does not exercise TIME-WAIT | Server-initiated closes, seven held in streaming and checked alive, red-proof without abort |
| T-R3-5 | Major | Case 12 without overlap; red-proof trips the canary | Own boot without the canary; baseline and overlap precondition; named needle |
| T-R3-6, S-R3-3 | Major/Minor | early_data skip untested; preconditions | Preconditions (offered, no sequence advance, until first success) in C6; host-client cases and mutations |
| S-R3-1 | Minor | CA constraints open in the other name form | Both forms constrained per mode; negative leaves per mode |
| S-R3-2 | Minor | Ephemerals not wiped; no `tls` stack scrub | Secret types; `tls` scrub after exchange and TlsSign; seam test; mutation |
| F-N-a | Minor (prose) | Audit list gaps | D5 events and `tls` halt table; `StackHighWater` reused; base+value spellings |
| F-N-b | Minor | Boot-time TLS check leaves stack copies | `key` stack scrubbed after the check |
| F-N-c | Minor (prose) | L3 row narrower than C8 | `inner_rx`/`inner_tx` named |
| F-N-d | Minor | TLS_PORTS validation | Rules and tests in C3 |
| T-R3-7 | Minor | Case 8 zero-count control | `gateway_private` present |
| T-R3-8 | Minor (prose) | Canary measurement | curl `time_appconnect − time_connect` vs 1/3 timeout |
| T-R3-9 | Minor (prose) | Case 13 observation | `s_client -msg`, ECONNRESET, sniffer |
| T-R3-10 | Minor | Lock pin without fixture | Fixture and selftest |

## Recurring Issue Check (round 3)

### Functionality expert
R1 N-a; R2 resolved; R3 checked; R4 N-a; R5–R9 N/A; R10 checked; R11 N/A;
R12 N-a; R13–R15 N/A; R16, R17 checked; R18 N-d; R19–R21 N/A; R22 checked;
R23, R24 N/A; R25 resolved; R26–R28 N/A; R29 re-verified; R30, R31 N/A; R32
checked; R33 N/A; R34, R35 checked; R36, R37 N/A; R38 resolved; R39 N-b; R40,
R41 resolved; R42, R43 checked; R44–R48 N/A; R49 N-c; R50 checked; R51 N/A;
R52 checked; R53 resolved; R54–R57 N/A.

### Security expert
R1, R2 OK; R3 R3-2; R4–R11 N/A; R12 OK; R13–R16 N/A; R17, R18 OK; R19–R28
N/A; R29 OK; R30, R31 N/A; R32 OK; R33 N/A; R34, R35 OK; R36, R37 N/A; R38 OK;
R39 R3-2; R40–R43 OK; R44–R46 N/A; R47–R53 OK; R54 N/A; R55 OK; R56, R57 N/A;
RS1, RS2 OK; RS3 R3-3; RS4 OK; RS5 R3-1; RS6 OK.

### Testing expert
R1 N/A; R2 watch; R3 resolved; R4 R3-1; R5, R6 N/A; R7 resolved; R8–R11 N/A;
R12 resolved; R13–R15 N/A; R16 resolved; R17 watch; R18 resolved; R19–R28
N/A; R29 checked (kani-gate cover enforcement true); R30, R31 N/A; R32 OK;
R33, R34 N/A; R35 OK; R36, R37 N/A; R38 R3-3; R39 R3-2, R3-3; R40, R41 OK; R42
partial (R3-6, R3-10); R43 N/A; R44 OK; R45 watch; R46 N/A; R47 OK; R48 N/A;
R49 OK; R50 resolved; R51, R52 N/A; R53 note (R3-8); R54–R57 N/A; RT1, RT2 OK;
RT3 watch; RT4 R3-4, R3-5; RT5, RT6 OK; RT7 R3-5, R3-6, R3-7, R3-10; RT8 OK;
RT9 watch; RT10 R3-6; RT11 watch.

# Review round 4
Date: 2026-10-24

## Changes from Previous Round

Plan v4 (b7aa69f). Security: S-R3-1/2/3 and S-N7 resolved; two Minors
(prose; one reachable only by building), no design finding — saturated in
its scope. Functionality: F-N-a…d resolved; one Major (socket-storage wipe
order infeasible with smoltcp) and one prose Minor. Testing: T-R3-1…10
resolved; one Major (no gate sees the `tls` stack-scrub mutation) and three
Minors.

## Merged findings and dispositions (plan v5)

| ID(s) | Sev | Subject | Resolution |
|---|---|---|---|
| F-R4-1 | Major | smoltcp owns socket storage; "wipe before abort RST" infeasible | Abort and poll (RST out), then remove, wipe and re-create in the same event-loop pass; barrier = abort RST then a fresh SYN answered in a later pass |
| T-R4-1 | Major | `tls` stack scrub after `exchange` has no detecting gate | ct-harness residue case for `exchange` + scrub; RESIDUE-CASES; selftest under `ct` |
| F-R4-2, S-R4-1 | Minor (prose) | close_notify sealing order; the wait cannot decrypt | Seal, wipe, transmit; the wait ends on any inbound record or FIN, undecrypted |
| S-R4-2 | Minor (build-reachable) | IP-mode leaf CN vs `invalid` dNSName constraint | Empty subject in IP mode; IP-mode positive fixture |
| T-R4-2 | Minor | Held connections may idle out | Backend sends a byte to each between cycles |
| T-R4-3 | Minor (build-reachable) | Red-proof magnitude | Lowered budget makes the per-call wait several times the bound |
| T-R4-4 | Minor (prose) | Rosenpass setup for `https-contention` | Reuses the cookie boots' installation |

## Recurring Issue Check (round 4)

### Functionality expert
R1–R3 checked; R4 resolved; R5–R11 N/A; R12 resolved; R13–R15 N/A; R16,
R17 checked; R18 resolved; R19–R21 N/A; R22 checked; R23, R24 N/A; R25
checked; R26–R28 N/A; R29 checked; R30, R31 N/A; R32 checked; R33 N/A; R34,
R35 checked; R36, R37 N/A; R38 R4-1, R4-2; R39 R4-1; R40 checked; R41 R4-1;
R42, R43 checked; R44–R48 N/A; R49 resolved; R50 checked; R51 N/A; R52, R53
checked; R54–R57 N/A.

### Security expert
R1–R3 OK; R4–R11 N/A; R12 OK; R13–R16 N/A; R17, R18 OK; R19–R28 N/A; R29 OK
(R4-2 note); R30, R31 N/A; R32 OK; R33 N/A; R34, R35 OK; R36, R37 N/A; R38 OK;
R39 OK (R4-1 prose); R40–R43 OK; R44–R46 N/A; R47–R53 OK; R54 N/A; R55 OK;
R56, R57 N/A; RS1–RS6 OK.

### Testing expert
R1 N/A; R2 watch; R3, R4 resolved; R5, R6 N/A; R7 resolved; R8–R11 N/A; R12
resolved; R13–R15 N/A; R16 resolved; R17 watch; R18 resolved; R19–R28 N/A;
R29 checked; R30, R31 N/A; R32 OK; R33, R34 N/A; R35 OK; R36, R37 N/A; R38
resolved; R39 R4-1; R40–R42 OK; R43 N/A; R44 OK; R45 watch; R46 N/A; R47 OK;
R48 N/A; R49, R50 OK; R51, R52 N/A; R53 OK; R54–R57 N/A; RT1, RT2 OK; RT3
watch; RT4 resolved; RT5, RT6 OK; RT7 R4-1 (R4-3 note); RT8 OK; RT9 watch;
RT10 resolved; RT11 watch.

# Review round 5
Date: 2026-10-24

## Changes from Previous Round

Plan v5 (565135c). Security: S-R4-1/2 resolved; two prose Minors (R5-1
fatal alerts share the seal-then-wipe order; R5-2 critical SAN for an
empty-subject leaf) — no design finding. Functionality: F-R4-1/2 resolved;
two Minors (R5-1 RST dispatch before removal, design; R5-2 no outside poll
between RST and wipe, prose). Testing: T-R4-2/3/4 resolved, T-R4-1 partly;
one Major (R5-1 residue case not bound to the shipped build) and two Minors
(R5-2 scrub in the library, R5-3 barrier SYN rate-limited).

## Dispositions (plan v6)

| ID | Sev | Resolution |
|---|---|---|
| T-R5-1 | Major | libcrux crates `=`-pinned in tools/ct-harness to the root lock; ct-shape identity roots for `exchange` and the scrub in pd-tls |
| T-R5-2 | Minor | `tls_core::scrub_session_stack` and `SCRUB_DEPTH_EXCHANGE`; the harness asserts the high-water |
| T-R5-3 | Minor | Barrier SYN from an otherwise unused address, bounded retries, distinct failure message |
| F-R5-1 | Minor | Remove and wipe once the RST is dispatched; retried up to 8 passes, then removed anyway |
| F-R5-2 | Minor (prose) | No outside poll between the RST-emitting poll and the wipe |
| S-R5-1 | Minor (prose) | Order covers close_notify or a fatal alert |
| S-R5-2 | Minor (prose) | Critical SAN on the IP-mode leaf |

## Recurring Issue Check (round 5)

- Functionality: R38 R5-1; R39 resolved; R41 R5-1; R49 R5-2; all other rules
  checked or N/A as in round 4.
- Security: R3 R5-1 (prose); R29 RFC 5280 §4.2.1.6 cited; all other rules OK
  or N/A as in round 4.
- Testing: R2 watch; R3 R5-1; R16 partial (R5-1); R39 partial (R5-1, R5-2);
  R49 R5-1; R50 partial; RT1 R5-1; RT5 R5-2; RT9 watch; all other rules as in
  round 4.

# Review round 6
Date: 2026-10-24

## Changes from Previous Round

Plan v6 (d20ce32). Security: S-R5-1/2 resolved, **no findings**.
Functionality: F-R5-1/2 resolved; two Minors, both labelled reachable only
by building (R6-1 RNG-generic identity root and `#[inline(never)]` scrub;
R6-2 no public smoltcp observable for "RST dispatched"). Testing: T-R5-1/2/3
resolved; two design Minors (R6-1 ct-shape has no identity-only root class;
R6-2 the retry-exhausted wipe path is untested). No Critical or Major open.

## Dispositions (plan v7)

| ID | Sev | Resolution |
|---|---|---|
| F-R6-1 | Minor | Non-generic inner root taking randomness as bytes; generic shim excluded by name; scrub `#[inline(never)]` from the caller's frame |
| F-R6-2 | Minor | RST observed in `tls`'s own `Device` transmit path |
| T-R6-1 | Minor | ct-shape identity-only root class with fixtures, CT-SHAPE-FIXTURES, selftest |
| T-R6-2 | Minor | Close sequencing in `tls-core::conn` with unit tests; mutation; the storage wipe's red-proof scope stated |

Security's out-of-scope observation (the backend socket storage wipe has no
integration observable) is answered by T-R6-2's stated scope.

# Review round 7
Date: 2026-10-24

## Changes from Previous Round

Plan v7 (2a07f9a). Functionality: F-R6-1/2 resolved; one prose Minor
(R7-1: name the non-generic identity root; the close sequence applies to the
backend socket too). Testing: T-R6-1/2 resolved; one prose Minor (R7-1:
the storage wipe is a declared gap, not a red-proof). Security: no findings
since round 6. Both prose Minors are applied in the final plan.

## Saturation call

Round 7 meets all four conditions: (1) seven rounds completed; (2) no
Critical or Major open in any category; (3) no finding against the design —
the experts labelled both round-7 findings prose; (4) every remaining Minor
was prose-only, and both are applied. No finding is carried forward, so the
plan has no `Carried-Forward Plan Findings` section. Every contract is
locked.

Recorded Recurring Issue Check (round 7): functionality R3 R7-1(b), R38/R41
resolved, R50 resolved with R7-1(a), others N/A or checked; testing R49
R7-1 (prose), R3/R4/R7/R12/R16/R18/R52 resolved, R2/R17/R45/RT3/RT11 watch,
others OK or N/A.

# Re-plan R1 review (rounds 1–3)
Date: 2026-10-24

Trigger: the slice-3b probe (TlsSignHighWater 0.64–1.72 s on `tls`'s 0.05)
fired D3; R1 moves the TLS signing key into its own key PD.

- **Round 1** (security S F1–F6, functionality F1–F12, testing T1–T13):
  all three experts found the first draft's non-passive `tlskey` wrong
  (0.2 of tainted-driven CPU outside the 0.95 cap at priority 135, over
  the VPN). Also found: BootSeed with no source, the tpm PD's two-client
  arbitration, descriptor v2 details (0x50 hash, all-pair disjointness),
  gate enrolment, the test migration. R1 rewritten with a **passive**
  `tlskey` (8fedace).
- **Round 2:** security: all resolved, two prose Minors (budget stated,
  RM6-7/8 adversarial rate). Functionality and testing: "exactly one
  caller" broke ~25 laws fixtures (→ at most one, under L2); Busy order
  in the gate (after every refusal, before `once()`, no side effects,
  RSP_BUSY); the seed test needed a fixed Hw seam and scalar
  independence; per-line boot.cmd red-proofs; case 12 made positive (its
  numeric bound was timing-fragile); `limits` leaf crate instead of
  `layout`. Applied (9170f92, bb2ff0e).
- **Round 3:** functionality and testing: all round-2 findings resolved;
  three Minors (Fresh attacker, `limits` no_std + a unit test, the
  flush-reuse harness's ownership check). Applied (7987dc3 and the next
  commit). Security had no open findings after round 2.

Saturation: no Critical or Major open in any category, no design finding
open, the last Minors applied. C12 locked.

## Re-plan R2 review, round 1 (2026-10-25)

R2's first draft proposed two changes: one ClientHello per pass with a rotating index, and an
outside egress after each connection. Three experts reviewed it.

- **Functionality.**
  - Major:
    - F1: a deferred hello schedules no pass.
    - F2: rotation ignores the admission deadline.
    - F3: the holder's sign runs before others' Finished.
    - F4: the egress timestamp is stale, no notify goes out mid-pass, and the effect cannot be pinned.
    - F5: no capacity contract.
  - Minor:
    - F6: the deferral point, the phase guard and the turn unit.
    - F7: a half-closed client.
- **Security.**
  - Major:
    - S1: silent turn holders, with no follow-up pass.
  - Minor:
    - S2: the time bound.
    - S3: the fragmented hello.
    - S4: the FIN claim was wrong; an RST is dropped at the TLS tier after the slot is released.
- **Testing.**
  - Major:
    - T1: no follow-up pass.
    - T2: staggering controls neither change.
    - T3: a time threshold is flaky both ways.
    - T4: rotation can't be red-proved without re-arrival.
    - T5: there is no counter line.
    - T6: fix-or-record has no repro budget.
  - Minor:
    - T7: fragments.
    - T8: wiring and the host name. mrx33 is a third worker set up the same day, so this needs no change.

All are resolved in R2's revision; each resolution is cited inline as R2-F*/S*/T*:

- earliest-admission turn;
- the hello served last after an egress;
- another pass while a hello waits;
- fresh egress time;
- per-connection egress dropped;
- the capacity contract with a trigger;
- the bare-RST Answer-tier exemption with an R43 bound;
- per-port diagnosis with backend receipt;
- the ordering predicate instead of a time threshold;
- the stated reproduction budget.

Diagnosis runs since round 1: 3 more runs, 24 of 24 handshakes complete; the 25.5 s stall did not
recur.

## Re-plan R2 review, round 2 (2026-10-25)

- **Functionality.**
  - Resolved: F1–F4, F6 and F7 (accepted by design).
  - F5 continuing as N2 (Major): the evidence already breaks the capacity trigger.
  - New: N1 (Major), the RST exemption breaks I8 and its proofs, and its R43 bound is false. N3 (Minor), where `after_egress` goes. N4 (Minor), step 3 and the wiring are not pinned.
- **Security.**
  - Resolved: S1–S3.
  - New: S5 (Major), the bare-RST exemption. A compromised `tls` can send RSTs to any address, and a remote attacker can elicit them; either takes the answer and unsolicited buffers. Recommended: no exemption, recorded as a residual.
- **Testing.**
  - Resolved: T2, T3, T6–T8. T1, T4 and T5 partly resolved.
  - New: N1 (Major), the test-gate needle depends on host load because other failures fire before the predicate. N2 (Minor), no per-port backend receipt and no ServerHello definition. N3 (Minor), the turn mutation is ambiguous. N4 (Minor), the PD wiring is unpinned. N5 (Minor), the RST pair could not tell the tiers apart.

Resolved in R2's revision (rounds 1–2):

- **RST loss:** no exemption, recorded as a residual, plus a unit pin of the TLS tier for a bare RST|ACK (S5/F-N1; T-N5 adapted).
- **Capacity:** the `HS_CAP` mechanism is decided now; its value comes from C13's measurement with a stated formula, and refusals are audited `TlsClosed(HandshakeCap)` (F5/N2).
- **RST bookkeeping:** `after_egress` and `after_sign` run once per pass, after the last egress (F-N3).
- **Wiring:** a check-pins rule for `Pass::serve`'s `pass_due`; steps 3 and 6 recorded as review-only (F-N4, T-N4).
- **Ordering predicate:** judged first, over whatever was observed, with every red case defined (T-N1).
- **Per-port observation:** the `X-Probe` marker, the backend's first-chunk time, and the first ServerHello defined (T-N2).
- **Turn mutation:** ignore `since`, pick the lowest eligible index (T-N3).
- **Timeout unit test:** reworded as a `tick` regression.

## Re-plan R2 review, round 3 (2026-10-25)

Every round 2 finding is resolved, apart from part of T-N4 (the check-pins anchor).

New findings:

- **Functionality.**
  - R3-F1 (Minor): "admitted" cannot be observed.
  - R3-F2 (Minor): the two `HS_CAP` rules can disagree, and the measurement conditions are not stated.
  - R3-F3 (Minor): the cap's stated purpose is wrong, its residuals are unrecorded, and the refusal precedence is not set.
- **Security.**
  - S6 (Minor): `HS_CAP` has no floor, so a single source could lock out new handshakes.
- **Testing.**
  - T-R3-1 (Major): below 3 admitted, the predicate is red on correct code; `c` is sensitive to outliers.
  - T-R3-2 (Major): "admitted" cannot be observed, and exactly `HS_CAP` admitted is a race.
  - T-R3-3 (Minor): the coalescing order is an unstated dependency.
  - T-R3-4 (Minor): main.rs has three `fn serve`, so the check-pins anchor is ambiguous.
  - T-R3-5 (Minor): the cap test cannot be built when `HS_CAP = MAX_CONNS`.
  - T-R3-6 (Minor): the manifest deltas are not listed.

Resolved in R2's revision (rounds 1–3):

- **`HS_CAP`:**
  - a compile-time assert of 3 ≤ `HS_CAP` ≤ `MAX_CONNS`, with both reasons stated;
  - a result below 3 is a D3 stop;
  - the value is measured with the cap inert;
  - `c` and `L` come only from runs that met the completion rule;
  - `min(MAX_CONNS-1, ⌊⅔T/c⌋)` applies when the first rule fails;
  - `admit_with_cap` takes the cap as a parameter;
  - the precedence is PerSource > HandshakeCap > Full;
  - the purpose is restated as a latency bound;
  - the residuals (the real-source lockout threshold, refusal slot occupancy) go under RM6-7.
- **The probe:**
  - admitted versus refused is classified per port from the sniffer, using a one-sided RST-before-timeout bound;
  - admitted ≥ min(`HS_CAP`, conns), and no TlsTimeout line;
  - admitted with no ServerHello gets its own needle;
  - the refusal audit is expected iff the sniffer saw a refusal, and the ordering dependency is recorded.
- **check-pins:** anchored in `impl Pass for Pass`, fail-if-missing, with deny fixtures and a pins-gate selftest on the real tree.
- **Manifest:** the deltas are listed.

## Re-plan R2 review, round 4 (2026-10-25, one verifier, all perspectives)

Round 3 findings:

- Resolved: R3-F1, R3-F3, S6, T-R3-2 to T-R3-6.
- R3-F2: resolved, but it raised a new problem (N2 below).
- T-R3-1: continued as R4-N1.

New findings:

- **R4-N1 (Major): the floor of 3 undercounts.** `pass_due` starts pass 2 before A's Finished can come back, so A's request reaches the backend only in pass 4's step 3. The floor is now 4, with the reason restated.
- **R4-N2 (Major): the cap is undefined exactly when it is needed.** If queueing at the inert cap times out the 8th handshake on every run, every run counts as a stall and no value results. The fix defines a *capacity* run: the predicate holds, ServerHellos cross in admission order with no outlier gap, and the only failures are TlsTimeout(Handshake) on the latest-admitted ports. A capacity run feeds `c` and sets `L = ∞`. Six runs with no complete or capacity run is a D3 stop.

Also changed: the second timing host is z1mn. mrx33 fails cookie boot a at 4209823 as well (2 of 2), which puts it outside the calibrated timing envelope.

## Re-plan R2 review, round 5 (2026-10-25, one verifier)

- **R4-N1 resolved.** The pass count was checked against the code: A's request leaves in pass 4's step 3, and D's flight is the first that can follow a receipt.
- **R4-N2 partly resolved.** The intent is right; two new findings follow.
- **R5-M1 (Major): admission order cannot be observed.** Ports admitted in the same pass share `since` and are ordered by slot index. The capacity-run definition is now decided only from observable facts: failed ports are among the last k first-ServerHello crossings, or have none; earlier ports completed; the gap rule is defined, with at least 3 gaps and an even-count median. The earliest-deadline order is left to the unit tests.
- **R5-M2 (Major): the measurement runs were not separated from the gate.** Three changes:
  - the probe prints per-port times and classification on its failing path;
  - a capped tree re-runs the gate 3× on gx10 and z1mn;
  - the deviation log records each run's classification.

## Re-plan R2 review, round 6 (2026-10-25, final verification)

R5-M1 and R5-M2 are resolved and consistent.

The end-to-end read against the code found one Major. **R6-M1:** the precedence HandshakeCap > Full made `HS_CAP = MAX_CONNS` non-inert, because every new slot opens in Handshake. The existing `table_is_full_at_max_conns` would go red on correct code.

Resolution, as R6-M1's first option and R3-F3's suggested order:
- The precedence is PerSource > Full > HandshakeCap. HandshakeCap now means a free slot was withheld.
- The unit tests pin Full with no free slot, and the inertness at `cap = MAX_CONNS`.

Everything else checked clean in this round:
- the floor-of-4 pass trace;
- the lockstep mutation, red on both the inert and the capped tree;
- the boot's case order versus HandshakeCap;
- the check-pins anchor;
- the fixture count.

**Saturation call.** No Critical or Major finding is open.
- R6-M1's fix is the reviewer's own first option, a one-line precedence change together with the restated tests.
- It touches no other part of R2: the measurement, the probe and the gates are unaffected, because Full and HandshakeCap differ only when no slot is free.

C13 is locked.

## R2 amendment A1 review (2026-10-25, one verifier, all perspectives)

One Major: the "some client's Finished precedes the last first-ServerHello" predicate is fooled by a lockstep that runs in two waves. The mutation serves the hellos complete at each pass start, and a hello arriving a few ms late splits the batch. The fix judges every consecutive pair by first-ServerHello order. A port's Finished is its first client payload past the end of its ClientHello.

Checked clean:
- **CCS.** OpenSSL's compat CCS follows the server Finished, and tls-core accepts it only in AwaitClientFinished.
- **The sniffer data.** It supports the predicate; one new field is needed.
- **HS_CAP=3 against the other cases.** All of them complete their handshakes one at a time.
- **No security regression** beyond RM6-7.

Stale R2 text and the conn.rs assert are noted as superseded in A1. Resolved in A1; no Critical or Major finding remains open.

## Re-plan R3 review (2026-10-25, one verifier)

Four Major findings, all resolved in R3's revision:

- **F1. The step harnesses bounded the whole remainder, not the element.** Fix: `rest` is symbolic up to MAX_HEAD, with the delimiter assumed within the element bound; the no-delimiter case is a separate harness.
- **F2. The step properties were too weak for the rewrite arithmetic.** Fix: `next_line` gets an exact decomposition; `field_line` asserts that `f.line` is the line; `Writer::put` gets a frame condition and Ok iff it fits. These are now the acceptance criteria.
- **F3. The decision overclaimed "every length", and the composed bound ignored the per-line bounds.** Fix: the claim is withdrawn; all bounds are tabled, the theorem takes their minimum, the per-line bounds are raised where they can be, and `is_ipv6` has a piece-step fallback.
- **F4. Only a table pinned the `next_option` replacement, which is security-relevant.** Fix: the old splitter stays as a `cfg(test)` reference, a bolero differential compares against it, the edge cases have a table, and the None semantics are specified.
