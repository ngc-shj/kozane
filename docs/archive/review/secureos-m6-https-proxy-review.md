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
