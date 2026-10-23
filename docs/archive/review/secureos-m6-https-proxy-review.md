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
