# Plan Review: secureos-m2-5-cookies-keepalive
Date: 2026-10-19
Review round: 1

## Changes from Previous Round
Initial review. Local LLM pre-screen findings (dependency direction, constant homes, keepalive on `previous`, C5 naming) were applied before the round; "Cookie is not a secret" was rejected (bearer token for an (ip, port)). Merge done manually (Ollama merge skipped for latency; json indices joined by hand).

## Merged findings (dedup, perspective convergence)
| Merged | Sources | Severity | Label | Subject |
|---|---|---|---|---|
| M1 | Func F1, Test F1 | Critical | design | C6 flood cannot reach under-load on the user-net topology |
| M2 | Test F2, Func A1-part | Critical | design | Handshake-under-flood passes vacuously (old session, load oscillation, no mac2 attribution, peer 0) |
| M3 | Test F3, Func A1 | Critical | design | "No HandshakeKeyRateLimited" has no positive control |
| M4 | Sec S1, Func F2 | Major | design | Global cookie-reply cap starves legitimate clients; TX ring contention |
| M5 | Sec S2, Func F4 | Major | design | Key-budget invariant omits the 64-deep ih backlog and the boot-seed token |
| M6 | Func F3 | Major | design | Under-load signal blind to hs backlog |
| M7 | Func F5, Sec S3, Test F5-part, Func A2 | Major | design | Secret type home breaks ingress-core deps/Kani; secret passed by value |
| M8 | Func F6 | Major | design | Audit events without producer; Mac2Invalid unreachable; nonce failure undefined |
| M9 | Func F7, Sec S5 | Major | design | Rotation gap every 120 s; no retry after RNDR failure |
| M10 | Test F4 | Major | design | No unit oracle for the XChaCha reply; PD adapter port binding untested |
| M11 | Test F5, F6 | Major | design | Kani vacuity, stub over-approximation, (c)/(d) unproved |
| M12 | Test F7, Func F10-part | Major | design | C5 red-proof covers one clause; per-path key calls |
| M13 | Test F8, Func F12 | Major | prose | Manifest / selftest / Kani / seed / file list incomplete; stale SC13 text |
| M14 | Sec S4 | Minor | design | Per-reply RNDR couples attacker rate to the shared RNG |
| M15 | Sec S6, Func F10 | Minor | prose | Member sets wrong/narrow; L4 not L5 |
| M16 | Sec S7, Func F9 | Minor | prose | Citation fixes (port byte order, keepalive semantics, names, peer numbering, retransmit jitter) |
| M17 | Sec S8 | Minor | design | Timer-exemption clauses for the new channel not red-proved |
| M18 | Func F8 | Minor | design | mac2 needs a 16-byte-key BLAKE2s MAC |
| M19 | Func F11, Test F9 | Minor | design | Keepalive loop semantics; keepalive case timing/evidence/ordering |

Resolution for every merged finding: reflected in plan rev 2 (see plan; obligations cite these IDs).

## Functionality Findings
# Functionality expert — Round 1
Verified: 3 key calls (noise.rs:166,177,214), key bucket 256/0.5ms, timer 1 Hz, xchacha module, keepalive reuses ToIngress::Outbound.
F1 Critical design (R50,R29): C6 flood infeasible on user-net topology (run.py:12-13,626): single source 10.0.2.2; per-IP bucket (lib.rs:154,177-178) caps at 20/s < 200/s refill → never under load; selftest passes for wrong reason. Fix: tap/bridge in netns, AF_PACKET spoofed flood; loud precondition (>64 distinct sources reached ingress, WgUnderLoad before peer traffic); allow side without flood.
F2 Major design (R29): global cookie-reply cap starves legit clients; values unspecified; wireguard-go has none; not needed for amplification. Fix: size from ingress L13 budget or drop; residual; C6 flood rate vs cap; paired tests.
F3 Major design (R29): under-load proxy (forward bucket) does not observe hs backlog; hs (0.2 budget, ~5 X25519/handshake incl. key's on hs SC) may be slower than 200/s → flood at 150/s never triggers load, ih ring full, legit initiations dropped at pdkit::send (main.rs:198). Fix: (b) enter load when to_hs in-flight >= NET_RING_SLOTS/8 (wireguard-go), needs occupancy accessor in ring::link/pdkit::Tx; (a) measure hs cost, set FORWARD_INTERVAL_NS with headroom; both-side tests.
F4 Major design (R29,R42): C5 omits 64-deep ih queue: 64 queued + 64 forwarded = 384 calls > 256. Fix: (FORWARD_BURST + ring depth)*3 <= KEY_BURST → FORWARD_BURST <= 21; hs-core dev-dep layout; or weaken claim.
F5 Major design (R29,R10): Gate holds wg-core CookieSecret → libcrux in ingress-core, breaks Kani and C5 no-cycle claim. Fix: secret owned by PD adapter behind CookieCrypto (rotate(fresh)->bool, clear()); Gate keeps born_ns only; (c) provable in Kani; removes by-value [u8;32].
F6 Major design (R4,R12): WgUnderLoad / CookieSecretUnavailable have no producer (classify returns one Outcome, tick returns ()); Mac2Invalid unreachable per design table; nonce RNDR failure undefined. Fix: TickReport{entered_load,left_load,secret_unavailable}, take_load_entered(); seal_reply draws nonce internally → None on failure; Outcome→Event table; transition tests paired.
F7 Major design (R38): tick-only rotation → ~1 s fail-closed gap per 120 s (wireguard-go lazy, no gap); CookieSecretUnavailable mis-attributed; no retry after RNDR failure. Fix: rotate at MAX_AGE-2 ticks (118 s), 120 s backstop with own event; retry every tick while none; tests per clause.
F8 Minor design (R29): mac2 keyed with 16-byte cookie; crypto::mac fixed 32-byte key (crypto.rs:90); BLAKE2s param block encodes key length. Fix: state key length; 16-byte keyed MAC.
F9 Minor prose (R29): (a) wireguard-go port LE; (b) needAnotherKeepalive not equivalent (wg sends second keepalive) — say flag unnecessary; (c) wg arms on any non-empty authenticated packet and clears on handshake response sent — record deviations; (d) scenario 4: keepalive prevents peer's new-handshake timer (15 s), not firewall; (e) retransmit 5 s + jitter up to 333 ms; (f) constants are BUCKET_BURST/BUCKET_INTERVAL_NS; (g) layout asserts, not generates; (h) timer-role laws case is new; (i) wireguard-go is peer 0.
F10 Minor design (R42): rg 'Outcome::Initiation' already 6 hits (tests/proofs); add rg 'self\.to_hs' =1; key calls per exit path (UnknownPeer 1, Decrypt/Replay/Flood 2, success 3).
F11 Minor design: keepalive loop stops on seal failure → remaining peers delayed; per-call invariant vacuous. Fix: keepalive() clears failing peers internally; invariant per unacked cycle; call after outbound drain (pds/data/main.rs:211-221).
F12 Minor prose (R3): no file list: ingress-core lib/proofs/tests (Outcome +4, respond/udp/classify params, SC13 docs lib.rs:127-132,196-200); pds/ingress main (arms 150-195, timer, doc "Holds no secret", separate cookie buffer since reply used by to_peer); audit-event (enum, code, FIXED, name, slot, FIXED_SLOTS 31→36, tests.rs:157); layout lib/tests (CH_INGRESS/CH_TIMER); pds/timer PEERS; secureos.system; laws.toml; key-core, pds/key, hs-core dev-deps; wg-core cookie, KEEPALIVE_TIMEOUT_NS, 16-byte MAC, XChaCha; wg-wire; data-core; pds/data; run.py; manifest (UNIT-*, UNIT-TESTS, KANI-*, CHECK-SELFTEST-FIXTURES); check-selftest needle 9<10, CASES_FOR_GATE, SC13→SC20 comment; architecture R6; deviation log.
A1 [Adjacent Major]: C6 gate proof (mac2 removed) cannot redden no-HandshakeKeyRateLimited (held by forward bucket); key passive on hs's 0.2 budget may make it unreachable on TCG. Fix: mutation disabling forward bucket requiring HandshakeKeyRateLimited, else rewrite claim.
A2 [Adjacent Minor]: tick passes secret as Copy [u8;32] (L12 residue); F5 removes.

## Security Findings
# Security expert — Round 1
Verified: 3 key calls (noise.rs:164,176,214; replay path 2), key bucket 256/0.5ms (pds/key/main.rs:25-26), timer 1 Hz, RNDR EL0 via cpu, libcrux xchacha module, mac2 over msg[..132], cookie key HASH("cookie--"||S_pub).
S1 Major design (RS2,R53,R43): global cookie-reply cap → spoofed flood starves real clients of cookies (wireguard-go has no cookie limiter); unsized; replies share to_driver ring (64) with data TX. Fix: size cap from measured ingress mac1 throughput (cap binds only where input already shed); reserve TX slots for data/hs; C6 flood >=10x cap, assert measured rate, selftest for vacuous low flood.
S2 Major design (R29,R49): key-budget invariant omits ih ring backlog (NET_RING_SLOTS=64, layout/lib.rs:7) drained by hs while-recv loop (pds/hs/main.rs:139) and hs boot_seed token (key-core:179). Correct bound (FORWARD_BURST+NET_RING_SLOTS)*3 <= KEY_BURST-1; fails at 64. Fix: include ring term; FORWARD_BURST 16 → 240<=255, or shallower ih ring; selftest per term; or downgrade class.
S3 Minor design (R39,R42,L12): CookieSecret in wg-core contradicts ingress-core deps/Kani; tick passes [u8;32] by value (unzeroized move). Fix: secret type in ingress-core/leaf crate, zeroize, no Copy/Clone/Debug, CookieCrypto takes &; fresh: FnOnce(&mut [u8;32])->bool in place; paired test failing fill → None.
S4 Minor design (R43,L9): RNDR per cookie-reply nonce couples attacker rate to shared RNG used fail-closed by hs (hs-core:121). Nonce needs uniqueness only. Fix: nonce = BLAKE2s(secret||counter)[..24]; RNDR only for rotation; else specify failure path.
S5 Minor design (R38): rotation only at expiry → up to ~1 s NoCookieSecret per 120 s. Fix: rotate at age >= MAX_AGE - 2 ticks; test continuous ticks never NoCookieSecret (allow) / RNDR fail → NoCookieSecret (deny).
S6 Minor prose (R42,R49): member set misses PD-side to_hs (pds/ingress/main.rs:207); cite L4 not L5. Fix: rg 'self\.to_hs' pinned.
S7 Minor prose (R29): wireguard-go uses little-endian port (AddrPort.MarshalBinary); Linux cookie.c uses be16. Cite kernel or say local/opaque; note on-path observer can decrypt cookie replies (public key) — accepted by whitepaper.
S8 Minor design (R43,RT7): C4 selftest should red-prove timer exemption for new channel: flip notify ingress=true → must fail "timer pd tainted" (L1); committed notify={timer=true,ingress=false} passes.

## Testing Findings
# Testing expert — Round 1
F1 Critical design (RT2,RT5,RT7): C6 flood cannot reach under-load. Boot 2 outside NIC is QEMU user-net hostfwd (run.py:626) — all sources appear as 10.0.2.2; per-source bucket (20/s) < forward refill (200/s). Spoofed sources only on boot 1 dgram link without wireguard-go. Fix: tap in netns (10.0.2.2/24, MAC=outside_router_mac) + AF_PACKET spoofed injection, preflight probes raising Fail; harness asserts its own flood rate (>=11 distinct sources, >200/s). Fallback: dgram boot + Python initiator with independent XChaCha oracle.
F2 Critical design (RT4,RT8) [Adjacent Major: load oscillation]: handshake-under-flood vacuous — wireguard-go is peer 0 not peer 1; it already has a session; load self-cancels (mac2-invalid not forwarded → bucket refills → load ends after 1 s) so retry may land off-load; no audit attribution. Fix: force fresh handshake (restart / re-add peer; assert latest_handshake changed); audit event for mac2-valid forward under load, ordered after WgCookieSent to wg endpoint and before HandshakeOk; flood persists across retries; selftest needle names attribution assertion.
F3 Critical design (RT4,RT7): "no HandshakeKeyRateLimited" absence assertion has no positive control; forward bucket+C5 prevent it independently of cookies; hs under TCG may not reach >667 init/s. Fix: selftest bypassing forward bucket requiring HandshakeKeyRateLimited to appear, or drop the clause and carry key-unreachability on C5+Kani; record measured hs handshake rate (R53).
F4 Major design (RT5,RT1): no unit oracle for XChaCha cookie reply; PD CookieCrypto adapter untested; wireguard-go cannot detect port-ignoring adapter. Container has cryptography 43 (ChaCha20Poly1305, ChaCha20) + hashlib.blake2s → pure-Python HChaCha20 golden vector; libcrux XChaCha KAT (draft §A.3.1); wg.py opens cookie replies/sets mac2; paired integration allow (same ip:port) / deny (other port → WgMac2Invalid + new reply).
F5 Major design (RT4,RT7): Kani (a)/(b) vacuous from default Gate (needs >32 forwards); no covers. CookieSecret (wg-core type) in Gate pulls libcrux into ingress-core → kills Kani, contradicts C5 dependency claim. Fix: symbolic Gate start; covers for CookieReply, Mac2Invalid, CookieRateLimited, NoCookieSecret, Initiation-under-load, RateLimited; (b) on bucket type directly + one-step classify harness; secret generic / ingress-core local.
F6 Major design (RT1): stub leaves (c)/(d) unproved; seal_reply stub over-approximates lengths; fresh closure unconstrained. Fix: recording stub, Kani asserts no crypto call when mac1 false (d) and now-born<MAX_AGE at every call (c); stub returns Some(COOKIE_REPLY_LEN)|None; cover fresh None/Some.
F7 Major design (RT7): C5 red-proof covers only burst clause; interval clause and per-path max key calls not proven (reject paths). Fix: counting wrapper per outcome path (<=, == on accept); separate selftest cases per clause with own needles; mutation adding extra key call.
F8 Major prose (R3,RT7): manifest/selftest list incomplete — UNIT-* per crate, KANI-HARNESSES/KANI-INGRESS-CORE/KANI-WG-WIRE; CookieReply *_parse_is_total harness; CASES + CASES_FOR_GATE entries; C4 laws case needs own law-ID needle (existing laws case injects unknown element → L4); integration-count needle 9<10; bolero seed-cookie-reply; stale SC13 text in tools/package:19,44, check-selftest:143, Makefile:75, test_package.py.
F9 Minor design (RT4,RT10): keepalive timing origin/evidence: measure from host send / inside receipt; decrypt with recv key, assert empty plaintext; at-most-one window; deny side positive control (echo reply seen); run keepalive before flood; unit tests: second data doesn't move unacked_since, rejected packet doesn't arm, backward clock.

## Adjacent Findings
- Test F2 → Func: load oscillation (merged M2/M6). Sec S1 → Test: flood rate unpinned (M4). Func A1 → Test (M3). Func A2 → Sec (M7).

## Quality Warnings
None (every finding cites plan section or file:line).

## Recurring Issue Check
Each expert's full R1–R57 (+RS1–RS6 / RT1–RT11) check is preserved verbatim in the expert outputs archived at the time of the round; summary of non-N/A statuses:
### Functionality expert
R2 checked; R3 F12; R4 F6; R10 F5; R12 F6; R13 checked; R16 F1; R18 checked; R29 F2,F3,F4,F8,F9; R32 checked; R35 checked; R38 F7; R39 checked (A2); R40 checked; R41 F1; R42 F4,F10; R48 checked; R49 checked (F4); R50 F1; R52 checked (F3); R53 checked (F3); R55 checked; all others N/A.
### Security expert
R1 N/A; R2 OK; R3 S3; R4 OK; R10 S3; R12 OK; R16 OK; R17 OK; R18 OK; R19 OK; R29 S2,S7; R32 OK; R34 OK; R35 OK; R36 OK; R38 S5; R39 S3; R40 OK; R41 OK; R42 S3,S6; R43 S1,S4,S8; R48 OK; R49 S2,S6; R50 adjacent S1; R51 OK; R52 S1; R53 S1; R55 OK; RS1 OK; RS2 S1; RS3 OK; RS4 N/A; RS5 N/A; RS6 N/A; all others N/A.
### Testing expert
R2 OK; R3 F8; R10 OK; R12 OK; R16 OK (F1); R29 F2,F8; R32 OK; R34 OK; R35 OK; R38 adjacent F2; R40 OK; R41 F3; R42 OK; R44 OK; R49 F3; R50 F1,F3; R53 F3; RT1 F6; RT2 F1; RT3 OK; RT4 F2,F3,F5,F9; RT5 F4; RT6 OK; RT7 F3,F5,F7,F8; RT8 F2,F9; RT9 N/A; RT10 OK; RT11 OK; all others N/A.

---

# Review round: 2
Date: 2026-10-19

## Changes from Previous Round
Plan rev 2 addressed M1–M19: arrival meter + backlog load signal, forward cap 16 / 5 ms, ring-aware key bound, no cookie cap with TX reserve, adapter-owned secret, 118 s rotation, derived nonces, tap topology, Outcome→Event table, two-branch key-exhaustion control.

## Round-2 findings (merged)
| ID | Sources | Severity | Label | Subject | Resolution (rev 3) |
|---|---|---|---|---|---|
| R2-1 | Func F1, Test N1 | Critical | design | Audit coalescing / no endpoint make C6 assertions unobservable | Never-coalesced class for transition events; two fresh tap boots; sniffed cookie reply bound to wireguard-go's sender index; attribution by exclusion |
| R2-2 | Func F3, Sec N1 | Major | design | Forward bucket drainable outside load | Forward-below-half as third trigger, Kani (f), arrival/forward ordering asserts + selftests, values set |
| R2-3 | Func F2 | Major | design | in_flight/tx_free stale; tick lacks backlog | Reclaim-then-count accessors; backlog passed to tick_if_due; drain/full tests |
| R2-4 | Sec N2 | Major | design | ingress handler never leaves from_outside under flood (pre-existing, fixed in scope) | Bounded loop K=NET_BUFFERS with from_hs/from_data/tick_if_due each pass; pass_plan unit tests; ingress-unbounded-loop selftest; C6 data-path and hs-response assertions under over-capacity flood |
| R2-5 | Test N2, Sec N3 | Major | design | Load continuity unevidenced; TX reserve as implicit cookie cap | In-guest continuity (no WgLoadCleared, no WgCookieSuppressed); Phase-2 TX vs reply-rate measurement; handshake-class reservation if it binds; residual text |
| R2-6 | Test N3 | Major | design | M3 lacks rule; recorded resolved while pending | Numeric/observable rule, peer-keyed flood, mutation also disables mac2 gating; marked PROVISIONAL with the M3 pending marker, must be decided before Phase 3 |
| R2-7 | Func F4 | Minor | design | TX reserve boundary inconsistent | `> NET_BUFFERS/2` everywhere |
| R2-8 | Func F5 | Minor | prose | Idle clearing vs rotation | Rotation is the only clearing; scenario 3 reworded |
| R2-9 | Func F6, Test N5 | Minor | prose | laws needle / single-file flip | Exact needle, flip both files |
| R2-10 | Func A2, Test N6 | Minor | design | NET_BUFFERS injection trips other gates | Inject into assertion operands |
| R2-11 | Test N4 | Minor | design | integration-cookie may fail at ping first | Attribution evaluated before ping |
| R2-12 | Test N7 | Minor | design | Paired deny side vacuous | Fresh initiation from port B with port-A mac2; positive cookie-at-B signal; total=1 ordering |
| R2-13 | Sec N4, Func note | Minor | prose | Backlog +1 | `NET_BUFFERS + 1` (243 ≤ 255) |
| R2-14 | Func A1 | Minor | design | Key-exhaustion mutation must disable mac2 gating | Included |
| R2-15 | Sec N3 | Minor | design | Skip mac2 MAC on zero mac2 | Invariant (d) extended |

Security checked without finding: nonce derivation (PRF, domain separation), backlog trust.

## Raw expert outputs
# Functionality expert — Round 2
Resolved: M7, M8, M9, M18, M15, M19, M13, M16, M4, M5 (note: hs holds one dequeued initiation → 81×3=243 ≤255; prose +1).
F1 Major design (R40,R29): C6 audit assertions unobservable — records carry no endpoint; producers coalesce (1st, 65th, ...); shared cookie boot consumes first WgUnderLoad/WgMac2Accepted/HandshakeOk in paired case → flood case precondition aborts deterministically. Fix: peer-side attribution (latest_handshake changed + tap capture: type-3 reply to peer0 ip:port then initiation with non-zero mac2); audit only first-occurrence (separate boots) or exempt transition events from coalescing with unit tests.
F2 Major design (R29,R50): in_flight/tx_free stale until reclaim (only via pdkit::send); after flood load sticks forever; tick has no backlog input → left_load flaps. Fix: reclaim-then-count each notified pass and tick; pass backlog to tick; tests (drain → clears after 1 s; full → stays; count after return before send).
F3 Major design (R29,R43): arrival constants unspecified/unordered vs forward bucket → forward bucket can empty outside load → legit RateLimited without cookies. Fix: ARRIVAL_INTERVAL_NS >= FORWARD_INTERVAL_NS, ARRIVAL_BURST < 2*FORWARD_BURST compile-time asserts; unit + Kani (forward exhausted ⇒ under_load); selftest.
F4 Minor design: TX reserve boundary inconsistent (Design >= half vs (e)/test > half).
F5 Minor prose: idle clearing contradicts perpetual rotation; pick one.
F6 Minor prose: needle must be "timer pd 'timer' is tainted" (check.rs:239); state whether selftest edits .system alone (L4+L1) or with laws.toml.
A1 Minor adjacent: key-exhaustion branch-1 mutation must also disable mac2 gating.
A2 Minor adjacent: raising NET_BUFFERS trips ring/layout asserts; inject test-local constant.

# Security expert — Round 2
Resolved: M5 (off-by-one N4), M7, M14, M15, M16, M17, M9 (tick starvation N2); M4 cap gone but TX reserve acts as cap (N3). Checked no finding: nonce HASH(secret||counter) (PRF, domain separated from MAC by param block); backlog trust (hs-only inflation; stale errs toward load).
N1 Major design (R53,R49,RS2): forward bucket drainable outside load (no arrival/forward relation; ARRIVAL unset) → spoofed flood below threshold blocks all handshakes. Fix: forward-below-half as third trigger, or asserts ARRIVAL_BURST/2 < FORWARD_BURST, ARRIVAL_INTERVAL >= FORWARD_INTERVAL with selftests; sequence test deny/allow; record cost of permanent load in R6.
N2 Major design (R34,R38,R50) [Adjacent]: ingress notified() never leaves from_outside under sustained flood (main.rs:152,265-269): tick/rotation, hs responses, data output starve; pre-existing; C6 flood rate too low. Fix: bounded loop K=NET_BUFFERS interleaving from_hs, from_data, tick_if_due(now); or rotation from now in classify; C6 flood above ingress capacity, assert saturation, require hs response, existing-session ping, rotation (no CookieSecretExpired); selftest restoring unbounded loop.
N3 Minor (R43,R29): TX reserve = implicit cookie cap at drain rate; data volume can suppress cookies; cookie work lowers transport capacity. Fix: skip mac2 MAC when mac2 zero; C6 record WgCookieSuppressed; reword claim; handshake-class TX reservation if it binds.
N4 Minor prose (R29): backlog term NET_BUFFERS+1 (hs frees slot before key calls, hs main.rs:139-148): 243 <= 255.

# Testing expert — Round 2
Resolved: F4/M10, F5+F6/M11, F7/M12, F8/M13, F9/M19, F1/M1.
N1 Critical design (RT4,R29): coalescing (totals 1,65,129; COALESCE_EVERY=64, audit-event lib.rs:4-6,31) + no endpoint → flood precondition/attribution unobservable in shared boot; vacuous if wait not anchored. Fix: flood in own boot, exact first-occurrence lines (WgUnderLoad total=1, WgMac2Accepted total=1, HandshakeOk total=1, order); attribution by exclusion (spoofed sources never get cookies); harness sniffs type-3 to wireguard-go port, opens it, receiver == wireguard-go sender index; same rule for paired case or never-coalesced state events with tests; red-prove needle.
N2 Major design (RT4,R53) [Adjacent Major: TX reserve blocks legit cookies]: load continuity not evidenced — send vs processed rate; ARRIVAL/BACKLOG_LOAD unvalued; TCG ingress throughput unmeasured; backlog drains under load; TX reserve may suppress peer 0's cookie. Fix: measure ingress processed rate and eth_out TX rate under TCG; ARRIVAL refill <= half processed; flood bounded above; in-guest evidence (processed rate from coalesced WgCookieSent spacing; no WgLoadCleared between WgUnderLoad and handshake; no WgCookieSuppressed before peer 0 cookie); distinct aborts.
N3 Major design (R50,R53,Anti-Deferral): M3 branch lacks numeric rule; flood with random keys takes unknown-peer path (1 call) → branch 2 near-certain unless flood uses harness-held peer keys (2-call replay path); recorded resolved while pending. Fix: numeric rule (rate×calls > 1/KEY_INTERVAL or burst ≥ KEY_BURST); fix flood composition and measurement method; record M3 provisional with grep-able TODO.
N4 Minor (RT7): integration-cookie red-proof may fail at ping before attribution needle; evaluate attribution first.
N5 Minor prose (RT7,R29): needle "timer pd 'timer' is tainted" (check.rs:239); flip notify in both .system and laws.toml (single flip trips mismatch check.rs:91-98).
N6 Minor (RT7): NET_BUFFERS injection trips ring/layout; inject into assertion operand.
N7 Minor (RT8,RT1): paired deny side vacuous (replay); use fresh initiation with port-A mac2 from port B, assert cookie reply at B + no WgMac2Accepted increment; name load mechanism (spoofed flood in accounted boot).

## Recurring Issue Check (round 2, non-N/A)
- Functionality: R3 checked; R4 F2; R12 checked; R13 checked; R16 checked; R29 F1,F3,F4,F5,F6; R38 checked; R40 F1; R41 checked; R42 checked; R43 F3; R49 checked; R50 F2; R53 checked (F3); others N/A.
- Security: R29 N3,N4; R34 N2; R38 N2; R39 OK; R42 OK; R43 N3 (nonce, backlog checked clean); R49 N1; R50 N2; R53 N1; RS1 OK; RS2 N1; RS3 OK; R2,R4,R10,R12,R16,R18,R19,R32,R35,R36,R40,R41,R48,R51,R55 OK; others N/A.
- Testing: R2,R3,R12,R16,R32,R34,R35,R41,R42,R49 OK; R29 N1,N5; R38 adj N2; R50 N3; R53 N2,N3; RT1 N7; RT2,RT3,RT5,RT6,RT10,RT11 OK; RT4 N1,N2; RT7 N4,N5,N6; RT8 N7; others N/A.

---

# Review round: 3
Date: 2026-10-19

## Changes from Previous Round
Plan rev 3 addressed R2-1..R2-15 (third load trigger, reclaim-then-count, bounded handler loop, never-coalesced transitions, two tap boots, sniffed attribution, M3 provisional).

## Round-3 findings (merged)
| ID | Sources | Severity | Label | Subject | Resolution (rev 4) |
|---|---|---|---|---|---|
| R3-1 | Func F1, Sec P1 | Major | design | Bounded loop leaves notifications/flush at handler end | Notify + audit.flush every pass; pass_plan PassActions; `ingress-late-notify` selftest |
| R3-2 | Func F2, Sec P3 | Major | design | Never-coalesced CookieSecret* mapped from per-initiation outcomes | Edge-only emission from Gate state; per-initiation → coalesced `WgCookieDropped`; 1000-outcome unit test |
| R3-3 | Func F3, Test P1 | Major | design | Flood unbounded above; allow side flaky | Two phases (near-capacity ≤1.5·C for interop/attribution; short ~3·C for data path); budgets sized for <1e-3 failure, recorded; no-flood allow check |
| R3-4 | Func F4, Test P4 | Major | design | Paired case load clears before allow step | Flood persists to allow-step response; no-WgLoadCleared guard; WgLoadCleared within 2 s after stop |
| R3-5 | Test P2 | Major | design | M3 measurement throttled by per-source bucket; weaker branch-1 absence; no mechanical tie | Mutation disables per-source bucket; measured hs rate from totals; peer-keyed absence phase; Go/No-Go row "M3 decision" + Phase-3 entry check for the M3 marker |
| R3-6 | Sec P2 | Minor | design | from_hs/from_data unbounded per pass | All three inputs bounded to K; break only when all < K |
| R3-7 | Sec P4 | Minor | prose | Invariant (d) forbade first-contact cookie | Reworded; Kani cover CookieReply with zero mac2 |
| R3-8 | Func F5 | Minor | design | RNDR retry attacker-paced | RETRY_INTERVAL 100 ms, invariant (g) |
| R3-9 | Test P3 | Minor | design | Sniffer drops / port / sender indices | BPF + SO_RCVBUF + tp_drops abort; fixed ListenPort; match set of sender indices |
| R3-10 | Test P5 | Minor | design | Kani (f) assumption | Under-load computed → (f) definitional |

Testing: the M3 pending marker is acceptable as a carried item (marker satisfies Anti-Deferral item 4). Security checked clean: transition event rates, TX reserve, reclaim, M3.

## Raw expert outputs
# Functionality expert — Round 3
Resolved: R2-2, R2-3, R2-7, R2-8, R2-9, R2-10, R2-13, R2-14; R2-1 direction (F2 remains).
F1 Major design (R4,R29): bounded loop issues no per-pass notifications/audit flush (main.rs:255-271 notifies after drains) → hs/eth_out/data/audit starve while passes stay full; unbounded-loop selftest needle unreachable. Fix: wake + flush each pass (pass_plan Continue{flush}); unit tests; recheck selftest needle.
F2 Major design (R29,R12): never-coalesced CookieSecretExpired/Unavailable mapped from per-initiation outcomes → attacker-rate uncoalesced audit into 128-slot ring. Fix: transition-only emission (TickReport.secret_unavailable, one-shot expired flag); per-initiation → coalesced WgCookieRefused; unit test 1000 outcomes → 1 transition + ceil(1000/64) coalesced.
F3 Major design (R29,R53): flood unbounded above → proportional shedding makes legit success probabilistic beyond 90 s. Fix: band 1.5–3× measured processing rate, harness asserts both bounds; size retry budgets from worst survival; allow-side no-flood check.
F4 Major design (R29): paired case short flood + 1 s hysteresis clears load before allow step. Fix: flood continues until allow step done; assert no WgLoadCleared in window; assert WgLoadCleared after flood stops.
F5 Minor design (R29): per-pass secret retry makes RNDR attacker-paced during failure (contradicts M14). Fix: retry at most every 100 ms / tick; unit test.

# Security expert — Round 3
Resolved: R2-2, R2-5/R2-15 (P4 wording), R2-13; R2-4 partial (P1, P2). Checked clean: WgUnderLoad/WgLoadCleared rate, TX reserve, reclaim, M3 provisional acceptable.
P1 Major design (R3,R49): wake-ups and audit.flush at handler end (main.rs:270-279; pdkit Audit notifies only in flush) → under flood hs/eth_out/data/audit never notified; ring overflow drops transitions. Fix: notify + flush each pass via pass_plan; selftest moving notifications back must fail flood case on hs-response assertion.
P2 Minor design (R49): from_hs/from_data unbounded per pass (main.rs:220,231); inside-originated flood could starve from_outside and tick (QUESTION: data vs ingress throughput unmeasured). Fix: bound all three to K; break only when all < K; tests; narrow claim.
P3 Minor design (R29,R49): never-coalesced CookieSecret* mapped from per-initiation outcomes → attacker-rate uncoalesced records. Fix: edge-only emission; per-initiation → coalesced WgCookieDropped; unit test.
P4 Minor prose (R29): invariant (d) wording forbids seal_reply for zero mac2. Fix: no crypto when mac1 failed; no mac2_valid when mac2 zero; Kani cover CookieReply with zero mac2.

# Testing expert — Round 3
Resolved: R2-1, R2-9, R2-10, R2-11, R2-12, R2-5, new unit tests and selftests valid. The M3 pending marker is acceptable as carried item (marker meets Anti-Deferral 4) given P2 fixes.
P1 Major design (RT4,R53): over-capacity flood sheds legit frames; retry budgets not derived from survival ratio → flaky; conflicting with unbounded-loop red-proof need. Fix: bound offered rate (<=1.5·C) and size budgets for <1e-3 failure; or two phases (near-capacity for attribution/interop, short over-capacity for data-path starvation).
P2 Major design (R50,RT4): M3 measurement keeps per-source bucket (20/s/IP) → branch 2 for wrong reason; branch-1 absence on weaker flood; no mechanical tie. Fix: disable per-source bucket or enough spoofed sources; assert forwarded rate; branch-1 absence with peer-keyed composition; Phase-3 entry check no M3 marker left / Go-No-Go row.
P3 Minor (RT4): sniffer drops under flood, wg-go listen port changes on restart, multiple sender indices. Fix: BPF filter + SO_RCVBUF, PACKET_STATISTICS tp_drops abort, ListenPort / wg show listen-port, match set of sender indices.
P4 Minor (RT4): paired flood must persist through allow step; guard no WgLoadCleared; keep below capacity.
P5 Minor (RT4,RT7): Kani (f) from symbolic Gate — state whether under-load is computed (definitional) or stored (inductive with minimal assume + cover).

## Recurring Issue Check (round 3, non-N/A)
- Functionality: R4 F1; R12 F2; R13 checked; R29 F1–F5; R38 checked; R40 checked; R41 checked; R42 checked; R43 checked; R50 checked; R53 F3; others N/A.
- Security: R3 P1; R29 P3,P4; R49 P1,P2,P3; R34 OK; R38 OK; R39 OK; R42 OK; R43 checked (P3, P2); R50 OK; R53 OK; RS1–RS3 OK; R2,R4,R10,R12,R16,R18,R19,R32,R35,R36,R40,R41,R48,R51,R55 OK; others N/A.
- Testing: R2,R3,R12,R16,R29,R32,R34,R38,R41,R42,R49 OK; R50 P2; R53 P1; RT1,RT2,RT3,RT5,RT6,RT8,RT10,RT11 OK; RT4 P1–P5; RT7 OK, P5; others N/A.

---

# Review round: 4
Date: 2026-10-19

## Changes from Previous Round
Plan rev 4 addressed R3-1..R3-10 (per-pass notify/flush, all inputs bounded, edge-only events + WgCookieDropped, two flood phases with bands and sized budgets, persistent paired flood, M3 measurement without per-source bucket + Go/No-Go row, sniffer hardening, computed under-load).

## Round-4 findings
| ID | Expert | Severity | Label / reach | Subject | Resolution (rev 5) |
|---|---|---|---|---|---|
| R4-S-Q1 | Sec | Minor | design (b) | Secret usability decided twice; infallible make_cookie → zero-key cookie on divergence (fail-open of (a)) | CookieSecret validity flag; make_cookie/reply_nonce → Option; adapter fails closed; deny/allow tests |
| R4-T-Q1 | Test | Major | design | WgLoadCleared within 2 s too short; no lower bound | [1 s, 3.5 s] from named constants |
| R4-T-Q2 | Test | Minor | design (b) | Over-capacity phase not tied to ping budget | Flood runs until ping concludes, asserted |
| R4-T-Q3 | Test | Minor | design (b) | Phase-1 band may be empty; session age | the CF feasibility marker gate (Go/No-Go row CF); session set up before Phase 2 with age check |
| R4-T-Q4 | Test | Minor | prose (a) | Gate lacks last_retry / edge flags | Fields added; Kani symbolic Gate ranges over them; (g) two-call harness |
| R4-F-F1 | Func | Minor | design (b) | Bands empty if C ≤ refill; paired flood lacks lower bound | C ≥ 2×refill gate; bands [1.2×refill, 0.8·C] |
| R4-F-F2 | Func | Minor | design (b) | Phase-1 above C breaks loop red-proofs | Phase 1/precondition below 0.8·C; PASS-line sanity in selftests |
| R4-F-F3 | Func | Minor | prose (a) | "next pass recovers" vs RETRY_INTERVAL | Reworded |

Security: all R3 fixes verified; R43 widening checked clean. Testing: R3 fixes verified; Round-3 additions sound. Functionality: R3 fixes verified; key bound and control classes unchanged.

## Recurring Issue Check (round 4, non-N/A)
- Functionality: R4,R12,R13,R38,R40,R41,R42,R43 checked; R29 F1,F3; R50 F2; R53 F1; others N/A.
- Security: R48 Q1; R43 checked clean; R3,R29,R38,R39,R42,R49,R50,R53,RS1–RS3 OK; R2,R4,R10,R12,R16,R18,R19,R32,R34,R35,R36,R40,R41,R51,R55 OK; others N/A.
- Testing: R2,R12,R16,R29,R32,R34,R38,R41,R42,R49,R50 OK; R3 Q4; R53 Q3; RT1,RT2,RT5,RT6,RT8,RT10,RT11 OK; RT3 Q1; RT4 Q1,Q3; RT7 Q2; others N/A.

---

# Review round: 5
Date: 2026-10-19

## Changes from Previous Round
Plan rev 5 addressed Round-4 findings (validity flag, [1 s, 3.5 s] window, flood bands [1.2×refill, 0.8·C], the CF feasibility marker, Gate fields, RETRY wording).

## Round-5 findings (labels as filed by the experts)
| ID | Expert | Severity | Label / reach | Subject | Resolution (rev 6) |
|---|---|---|---|---|---|
| R5-S-1 | Sec | Minor | prose (a) | Accepted-cost figure hardcoded while ARRIVAL may be retuned | Stated as 1/ARRIVAL_INTERVAL_NS; R6 and deviation log updated on retune |
| R5-F-F1 | Func | Minor | prose (a) | WgLoadCleared lower bound wording; session timing; "Phase 2" ambiguity; fragment | Reworded; flood steps renamed; C3 test cited as authority |
| R5-T-S1 | Test | Minor | design (b) | Run-time source of C unspecified | Per-run C probe; bands derived per run; abort if C < 2×refill |
| R5-T-S2 | Test | Minor | prose (a) | Same as R5-F-F1 | Merged with R5-F-F1 |

## Saturation call (Round 5)
- Condition 1: five rounds completed.
- Condition 2: no open Critical or Major in any category. M3 (Major, Round 1) is carried as a measurement-dependent decision with an Anti-Deferral entry and a mechanical Phase-3 gate. It is not a deferred fix: C5 and Kani (b) hold either way.
- Condition 3: no Round-5 finding against the contracts, control classes or invariants. The one design-labelled finding (R5-T-S1) concerns harness parameter sourcing and is reachable only by building and executing.
- Condition 4: the remaining Minors are prose-only (a) or (b), and all were applied in rev 6 anyway.

Decision: plan review closed. Proceed to Phase 2. C1–C7 locked; M3 and CF carried, with the Phase-3 entry check that neither pending marker is left in docs/ (both settled and removed in batch 4).

## Recurring Issue Check (round 5, non-N/A)
- Functionality: R29 F1; R38, R43, R50, R53 checked; others N/A.
- Security: R27, R29 R5-1; R43 checked (no widening); R48, R38, R39, R50, R53, RS1–RS3 OK; R2, R3, R4, R10, R12, R16, R18, R19, R32, R34, R35, R36, R40, R41, R42, R49, R51, R55 OK; others N/A.
- Testing: R29 S2; R53 S1; RT4 S1; R2, R3, R12, R16, R32, R34, R38, R41, R42, R49, R50 OK; RT1–RT3, RT5–RT8, RT10, RT11 OK; others N/A.
