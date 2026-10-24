# Code Review: secureos-m6-https-proxy
Date: 2026-10-24T23:00:08+09:00
Review round: 1

Base: fbfb83b (the commit before M6; main lacks M5). Reviewed at 4209823.

## Changes from Previous Round
Initial review. Ollama seeds skipped: the diff (136 files, ~22.5k lines) exceeds the seed analyzer's window.

## Functionality Findings (round 1)
F1 [Major, security-relevant] A RST in SYN-RECEIVED followed by a new SYN in the same ingress batch lets the new connection inherit the admitted slot, its source (X-Forwarded-For) and per-source accounting — crates/pds/tls/src/main.rs:892 (gone = Closed|Listen only). Fix: gone also when the client's remote endpoint is not the admitted l.peer (address and port), or None outside Closed/Listen; retarget l.peer before abort; integration red-proof (SYN p1, then RST p1 + SYN p2 in one burst).
F2 [Minor] Slot::error() is a no-op once close() moved the slot to Draining; lingers up to 2 s instead of aborting — main.rs:833, proxy.rs:233/325.
F3 [Minor] More than MAX_EXTENSIONS extensions refused as DuplicateExtension — crates/tls-wire/src/hello.rs:61.
F4 [Minor] Stale key / TlsKeyMismatch / 128 KiB stack references — tls-core rng.rs:23,28; config validate.rs:456; config/gateway.toml:7; hybrid.rs:50.
F5 [Minor, question] TX_BUF 8 KiB vs MAX_CLIENT_OUT 4169 allows one record in flight — main.rs:65.

## Security Findings (round 1)
S1 [Major] Inside eth_in TX has no reserve tier for tls frames; inner drain_tls unbounded — crates/pds/inner/src/main.rs:167-185, crates/inner-core/src/lib.rs from_tls. Fix: inside tier (free > INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE, refuse at equality), bound drain_tls per notification; deny/allow pair; separate red-proofs.
S2 [Minor] exchange_with_randomness public with caller randomness, no caller rule — crates/tls-core/src/hybrid.rs:83. Fix: check-pins rule allowing calls only in hybrid.rs and tools/ct-harness, fixture.
S3 [Minor] RFC 6979 candidate rejection probability stated 2^-128, actually ~2^-32 — crates/tlskey-core/src/lib.rs:378-381 and plan.
S4 [Minor] Client-IP headers beyond X-Forwarded-*/X-Real-IP/Forwarded pass through — crates/http-wire/src/lib.rs:67-77. Fix: add True-Client-IP, X-Client-IP, X-Cluster-Client-IP, CF-Connecting-IP, Fastly-Client-IP, X-Original-Forwarded-For, Client-IP to DROPPED with unit pair.
S5 [Minor] mkcert docstring claims NAME-only constraint; dNSName subtree permits subdomains — tools/mkcert.
Seed: unavailable. Recurring: R3 S1, R29 S3, R42 S4, R49 S5, others OK/N/A. RS1-RS5 OK, RS6 N/A.

## Testing Findings (round 1)
T1 [Major] MIR-CRATES stale at 9; mir-gate members now 10 (http-wire); mir not run since enrolment — tests/manifest.txt:26
T2 [Major] Plan-named mutations missing: parse_tcp data-offset rule (c2-tcp-offset) and tls_egress SYN refusal (c2-tls-egress-syn) — tools/check-selftest:163
T3 [Major] C8 one-selftest-per-wipe-point partly delivered: handshake/KeyUpdate (drop-based Secret zeroize) and wipe_state close wipe unproven — tools/check-selftest:1202
T4 [Major] Undiagnosed intermittent slowloris connect timeout in residue boot — tests/integration/run.py:4715; make it self-diagnosing, no retries
T5 [Major] Scrub depth at hello_keys production site has no measured ceiling (50312 B logged vs 48 KiB constant) — tools/ct-harness/src/residue.rs:715, hybrid.rs:52
T6 [Minor] Kani rewrite harness doc says 64 B / 3 fields; actual 16 / 2 — crates/http-wire/src/proofs.rs:134, deviation log
T7 [Minor] compile_fail doctests lack error codes; only Clone red-proved; l14-clone needle generic — hybrid.rs:11, secret/src/lib.rs
T8 [Minor] Concurrent probe passes with zero completed handshakes — run.py:5216
T9 [Minor] Sequential probe TlsSignHighWater count lacks since=mark — run.py:4535
T10 [Minor] Residue key/IV needles lack positive control — run.py secret_forms
T11 [Minor] T22 integration cost not recorded — deviation log
Env: VE9/VE10/VE11 blocked-deferred; VE10/VE11 should move to residual IDs given M7 is QEMU-only.

## Adjacent Findings
F1 escalated to security by the functionality expert; handled as a security fix.

## Quality Warnings
None.

## Recurring Issue Check
Per expert, recorded in each expert's section above (R3: S1, F4, T3; R29: S3, F4; R38: F1, F2; R42: S4; R49: S5, F1; R50: T1, T5; RT4: T8; RT7: T2, T3, T7; others OK or N/A).

## Environment Verification Report
verified-local (QEMU): TCP, TLS X25519MLKEM768 + ECDSA (OpenSSL s_client, curl), proxy, residue, floods, release; MIR gate 10 members (make mir rc=0). blocked-deferred: VE9 (browser/WebPKI, SC37/RM6-3), VE10 (real NIC line rate), VE11 (RNDR quality on a board) — plan section 'QEMU-verifiable vs hardware-required'; M7 is now QEMU-only (owner 2026-10-24), so VE10/VE11 become residuals.

## Resolution Status
All round 1 findings addressed; details in the deviation log's "Phase 3 round 1 fixes". Gates run: pins, lint, lint-pds, unit, laws, image, ct, ct-shape, bolero, mir. Not run: Kani, Verus, make test/check, check-selftest; `test`-gate selftest cases need a QEMU red-proof.

### F1 [Major] Reset listener inherits the admitted slot — Fixed
- Action: client gone also when the remote endpoint differs from the admitted `l.peer` (address and port) or is None outside Closed/Listen; `l.peer` retargeted before the abort; comment corrected. Integration case `https rst inherit` (residue boot); selftest `https-rst-inherit` (needs QEMU red-proof).
- Modified: crates/pds/tls/src/main.rs:903, crates/pds/tls/src/main.rs:1173; tests/integration/run.py:4809; tools/check-selftest:1281

### F2 [Minor] Slot::error no-op once Draining — Fixed
- Action: `error()` aborts a Draining/Lingering slot (TlsClosed(Error)); unit test.
- Modified: crates/tls-core/src/conn/proxy.rs:234; crates/tls-core/src/tests.rs:1317

### F3 [Minor] Too many extensions refused as DuplicateExtension — Fixed
- Action: over `MAX_EXTENSIONS` is `Refusal::Decode`; unit test updated.
- Modified: crates/tls-wire/src/hello.rs:62; crates/tls-wire/src/tests.rs:472

### F4 [Minor] Stale key / TlsKeyMismatch / 128 KiB references — Fixed
- Action: references name `tlskey`, its Mismatch (code 8), the 192 KiB stack.
- Modified: crates/tls-core/src/rng.rs:23, crates/tls-core/src/rng.rs:28; crates/config/src/validate.rs:456; config/gateway.toml:7; crates/tls-core/src/hybrid.rs:46

### F5 [Minor] TX_BUF fits one record — Fixed
- Action: `TX_BUF` 8 → 9 KiB with `2 * MAX_CLIENT_OUT <= TX_BUF` asserted; within `TLS_STATE_MAX` (asserted); deviation log entry.
- Modified: crates/pds/tls/src/main.rs:68

### S1 [Major] No inside TX tier; drain_tls unbounded — Fixed
- Action: `from_tls` refuses (`TxReserve`, audited TxNoBuffer) unless free > INNER_TX_RESERVE + TLS_TX_SHARE_INSIDE, compile-time range assert; pd-inner's drain bounded at NET_BUFFERS via `ring::pass::drain`; unit allow/deny pair; selftest `s1-inner-tls-tier` (red-proved). The drain bound is `ring::pass::drain`'s (red-proved by `unbounded-drain`); a separate PD-level case would need QEMU.
- Modified: crates/inner-core/src/lib.rs:117, crates/inner-core/src/lib.rs:249; crates/inner-core/src/tests.rs:443; crates/pds/inner/src/main.rs:28, crates/pds/inner/src/main.rs:179; crates/pds/inner/Cargo.toml; Cargo.lock; tools/check-selftest:1058

### S2 [Minor] exchange_with_randomness has no caller rule — Fixed
- Action: check-pins P20 (hybrid.rs, tls-core's tests, tools/ct-harness, the lib.rs re-export); 3 deny + 2 allow fixtures.
- Modified: tools/check-pins:452; tests/tools/test_check_pins.py:707

### S3 [Minor] RFC 6979 rejection probability misstated — Fixed
- Action: ≈ 2^-32 per candidate, ≈ 2^-256 for the cap, in code and plan.
- Modified: crates/tlskey-core/src/lib.rs:383; docs/archive/review/secureos-m6-https-proxy-plan.md:262

### S4 [Minor] Client-IP headers pass through — Fixed
- Action: seven client-address fields added to DROPPED; unit pair (dropped byte-identical, a look-alike custom field kept).
- Modified: crates/http-wire/src/lib.rs:79; crates/http-wire/src/tests.rs:559

### S5 [Minor] mkcert docstring overstates the constraint — Fixed
- Action: docstring says NAME and its subdomains.
- Modified: tools/mkcert:25

### T1 [Major] MIR-CRATES stale — Fixed
- Action: 9 → 10 (make mir rc=0); deviation log entry.
- Modified: tests/manifest.txt:26

### T2 [Major] Plan-named mutations missing — Fixed
- Action: selftest `c2-tcp-offset` (rule removed, redundant `get` refusals made lenient) and `c2-tls-egress-syn`; both red-proved.
- Modified: tools/check-selftest:1044, tools/check-selftest:1053

### T3 [Major] Wipe points unproven — Fixed (needs QEMU red-proof)
- Action: selftest `residue-secret-drop` (Secret's drop zeroize removed) and `residue-wipe-state` (read/write secret wipes removed), residue boot, failure-only needles.
- Modified: tools/check-selftest:1287, tools/check-selftest:1294

### T4 [Major] Undiagnosed slowloris connect timeout — Fixed
- Action: a failed connect reports the SYNs on the tap, the gateway's answers, sniffer drops and TcpLimited/TlsClosed audits since boot; no retry.
- Modified: tests/integration/run.py:4740

### T5 [Major] Scrub depth at hello_keys unmeasured — Fixed
- Action: `hello_keys` pub (harness only); residue ceiling `hello-depth` measured 35 912 B (27 % headroom under 48 KiB), so `SCRUB_DEPTH_EXCHANGE` 48 → 52 KiB; RESIDUE-CASES 31 → 32; selftest `tls-hello-scrub-depth` (red-proved).
- Modified: crates/tls-core/src/handshake.rs:127; crates/tls-core/src/hybrid.rs:54; tools/ct-harness/src/residue.rs:750; tools/check-selftest:535

### T6 [Minor] Rewrite harness bounds misdocumented — Fixed
- Action: doc and deviation log state fixed request line, ≤ 16 symbolic field bytes, ≤ 2 fields; harness body unchanged.
- Modified: crates/http-wire/src/proofs.rs:134; docs/archive/review/secureos-m6-https-proxy-deviation.md:292

### T7 [Minor] compile_fail doctests lack error codes — Fixed
- Action: E0599/E0382/E0423/E0277, each verified by compiling (the clone doctests now clone an owned value); `l14-clone` needle names the doctest (red-proved).
- Modified: crates/tls-core/src/hybrid.rs:11; crates/secret/src/lib.rs:8; tools/check-selftest:1143

### T8 [Minor] Concurrent probe passes with zero handshakes — Fixed
- Action: fails when none completed; names a D3 breach on failed + TlsTimeout(Handshake) since the mark.
- Modified: tests/integration/run.py:5322

### T9 [Minor] TlsSignHighWater without since=mark — Rejected after test
- Action: the since=mark window was applied, and the https boot then failed
  ("tls audited no TlsSignHighWater during the probe"): a high-water line is
  emitted only on a new maximum, so the probe's signs need print none once an
  earlier case set a higher one. The boot's last line is the maximum over every
  sign, the probe's included, which is what SIGN_COST_NS records. Reverted to
  the whole boot with that reason in a comment.
- Modified: tests/integration/run.py (https_probe_case)

### T10 [Minor] Key/IV needles lack a positive control — Fixed
- Action: `check_secret_forms` checks `hkdf_expand_label` against RFC 8448 section 3 (verified from the RFC text) and the keylog fixture's ChaCha20 keys/IVs, first in the residue case.
- Modified: tests/integration/run.py:4241

### T11 [Minor] Integration cost not recorded — Fixed
- Action: snapshot counts per https boot recorded; wall time not in the logs, stated as unavailable.
- Modified: docs/archive/review/secureos-m6-https-proxy-deviation.md (Phase 3 round 1 fixes)

### Env: VE10/VE11 — Recorded
- Action: M7 QEMU-only (owner, 2026-10-24): VE10/VE11 become residuals RM6-9/RM6-10; VE9 stays blocked-deferred.
- Modified: docs/archive/review/secureos-m6-https-proxy-deviation.md (Phase 3 round 1 fixes)
