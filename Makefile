# Run inside the dev container (make -C docker run && make -C docker exec).
# Every gate runs unpiped under pipefail; counts go to build/counts/ and are
# compared with tests/manifest.txt so a gate that silently runs nothing fails.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c

BUILD ?= build
# M9 plan C1, C15: Kozane's own board (EL1, GICv3), from the dev image's SDK.
MICROKIT_BOARD := kozane_virt_aarch64_el1
# Development images print through the debug kernel too; what ships, and
# what `make test` boots, is `release` (M5 plan C7: tools/package refuses
# anything else).
MICROKIT_CONFIG ?= debug

ifndef MICROKIT_SDK
$(error MICROKIT_SDK is not set; run inside the dev container)
endif

sdk_config_dir := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
target := aarch64-sel4-microkit
system := system/kozane.system
policy := policy/laws.toml
loader := $(BUILD)/loader.img
counts := $(BUILD)/counts

pds := supervisor eth-out eth-in ingress audit timer tpm rng key hs inner data pq pqkey tls tlskey policy auditkey
host_crates := wire ring boot-stage rng-core supervisor-core audit-event drbg ingress-core inner-core layout laws supervisor-allowlist config secret-blob mksecrets wg-wire wg-core key-core msgs hs-core data-core cpu rosenpass-wire rosenpass-core pqkey-core mce460896 tpm2-wire tpm2 tls-wire tls-core http-wire ct limits tlskey-core secret policy-wire policy-client release-seq auditkey-core audit-core
empty :=
space := $(empty) $(empty)
# A crate shipped in more than one feature set is proved in each
# (`kani_variants_<crate>`, cargo arguments, `;`-separated) and tools/mir-gate
# compares each shipped variant with the proof build of its own features.
kani_variants_boot-stage := --features boot-stop
# The `policy` PD links policy-wire with `verifier` (M8 plan D-2), every
# other PD without it.
kani_variants_policy-wire := --features verifier
kani_crates := wire ring boot-stage drbg rng-core supervisor-core ingress-core inner-core wg-wire msgs rosenpass-wire tpm2-wire tls-wire http-wire policy-wire audit-event auditkey-core audit-core rosenpass-core

.PHONY: clean-counts
.PHONY: all image package run test check check-selftest repro mir audit lint lint-pds unit kani verus ct ct-harness ct-shape rp-residue bolero fuzz-long laws pins manifest kernel-config clean
all: image

$(counts):
	mkdir -p $@

# One cargo invocation per PD: features must not unify across PDs (only
# eth-out needs a heap). cargo does its own dependency tracking. The target
# dir is per kernel config: the PDs compile against that config's headers
# (SEL4_INCLUDE_DIRS), so a debug and a release build never share objects;
# the ELFs land in $(BUILD) for the image built right after them.
.PHONY: pds
pds:
	$(foreach pd,$(pds),$(call build_pd,$(pd));)

# The PD target directory is outside the tree and fixed per config: LLVM's
# local ThinLTO names promoted symbols with a hash of the absolute output
# path, so the image is reproducible from any tree path only if this does
# not move (M5 plan C3, tools/repro). Source paths are remapped below.
pd_target ?= $(HOME)/.cache/kozane/pd-target-$(MICROKIT_CONFIG)

.PHONY: print-pd-target
print-pd-target:
	@echo $(pd_target)

define build_pd
SEL4_INCLUDE_DIRS=$(abspath $(sdk_config_dir)/include) \
	RUSTFLAGS="-Zunstable-options --remap-path-prefix=$(CURDIR)=/kozane" \
	cargo build --locked \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(target) \
		--release \
		--target-dir $(pd_target) \
		--artifact-dir $(BUILD) -Z unstable-options \
		-p pd-$(1) $(if $(features_$(1)),--features $(features_$(1)))
endef

# L11: single core, MCS. M9 plan C1: EL1 (no hypervisor support), GICv3,
# SMC calls (the supervisor's PSCI reset), and the physical timer and
# counter exported to EL0 (C14, D13). tools/kernel-config names the first
# line that fails.
kernel_config_file ?= $(sdk_config_dir)/include/kernel/gen_config.h
kernel-config:
	tools/kernel-config $(kernel_config_file)

# Zero blob for the secrets region: `make image` is never deployable (`key`
# is Unavailable on it); `make package` seals a real one for U-Boot to copy
# in at boot (plan C16, M5 plan C8).
$(BUILD)/secrets-placeholder.bin:
	mkdir -p $(BUILD)
	head -c 4096 /dev/zero > $@

# Same for the pqkey secrets region (`pqkey` is Unavailable on it).
$(BUILD)/pq-secrets-placeholder.bin:
	mkdir -p $(BUILD)
	head -c 16384 /dev/zero > $@

# Same for the tlskey secrets region (`tlskey` is Unavailable on it, and
# `tls` halts before listening; M6 plan C12).
$(BUILD)/tls-secrets-placeholder.bin:
	mkdir -p $(BUILD)
	head -c 4096 /dev/zero > $@

# Same for the auditkey secrets region (`auditkey` is Unavailable on it;
# M8 plan C10).
$(BUILD)/audit-secrets-placeholder.bin:
	mkdir -p $(BUILD)
	head -c 4096 /dev/zero > $@

# Zero bundle slots (M8 plan C4), BUNDLE_MAX each, as tools/measure.py reads
# it from crates/limits.
$(BUILD)/policy-slot-placeholder.bin: crates/limits/src/lib.rs tools/measure.py
	mkdir -p $(BUILD)
	python3 -c 'import sys; sys.path.insert(0, "tools"); import measure; sys.stdout.buffer.write(bytes(measure.BUNDLE_MAX))' > $@

# The laws checker runs on the exact file handed to the Microkit tool. Its
# ELF check (W^X, the timer scan's result) runs in `package`, after the scan
# (M9 plan D13).
image: pds kernel-config $(BUILD)/secrets-placeholder.bin $(BUILD)/pq-secrets-placeholder.bin $(BUILD)/tls-secrets-placeholder.bin $(BUILD)/audit-secrets-placeholder.bin $(BUILD)/policy-slot-placeholder.bin
	cargo run --locked -q -p laws -- check --system $(system) --policy $(policy) --search-path $(BUILD) --no-elf-check
	$(MICROKIT_SDK)/bin/microkit $(system) \
		--search-path $(BUILD) \
		--board $(MICROKIT_BOARD) \
		--config $(MICROKIT_CONFIG) \
		-r $(BUILD)/report.txt \
		-o $(loader)

# The published image, its boot descriptor and the four blobs sealed to
# one TPM's SRK and the image's PCR 8 (M5 plan C8, C11, M6 plan C12, M8
# plan C10);
# tools/package builds the same system with only the secrets prefill_paths
# changed and refuses anything else, and any kernel but a release one (M5
# plan C7):
# `make package MICROKIT_CONFIG=release ...`.
ifneq ($(filter package,$(MAKECMDGOALS)),)
ifeq ($(and $(SECRETS),$(PQ_SECRETS),$(TLS_SECRETS),$(AUDIT_SECRETS),$(SRK_PUBLIC),$(OUT)),)
$(error package: set SECRETS=<blob> PQ_SECRETS=<blob> TLS_SECRETS=<blob> AUDIT_SECRETS=<blob> SRK_PUBLIC=<tpm2b_public> OUT=<dir>)
endif
endif
# tools/package also runs tools/ct-shape (identity, forbidden, shape,
# printing) on the PD ELFs it packages against this harness, and wants a C9
# pass record for it on a non-debug kernel (M4 plan C11), so `make ct` must
# have passed. It records the node's NodeConfig digest from the gateway.toml
# the image was built from (crates/config's build.rs reads the same file)
# with tools/policy, for `policy verify --fleet --package-node` (M8 plan C2).
# M9 plan D13: first the timer scan over the ELFs it packages (no timer
# access outside `timer`, at least one inside), then laws' ELF check, which
# reads its result ($(BUILD)/timer-scan.txt) and checks W^X. Only the
# shipped release package of `make test` sets timer_scan_counts, so
# TIMER-SCAN-PDS reaches the counts once; every other package writes only
# the file.
gateway_config := $(or $(KOZANE_CONFIG),config/gateway.toml)
timer_scan_counts :=
package: image ct-harness $(firmware) policy-tool
	tools/timer-scan --system $(system) --search-path $(BUILD) --out $(BUILD)/timer-scan.txt
	cargo run --locked -q -p laws -- check --system $(system) --policy $(policy) --search-path $(BUILD)
	$(if $(timer_scan_counts),mkdir -p $(counts) && grep '^TIMER-SCAN-PDS ' $(BUILD)/timer-scan.txt > $(counts)/timer-scan)
	tools/package --secrets $(SECRETS) --pq-secrets $(PQ_SECRETS) --tls-secrets $(TLS_SECRETS) \
		--audit-secrets $(AUDIT_SECRETS) --srk-public $(SRK_PUBLIC) --firmware $(firmware) --out $(OUT) \
		--system $(system) --policy $(policy) \
		--image $(loader) --gen-config $(sdk_config_dir)/include/kernel/gen_config.h \
		--search-path $(BUILD) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		--microkit $(MICROKIT_SDK)/bin/microkit --harness $(ct_harness) \
		--gateway-config $(gateway_config) --policy-bin $(policy_bin)

# M7 plan C8: the fault-inject selftest variants, packaged as `package`
# does (same arguments) from PDs built with the feature into a BUILD of
# their own; the kernel, the C9 harness and the firmware are the main
# build's. `net`: ingress faults on frame A and halts on frame B, audit
# faults on ingress's first WgBadMessage; `timer`: the timer faults on a
# tick; `policy` (M8 plan C13): `policy` stops after a confirmed ADVANCE,
# before it selects. tools/release.py refuses an image any of them built.
fault_inject_net := features_ingress=fault-inject features_audit=fault-inject
fault_inject_timer := features_timer=fault-inject
fault_inject_policy := features_policy=fault-inject
package-fault-inject-%: ct-harness $(firmware)
	$(if $(fault_inject_$*),,$(error no fault-inject variant '$*'))
	$(MAKE) package BUILD=$(BUILD)/fault-inject-$* $(fault_inject_$*) timer_scan_counts= ct_dir=$(ct_dir) firmware=$(firmware) \
		policy_target=$(policy_target)

# Boots a package interactively, the shipped way (M7 plan I2.1): the
# shipped firmware measures it into a per-run copy of the swtpm state it
# was sealed to (tools/provision, then `make package`), through the one QEMU
# argv builder the suite uses (tests/integration/run.py). Both NICs as the
# integration test wires them: outside on user-net with 51820 forwarded to
# RUN_PORT, inside on a dgram socket. The bundle slots are the node's, never
# the package's (M8 plan C4): SLOT_A is the slot `tools/provision nv` wrote
# when it provisioned TPM_STATE, SLOT_B the inactive one (zeros if unset).
# Without a signed slot A at TPM_STATE's version every barrier PD halts (C6).
# TPM_KEY is the file TPM_STATE is encrypted with (`swtpm_setup --keyfile
# KEY --cipher aes-256-cbc`; M9 plan C1): swtpm never runs on a plaintext state.
RUN_PORT ?= 51820
run: $(firmware)
	python3 tests/integration/run.py --run "$(PKG)" "$(TPM_STATE)" $(RUN_PORT) "$(SLOT_A)" "$(SLOT_B)" "$(TPM_KEY)"

# The crate-level clippy denies (indexing, unwrap, arithmetic) only bite here.
lint: | $(counts)
	cargo clippy --locked $(foreach c,$(host_crates),-p $(c)) --all-targets -- -D warnings \
		> $(counts)/lint.log 2>&1 || { cat $(counts)/lint.log; exit 1; }
	# Count the workspace crates clippy actually covered (fresh ones included).
	cargo clippy --locked $(foreach c,$(host_crates),-p $(c)) --all-targets --message-format=json -- -D warnings \
		| python3 -c 'import json, sys; ws = set(sys.argv[1:]); \
			seen = {m["target"]["name"].replace("_", "-") for m in map(json.loads, sys.stdin) \
			        if m.get("reason") == "compiler-artifact"} & ws; print("LINT-CRATES", len(seen))' \
			$(host_crates) > $(counts)/lint

# PD code only compiles for the target, so host clippy never sees it: lint
# each PD as it is built (one invocation per PD, as `pds`), counted.
lint-pds: | $(counts)
	rm -f $(counts)/lint-pds.log
	$(foreach pd,$(pds),$(call clippy_pd,$(pd)) >> $(counts)/lint-pds.log 2>&1 \
		|| { cat $(counts)/lint-pds.log; exit 1; }; echo "LINT-PD-OK $(pd)" >> $(counts)/lint-pds.log;)
	awk '/^LINT-PD-OK/ { n++ } END { print "LINT-PDS", n + 0 }' $(counts)/lint-pds.log > $(counts)/lint-pds

define clippy_pd
SEL4_INCLUDE_DIRS=$(abspath $(sdk_config_dir)/include) \
	RUSTFLAGS=-Zunstable-options \
	cargo clippy --locked \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(target) \
		--release \
		--target-dir $(BUILD)/target-clippy \
		-p pd-$(1) $(if $(features_$(1)),--features $(features_$(1))) -- -D warnings
endef

unit: | $(counts)
	# --no-fail-fast: one failing crate must not hide another's failure (a
	# selftest needle in a later crate would never print).
	cargo test --locked --no-fail-fast $(foreach c,$(host_crates),-p $(c)) > $(counts)/unit.log 2>&1 \
		|| { cat $(counts)/unit.log; exit 1; }
	# Per-crate counts too, and stem collisions refused (tools/unit-counts).
	tools/unit-counts $(counts)/unit.log > $(counts)/unit

kani: | $(counts)
	rm -f $(counts)/kani.log
	$(foreach c,$(kani_crates),echo "KANI-CRATE $(c)" >> $(counts)/kani.log; \
		tools/kani-gate.sh -p $(c) $(kani_args_$(c)) >> $(counts)/kani.log \
		|| { cat $(counts)/kani.log; exit 1; }; \
		$(foreach v,$(subst ;, ,$(subst $(space),+,$(kani_variants_$(c)))),echo "KANI-CRATE $(c)" >> $(counts)/kani.log; \
			tools/kani-gate.sh -p $(c) $(subst +, ,$(v)) >> $(counts)/kani.log \
			|| { cat $(counts)/kani.log; exit 1; };))
	# Per-crate counts too (M2 plan T12), keyed KANI-<CRATE>.
	awk '/^KANI-CRATE / { c = toupper($$2) } /^KANI-HARNESSES/ { n += $$2; per[c] += $$2 } \
		END { print "KANI-HARNESSES", n; for (k in per) print "KANI-" k, per[k] }' \
		$(counts)/kani.log > $(counts)/kani

# Verus (M4 plan C1): one gate run per crate, serial, under kani-gate's lock.
verus_crates := wg-wire rosenpass-wire msgs ring wire
verus: | $(counts)
	rm -f $(counts)/verus.log
	$(foreach c,$(verus_crates),echo "VERUS-CRATE $(c)" >> $(counts)/verus.log; \
		tools/verus-gate.sh -p $(c) >> $(counts)/verus.log \
		|| { cat $(counts)/verus.log; exit 1; };)
	awk '/^VERUS-CRATE / { c = toupper($$2); n++ } /^VERUS-VERIFIED/ { v += $$2; per[c] = $$2 } \
		/^VERUS-ENSURES/ { ens[c] = $$2 } /^VERUS-NO-CHEATING/ { nc++ } \
		END { print "VERUS-FUNCTIONS", v; print "VERUS-TRUSTED-CHECKED", n; print "VERUS-NO-CHEATING-CRATES", nc + 0; \
		for (k in per) { print "VERUS-" k, per[k]; print "VERUS-ENSURES-" k, ens[k] } }' \
		$(counts)/verus.log > $(counts)/verus

# The C9 harness (M4 plan C9, deviation M-1): the PD's codegen on a linux
# target (support/targets/aarch64-ct-harness.json), build-std, linked by
# rust-lld so that C10 can compare its code with the PDs'. Its own lock.
# The repository's crates are path dependencies outside its workspace, so
# rustc sees their sources by absolute path; remapped to the relative path
# a PD's workspace build records, so that a panic Location an identity root
# references names the same file in both (M6 plan C7).
ct_dir ?= $(BUILD)/ct
ct_harness := $(ct_dir)/target/aarch64-ct-harness/release/ct-harness
ct-harness:
	RUSTFLAGS="-Zunstable-options -Clinker-flavor=gnu-lld-cc -Clink-self-contained=+linker --remap-path-prefix=$(CURDIR)/=" \
	cargo build --locked --release \
		--manifest-path tools/ct-harness/Cargo.toml \
		-Zjson-target-spec -Z build-std=std,panic_abort \
		--target support/targets/aarch64-ct-harness.json \
		--target-dir $(ct_dir)/target

# CT mode under memcheck, then residue mode natively (tools/ct-gate);
# writes build/ct/pass-<key> (tools/ct_record.py) only when both pass.
# check-selftest's scratch copy changes these two to inject its cases.
ct_valgrind := valgrind
ct_residue_wrap :=
ct: ct-harness | $(counts)
	tools/ct-gate $(ct_harness) "$(ct_valgrind)" "$(ct_residue_wrap)" > $(counts)/ct.log 2>&1 \
		|| { cat $(counts)/ct.log; exit 1; }
	# The harness's own clippy and unit tests (its report parser), on the
	# host: it is its own workspace, so `make lint` and `make unit` do not
	# see it. They run after ct-gate (a mutated harness must reach memcheck
	# first). ct-gate's record is only pending: it becomes the pass record
	# tools/package accepts on the last line, once both have passed, so a
	# failed or interrupted `make ct` leaves none.
	cargo clippy --locked --manifest-path tools/ct-harness/Cargo.toml --target-dir $(BUILD)/ct/target-host \
		--all-targets -- -D warnings > $(counts)/ct-lint.log 2>&1 || { cat $(counts)/ct-lint.log; exit 1; }
	cargo test --locked --manifest-path tools/ct-harness/Cargo.toml --target-dir $(BUILD)/ct/target-host \
		> $(counts)/ct-unit.log 2>&1 || { cat $(counts)/ct-unit.log; exit 1; }
	awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-CT-HARNESS", n + 0 }' $(counts)/ct-unit.log >> $(counts)/ct
	python3 tools/ct_record.py promote --root .

# C10 (tools/ct-shape): the mce460896 closures in pd-pqkey and pd-pq equal
# the harness's, nothing forbidden in them, their shape equals
# policy/ct-shape.toml, no PD ships a Verus symbol (C1 erasure), and none
# references the DebugPutChar syscall (M5 plan C6). On the release PDs,
# the ones that ship: a debug build always references it (rust-sel4's panic
# handler prints through it).
ct-shape: ct-harness | $(counts)
	$(MAKE) pds MICROKIT_CONFIG=release
	tools/ct-shape --harness $(ct_harness) --search-path $(BUILD) --system $(system) $(foreach pd,$(pds),$(BUILD)/pd-$(pd).elf) \
		> $(counts)/ct-shape.log 2>&1 || { cat $(counts)/ct-shape.log; exit 1; }
	cat $(counts)/ct-shape.log
	grep '^CT-SHAPE-SYMBOLS ' $(counts)/ct-shape.log > $(counts)/ct-shape

# M9 plan C7, I7.2 (deviation D-16): the initiator's residue cases, run
# natively in their own workspace and lock (tools/rp-residue), with the
# client's release profile. Not in the ct-harness, whose libcrux features
# and ct-shape baseline rosenpass-core's would change. Its clippy and unit
# tests here too: `make lint` and `make unit` do not see it.
rp_residue_target ?= $(BUILD)/rp-residue/target
rp-residue: | $(counts)
	cargo build --locked --release --manifest-path tools/rp-residue/Cargo.toml --target-dir $(rp_residue_target) \
		> $(counts)/rp-residue-build.log 2>&1 || { cat $(counts)/rp-residue-build.log; exit 1; }
	$(rp_residue_target)/release/rp-residue --run > $(counts)/rp-residue.log 2>&1 \
		|| { grep -v '^RP-RESIDUE-DEPTH ' $(counts)/rp-residue.log; exit 1; }
	tail -n 1 $(counts)/rp-residue.log | grep -q '^RP-RESIDUE-DONE ' || { cat $(counts)/rp-residue.log; exit 1; }
	cargo clippy --locked --manifest-path tools/rp-residue/Cargo.toml --target-dir $(rp_residue_target) \
		--all-targets -- -D warnings > $(counts)/rp-residue-lint.log 2>&1 || { cat $(counts)/rp-residue-lint.log; exit 1; }
	cargo test --locked --manifest-path tools/rp-residue/Cargo.toml --target-dir $(rp_residue_target) \
		> $(counts)/rp-residue-unit.log 2>&1 || { cat $(counts)/rp-residue-unit.log; exit 1; }
	{ grep '^RP-RESIDUE-CASES ' $(counts)/rp-residue.log; \
		awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-RP-RESIDUE", n + 0 }' $(counts)/rp-residue-unit.log; } \
		> $(counts)/rp-residue

bolero_targets := wire/tests::fuzz_parse_never_panics_and_round_trips \
	policy-wire/tests::fuzz_render_round_trips_and_parse_never_panics \
	wg-wire/tests::fuzz_parsers_never_panic_and_round_trip \
	rosenpass-wire/tests::fuzz_parsers_never_panic_and_round_trip \
	rosenpass-core/tests_initiator_vectors::fuzz_initiator_input_after_upstreams_prefix \
	tpm2-wire/tests::fuzz_response_parsers_never_panic_and_stay_in_bounds \
	tls-wire/tests::fuzz_parsers_never_panic_and_stay_in_bounds \
	http-wire/tests::fuzz_parse_never_panics_and_rewrite_reparses \
	http-wire/tests::fuzz_next_option_matches_the_reference_splitter

# Each target must load its committed seed corpus and complete > 0 runs, so
# a target that silently stops running fails (BOLERO-TARGETS).
bolero: | $(counts)
	cargo metadata --locked --format-version 1 > /dev/null
	rm -f $(counts)/bolero.log
	$(foreach t,$(bolero_targets),$(call bolero_one,$(word 1,$(subst /, ,$(t))),$(word 2,$(subst /, ,$(t)))))
	awk '/^BOLERO-TARGET-OK/ { n++ } END { print "BOLERO-TARGETS", n + 0 }' $(counts)/bolero.log > $(counts)/bolero

define bolero_one
	cargo bolero test -p $(1) $(2) -T 30s > $(counts)/bolero-$(1).log 2>&1 \
		|| { awk '{ l[NR] = $$0 } /panicked|deadly signal/ && !p { for (i = (NR > 60 ? NR - 60 : 1); i <= NR; i++) print l[i]; p = 1 }' \
			$(counts)/bolero-$(1).log; tail -20 $(counts)/bolero-$(1).log; exit 1; }
	grep -qE 'INFO: +[1-9][0-9]* files found in .*/corpus' $(counts)/bolero-$(1).log \
		|| { echo "bolero: seed corpus not loaded for $(1)"; exit 1; }
	# Generated inputs accumulate locally; this target's committed seeds must
	# exist (git failing is reported as such, not as "no seeds").
	seeds=$$(git ls-files -- 'crates/$(1)/src/__fuzz__/$(subst ::,__,$(subst fuzz_,,$(2)))/corpus/seed-*') \
		|| { echo "bolero: git ls-files failed for $(1)"; exit 1; }; \
		test -n "$$seeds" || { echo "bolero: no committed seed-* corpus for $(1)"; exit 1; }
	grep -qE '^Done [1-9][0-9]* runs' $(counts)/bolero-$(1).log \
		|| { echo "bolero: $(1) completed no runs"; exit 1; }
	cat $(counts)/bolero-$(1).log >> $(counts)/bolero.log
	echo "BOLERO-TARGET-OK $(1)" >> $(counts)/bolero.log

endef

fuzz-long:
	cargo metadata --locked --format-version 1 > /dev/null
	$(foreach t,$(bolero_targets),cargo bolero test -p $(word 1,$(subst /, ,$(t))) $(word 2,$(subst /, ,$(t))) -T 600s;)

# RustSec advisories over Cargo.lock, offline against the image's pinned
# advisory-db (tools/audit-gate; exceptions in policy/audit-ignore.toml).
audit: | $(counts)
	tools/audit-gate > $(counts)/audit.log 2>&1 || { cat $(counts)/audit.log; exit 1; }
	# The release tool's own workspace (M5 plan C13) is checked too.
	tools/audit-gate --lock tools/release/Cargo.lock --ignore policy/audit-ignore-release.toml > $(counts)/audit-release.log 2>&1 || { cat $(counts)/audit-release.log; exit 1; }
	# The policy tool's own workspace (M8 plan C2): the same libcrux build
	# chain as tools/release's, so the same exception file applies.
	tools/audit-gate --lock tools/policy/Cargo.lock --ignore policy/audit-ignore-release.toml > $(counts)/audit-policy.log 2>&1 || { cat $(counts)/audit-policy.log; exit 1; }
	# M9 plan D12: the client's and the launcher's own workspaces.
	tools/audit-gate --lock client/Cargo.lock --ignore policy/audit-ignore-release.toml > $(counts)/audit-client.log 2>&1 || { cat $(counts)/audit-client.log; exit 1; }
	tools/audit-gate --lock host/Cargo.lock --ignore policy/audit-ignore-release.toml > $(counts)/audit-host.log 2>&1 || { cat $(counts)/audit-host.log; exit 1; }
	grep '^AUDIT-ADVISORIES' $(counts)/audit.log > $(counts)/audit

laws: | $(counts)
	cargo run --locked -q -p laws -- check --system $(system) --policy $(policy) --search-path $(BUILD) --no-elf-check
	echo "LAWS-SYSTEMS 1" > $(counts)/laws

pins: release-tool policy-tool | $(counts)
	tools/check-pins > $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	# M7 plan C8: what the supervisor's source may name (RM7-5).
	cargo run --locked -q -p supervisor-allowlist -- crates/pds/supervisor/src >> $(counts)/pins.log \
		|| { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_check_pins.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_check_selftest.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_package.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_config_build.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_check_manifest.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_audit_gate.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_harness_signals.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	docker/make-seccomp.py --check >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_seccomp.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_rp_cookie_twin.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_ct_record.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_ct_shape.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_stack_headroom.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_unit_counts.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_proof_lock.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_selftest_split.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_kani_guard.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_verus_pairing.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_mir_gate.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_measure.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_vm.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_timer_scan.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_kernel_config.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_sdk_repro.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_release.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_provision.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_mkcert.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_policy.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_audit_verify.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	cargo clippy --locked --manifest-path tools/release/Cargo.toml --target-dir $(BUILD)/release/target --all-targets -- -D warnings \
		> $(counts)/release-lint.log 2>&1 || { cat $(counts)/release-lint.log; exit 1; }
	cargo test --locked --manifest-path tools/release/Cargo.toml --target-dir $(BUILD)/release/target \
		> $(counts)/release-unit.log 2>&1 || { cat $(counts)/release-unit.log; exit 1; }
	awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-RELEASE-TOOL", n + 0 }' $(counts)/release-unit.log >> $(counts)/pins.log
	cargo clippy --locked --manifest-path tools/policy/Cargo.toml --target-dir $(BUILD)/policy/target --all-targets -- -D warnings \
		> $(counts)/policy-lint.log 2>&1 || { cat $(counts)/policy-lint.log; exit 1; }
	cargo test --locked --manifest-path tools/policy/Cargo.toml --target-dir $(BUILD)/policy/target \
		> $(counts)/policy-unit.log 2>&1 || { cat $(counts)/policy-unit.log; exit 1; }
	awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-POLICY-TOOL", n + 0 }' $(counts)/policy-unit.log >> $(counts)/pins.log
	tools/verus-pairing >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	grep -E '^(CHECK-(PINS-RULES|PINS-FIXTURES|SELFTEST-FIXTURES)|PACKAGE-FIXTURES|SECCOMP-FIXTURES|CONFIG-BUILD-FIXTURES|CHECK-MANIFEST-FIXTURES|HARNESS-SIGNAL-FIXTURES|AUDIT-GATE-FIXTURES|RP-COOKIE-TWIN-FIXTURES|CT-RECORD-FIXTURES|CT-SHAPE-FIXTURES|STACK-HEADROOM-FIXTURES|UNIT-COUNTS-FIXTURES|PROOF-LOCK-FIXTURES|SELFTEST-SPLIT-FIXTURES|KANI-GUARD-FIXTURES|VERUS-PAIRING-FIXTURES|VERUS-PAIRED|MIR-GATE-FIXTURES|MEASURE-FIXTURES|VM-FIXTURES|TIMER-SCAN-FIXTURES|KERNEL-CONFIG-FIXTURES|SDK-REPRO-FIXTURES|RELEASE-FIXTURES|PROVISION-FIXTURES|MKCERT-FIXTURES|POLICY-FIXTURES|AUDIT-VERIFY-FIXTURES|UNIT-RELEASE-TOOL|UNIT-POLICY-TOOL)' $(counts)/pins.log > $(counts)/pins

# Builds its own deployment (fresh keys, generated config, release package);
# see run.py. Packaging a release kernel needs the C9 pass record, hence
# `ct` first (already made earlier in the same `make check`).
# it_boots (check-selftest only) runs a subset of the boots; such a run
# prints INTEGRATION-CASES-PARTIAL, which this grep does not take.
it_boots :=
test: ct firmware host-launcher | $(counts)
	KOZANE_IT_BOOTS="$(it_boots)" python3 tests/integration/run.py > $(counts)/test.log 2>&1 \
		|| { tail -40 $(counts)/test.log; exit 1; }
	grep '^INTEGRATION-CASES ' $(counts)/test.log > $(counts)/test
	tools/check-manifest --identity > $(counts)/identity

# M9 plan C6, C11: the gates `make check` does not run, each with its own
# counts directory and manifest, and the image identity of its run. Both
# boot the release package as `test` does; their cases are run.py's
# KOZANE_SUITE (kvm: every boot under KVM, VE21, gx10 only; kzc: kzc on
# kernel WireGuard under TCG, VE25). Baselines are measured, not gated
# (baselines.txt, no counts in it).
counts_kvm := $(BUILD)/counts-kvm
counts_kzc := $(BUILD)/counts-kzc
# The KVM device test-kvm requires: without it the gate fails, never skips.
kvm_dev := /dev/kvm
.PHONY: test-kvm test-kzc kzc-seams vm-seams
test-kvm: ct firmware host-launcher vm-seams kzc-seams
	rm -rf $(counts_kvm) && mkdir -p $(counts_kvm)
	KOZANE_SUITE=kvm KOZANE_ACCEL=kvm KOZANE_KVM_DEV=$(kvm_dev) KOZANE_IT_BOOTS="$(it_boots)" \
		KOZANE_BASELINES=$(abspath $(counts_kvm))/baselines.txt python3 tests/integration/run.py \
		> $(counts_kvm)/test.log 2>&1 || { tail -60 $(counts_kvm)/test.log; exit 1; }
	grep '^KVM-CASES ' $(counts_kvm)/test.log > $(counts_kvm)/test
	tools/check-manifest --identity > $(counts_kvm)/identity
	tools/check-manifest tests/manifest-kvm.txt $(counts_kvm)
test-kzc: ct firmware host-launcher kzc-seams
	rm -rf $(counts_kzc) && mkdir -p $(counts_kzc)
	KOZANE_SUITE=kzc KOZANE_IT_BOOTS="$(it_boots)" \
		KOZANE_BASELINES=$(abspath $(counts_kzc))/baselines.txt python3 tests/integration/run.py \
		> $(counts_kzc)/test.log 2>&1 || { tail -60 $(counts_kzc)/test.log; exit 1; }
	grep -E '^(KZC-CASES|INTEGRATION-ORACLE-CASES) ' $(counts_kzc)/test.log > $(counts_kzc)/test
	tools/check-manifest --identity > $(counts_kzc)/identity
	tools/check-manifest tests/manifest-kzc.txt $(counts_kzc)

# M5 plan C8: U-Boot from the image's pinned source, with the repo's config
# fragment and the boot command of support/u-boot/boot.cmd compiled in. The
# measure variant stops after measuring and prints PCR 8 (the C8 acceptance
# boot); both come from the same command lines (tools/uboot-config).
# LOCALVERSION= (set, though empty) keeps setlocalversion from appending
# "+" for an untagged tree; the fragment turns LOCALVERSION_AUTO off.
uboot_tarball ?= /opt/u-boot/u-boot-2025.01.tar.bz2
uboot := $(BUILD)/u-boot-shipped/u-boot.bin
uboot_measure := $(BUILD)/u-boot-measure/u-boot.bin
.PHONY: uboot
uboot: $(uboot) $(uboot_measure)

$(BUILD)/u-boot-%/u-boot.bin: support/u-boot/kozane.config support/u-boot/boot.cmd tools/uboot-config $(uboot_tarball)
	rm -rf $(BUILD)/u-boot-$*
	mkdir -p $(BUILD)/u-boot-$*
	tar -xjf $(uboot_tarball) -C $(BUILD)/u-boot-$* --strip-components=1
	tools/uboot-config $* $(BUILD)/u-boot-$*/kozane.frag
	env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* qemu_arm64_defconfig > $(BUILD)/u-boot-$*.log 2>&1
	cd $(BUILD)/u-boot-$* && scripts/kconfig/merge_config.sh -m .config kozane.frag >> ../u-boot-$*.log 2>&1
	env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* olddefconfig >> $(BUILD)/u-boot-$*.log 2>&1
	tools/uboot-config verify $(BUILD)/u-boot-$*/kozane.frag $(BUILD)/u-boot-$*/.config
	SOURCE_DATE_EPOCH=0 env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* -j$$(nproc) LOCALVERSION= >> $(BUILD)/u-boot-$*.log 2>&1 \
		|| { tail -30 $(BUILD)/u-boot-$*.log; exit 1; }

# M9 plan C2: the firmware is U-Boot alone, run as -bios at EL1 (EL2 under
# TCG, deviation D-2); TF-A left with M9 (D1). `firmware` is the shipped
# variant, `firmware_measure` the one that stops after measuring.
firmware ?= $(uboot)
firmware_measure := $(uboot_measure)
.PHONY: firmware
firmware: $(firmware) $(firmware_measure)

# M5 plan C13: hybrid-signed releases with dev keys (residual RM5-1).
#   make release-keys KEYS=<new dir outside the repo and cache volumes>
#   make release KEYS=<dir> PKG=<package OUT> OUT=<new dir>
#   make release-verify PUB=<keys dir> REL=<release dir> [ENVELOPE=<file> KIND=key|pq|tls]
release_bin := $(BUILD)/release/target/release/release
.PHONY: release-tool release-keys release release-verify
release-tool:
	cargo build --locked --release --manifest-path tools/release/Cargo.toml --target-dir $(BUILD)/release/target
release-keys: release-tool
	test -n "$(KEYS)" || { echo "release-keys: set KEYS=<dir>"; exit 1; }
	$(release_bin) keygen --dir $(KEYS) --forbid $(CURDIR) --forbid $(HOME)/.cargo/registry
release: release-tool host-launcher
	test -n "$(KEYS)" -a -n "$(PKG)" -a -n "$(OUT)" || { echo "release: set KEYS= PKG= OUT="; exit 1; }
	python3 tools/release.py make --keys $(KEYS) --pkg $(PKG) --out $(OUT)
release-verify: release-tool
	test -n "$(PUB)" -a -n "$(REL)" || { echo "release-verify: set PUB= REL="; exit 1; }
	python3 tools/release.py verify --pub $(PUB) --release $(REL) $(if $(ENVELOPE),--envelope $(ENVELOPE) --kind $(KIND))

# M8 plan C2, D11: the peer-policy signing toolchain, its own workspace as
# tools/release's. A fault-inject package's sub-make keeps the main build's
# target directory (`policy_target`).
policy_target := $(BUILD)/policy/target
policy_bin = $(policy_target)/release/policy
.PHONY: policy-tool
# M9 plan C4: the launcher, in its own workspace (host/, D12). The argv it
# embeds is rendered from tools/vm.py first. Commands run from host/ so its
# rust-toolchain.toml (1.97.1) applies, not the root nightly.
host_target := $(abspath $(BUILD))/host/target
.PHONY: host-launcher host
host-launcher:
	python3 -c "import sys; sys.path.insert(0, 'tools'); import vm; vm.render_launcher_args()"
	cd host && cargo build --locked --release -p kozane-vm --target-dir $(host_target)
# The gate: lint and unit with and without the test seams, the advisory
# check on host/Cargo.lock, and the seams marker (SEAMS=1 in the test build,
# the positive control; SEAMS=0 in the shipped one).
host: host-launcher | $(counts)
	cd host && cargo clippy --locked --all-targets --target-dir $(host_target) -- -D warnings \
		> $(abspath $(counts))/host-lint.log 2>&1 || { cat $(abspath $(counts))/host-lint.log; exit 1; }
	cd host && cargo clippy --locked --all-targets --features kozane-vm/test-seams --target-dir $(host_target) -- -D warnings \
		>> $(abspath $(counts))/host-lint.log 2>&1 || { cat $(abspath $(counts))/host-lint.log; exit 1; }
	# The shipped configuration first: without the seams, the fixed paths,
	# the root owner and the refused seam options are what the tests see.
	cd host && cargo test --locked --target-dir $(host_target) \
		> $(abspath $(counts))/host-unit.log 2>&1 || { cat $(abspath $(counts))/host-unit.log; exit 1; }
	$(host_target)/debug/kozane-vm --build-info | grep -qx 'SEAMS=0' || { echo "host: the plain test build has SEAMS=1"; exit 1; }
	cd host && cargo test --locked --features kozane-vm/test-seams --target-dir $(host_target) \
		>> $(abspath $(counts))/host-unit.log 2>&1 || { cat $(abspath $(counts))/host-unit.log; exit 1; }
	$(host_target)/debug/kozane-vm --build-info | grep -qx 'SEAMS=1' || { echo "host: test build lacks SEAMS=1"; exit 1; }
	$(host_target)/release/kozane-vm --build-info | grep -qx 'SEAMS=0' || { echo "host: shipped launcher has test seams"; exit 1; }
	awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-HOST", n + 0 }' $(abspath $(counts))/host-unit.log > $(counts)/host

# M9 plan C8-C10, D12: the client workspace. Lint and tests (the C harness
# under valgrind included, client-ffi's tests/c_harness.rs), and C9's header
# gate: cbindgen regenerates the header and it must equal the committed one.
client_target := $(abspath $(BUILD))/client/target
.PHONY: client
client: | $(counts)
	cd client && cargo clippy --locked --workspace --all-targets --target-dir $(client_target) -- -D warnings \
		> $(abspath $(counts))/client-lint.log 2>&1 || { cat $(abspath $(counts))/client-lint.log; exit 1; }
	# One run per crate, so each has its own count (plan T2.13): a test moved
	# from one crate to another is not a net zero.
	: > $(abspath $(counts))/client-unit.log
	for p in kozane-client kozane-client-cli kozane-client-ffi; do \
		(cd client && cargo test --locked -p $$p --target-dir $(client_target)) \
			> $(abspath $(counts))/client-unit-$$p.log 2>&1 || { cat $(abspath $(counts))/client-unit-$$p.log; exit 1; }; \
		cat $(abspath $(counts))/client-unit-$$p.log >> $(abspath $(counts))/client-unit.log; \
	done
	# The shipped kzc and kzc-psk: built without the seams (the tests'
	# self dev-dependency always enables them), and they refuse a seam option.
	cd client && cargo build --locked --release -p kozane-client-cli --bins --target-dir $(client_target)-ship \
		> $(abspath $(counts))/client-ship.log 2>&1 || { cat $(abspath $(counts))/client-ship.log; exit 1; }
	for b in kzc kzc-psk; do $(client_target)-ship/release/$$b --build-info | grep -qx 'SEAMS=0' \
		|| { echo "client: shipped $$b has test seams"; exit 1; }; done
	@# Not echoed: its refusal text must print only when it fails (a needle).
	@! $(client_target)-ship/release/kzc --root-prefix /nonexistent up 2> $(counts)/client-ship-seam.log \
		|| { echo "client: shipped kzc took --root-prefix"; exit 1; }
	@grep -q '^kzc: usage: kzc ' $(counts)/client-ship-seam.log || { echo "client: shipped kzc took --root-prefix"; cat $(counts)/client-ship-seam.log; exit 1; }
	cd client && cbindgen --quiet --config crates/client-ffi/cbindgen.toml --crate kozane-client-ffi \
		--output $(abspath $(BUILD))/kozane_client.h crates/client-ffi
	cmp -s client/include/kozane_client.h $(BUILD)/kozane_client.h \
		|| { echo "ffi: header differs"; diff -u client/include/kozane_client.h $(BUILD)/kozane_client.h; exit 1; }
	{ awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-CLIENT", n + 0 }' $(abspath $(counts))/client-unit-kozane-client.log; \
	  awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-CLIENT-CLI", n + 0 }' $(abspath $(counts))/client-unit-kozane-client-cli.log; \
	  awk '/^test result: ok\./ { n += $$4 } END { print "UNIT-CLIENT-FFI", n + 0 }' $(abspath $(counts))/client-unit-kozane-client-ffi.log; \
	} > $(counts)/client

policy-tool:
	cargo build --locked --release --manifest-path tools/policy/Cargo.toml --target-dir $(policy_target)

# M9 plan C4, C10: kozane-vm, kzc and kzc-psk with the test seams
# (--root-prefix, --user-map), which the test-kvm and test-kzc harness runs
# in its single-uid namespace (VE26). Debug builds, never shipped: the
# shipped launcher is host-launcher's, without --features.
kzc-seams:
	cd client && cargo build --locked -p kozane-client-cli --features test-seams --bins --target-dir $(client_target)
vm-seams: host-launcher
	cd host && cargo build --locked -p kozane-vm --features test-seams --target-dir $(host_target)

# M5 plan C4: the MIR each PD ships from a verified crate equals the MIR the
# proof configuration compiles (tools/mir-gate).
mir: | $(counts)
	tools/mir-gate --verus "$(verus_crates)" --kani "$(kani_crates)" --pds "$(pds)" \
		--variants "$(foreach c,$(kani_crates),$(if $(kani_variants_$(c)),$(c)=$(kani_variants_$(c));))" > $(counts)/mir.log 2>&1 \
		|| { cat $(counts)/mir.log; exit 1; }
	grep '^MIR-CRATES ' $(counts)/mir.log > $(counts)/mir

# M5 plan C3: the published (release) image rebuilt from a copy of the tree
# at another path, from a cold PD target directory, equals this one.
repro: | $(counts)
	$(MAKE) image firmware MICROKIT_CONFIG=release
	tools/repro release $(pds) > $(counts)/repro.log 2>&1 || { cat $(counts)/repro.log; exit 1; }
	grep '^REPRO-ARTIFACTS ' $(counts)/repro.log > $(counts)/repro

manifest:
	tools/check-manifest tests/manifest.txt $(counts)

# Count files from earlier runs are removed first, so a gate that does not
# run this time is reported missing instead of passing on a stale count.
clean-counts:
	mkdir -p $(counts)
	find $(counts) -maxdepth 1 -type f ! -name '*.log' -delete

check:
	$(MAKE) clean-counts
	$(MAKE) pins audit lint lint-pds unit client host kani verus ct ct-shape rp-residue bolero laws mir repro test
	$(MAKE) manifest

# Requires a prior `make check` (the manifest case reuses build/counts).
check-selftest:
	tools/check-selftest

clean:
	rm -rf $(BUILD) $(HOME)/.cache/kozane
