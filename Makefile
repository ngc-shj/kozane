# Run inside the dev container (make -C docker run && make -C docker exec).
# Every gate runs unpiped under pipefail; counts go to build/counts/ and are
# compared with tests/manifest.txt so a gate that silently runs nothing fails.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c

BUILD ?= build
MICROKIT_BOARD := qemu_virt_aarch64
# Development images print through the debug kernel too; what ships, and
# what `make test` boots, is `release` (M5 plan C7: tools/package refuses
# anything else).
MICROKIT_CONFIG ?= debug

ifndef MICROKIT_SDK
$(error MICROKIT_SDK is not set; run inside the dev container)
endif

sdk_config_dir := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)
target := aarch64-sel4-microkit
system := system/secureos.system
policy := policy/laws.toml
loader := $(BUILD)/loader.img
counts := $(BUILD)/counts

pds := eth-out eth-in ingress audit timer tpm key hs inner data pq pqkey
host_crates := wire ring audit-event ingress-core inner-core layout laws config secret-blob mksecrets wg-wire wg-core key-core msgs hs-core data-core cpu rosenpass-wire rosenpass-core pqkey-core mce460896 tpm2-wire tpm2
kani_crates := wire ring ingress-core inner-core wg-wire msgs rosenpass-wire tpm2-wire

.PHONY: clean-counts
.PHONY: all image package run test check check-selftest repro mir audit lint lint-pds unit kani verus ct ct-harness ct-shape bolero fuzz-long laws pins manifest kernel-config clean
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
pd_target ?= $(HOME)/.cache/secureos/pd-target-$(MICROKIT_CONFIG)

.PHONY: print-pd-target
print-pd-target:
	@echo $(pd_target)

define build_pd
SEL4_INCLUDE_DIRS=$(abspath $(sdk_config_dir)/include) \
	RUSTFLAGS="-Zunstable-options --remap-path-prefix=$(CURDIR)=/secureos" \
	cargo build --locked \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(target) \
		--release \
		--target-dir $(pd_target) \
		--artifact-dir $(BUILD) -Z unstable-options \
		-p pd-$(1) $(if $(features_$(1)),--features $(features_$(1)))
endef

# L11: single core, MCS as shipped by Microkit.
kernel-config:
	grep -q '^#define CONFIG_MAX_NUM_NODES  1$$' $(sdk_config_dir)/include/kernel/gen_config.h
	grep -q '^#define CONFIG_KERNEL_MCS  1$$' $(sdk_config_dir)/include/kernel/gen_config.h

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

# The laws checker runs on the exact file handed to the Microkit tool.
image: pds kernel-config $(BUILD)/secrets-placeholder.bin $(BUILD)/pq-secrets-placeholder.bin
	cargo run --locked -q -p laws -- check --system $(system) --policy $(policy) --search-path $(BUILD)
	$(MICROKIT_SDK)/bin/microkit $(system) \
		--search-path $(BUILD) \
		--board $(MICROKIT_BOARD) \
		--config $(MICROKIT_CONFIG) \
		-r $(BUILD)/report.txt \
		-o $(loader)

# The published image, its boot descriptor and the two blobs sealed to one
# TPM's SRK and the image's PCR 8 (M5 plan C8, C11); tools/package builds the
# same system with only the secrets prefill_paths changed and refuses
# anything else, and any kernel but a release one (M5 plan C7):
# `make package MICROKIT_CONFIG=release ...`.
ifneq ($(filter package,$(MAKECMDGOALS)),)
ifeq ($(and $(SECRETS),$(PQ_SECRETS),$(SRK_PUBLIC),$(OUT)),)
$(error package: set SECRETS=<blob> PQ_SECRETS=<blob> SRK_PUBLIC=<tpm2b_public> OUT=<dir>)
endif
endif
# tools/package also runs tools/ct-shape (identity, forbidden, shape,
# printing) on the PD ELFs it packages against this harness, and wants a C9
# pass record for it on a non-debug kernel (M4 plan C11), so `make ct` must
# have passed.
package: image ct-harness
	tools/package --secrets $(SECRETS) --pq-secrets $(PQ_SECRETS) --srk-public $(SRK_PUBLIC) --out $(OUT) \
		--system $(system) --policy $(policy) \
		--image $(loader) --gen-config $(sdk_config_dir)/include/kernel/gen_config.h \
		--search-path $(BUILD) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		--microkit $(MICROKIT_SDK)/bin/microkit --harness $(ct_harness)

# Boots an image interactively with both NICs as the integration test does
# (outside on user-net with 51820 forwarded to RUN_PORT, inside on a dgram
# socket). The default image holds the zero placeholder, so `key` is
# Unavailable and `hs` halts. A package is no loader image any more: it boots
# through U-Boot with the TPM it was sealed to (tests/integration/run.py).
LOADER ?= $(loader)
RUN_PORT ?= 51820
# Build the default image; another LOADER= is booted as is.
run: $(if $(filter $(loader),$(LOADER)),image)
	qemu-system-aarch64 \
		-machine virt,virtualization=on -cpu neoverse-n2 -m size=2G \
		-serial mon:stdio -nographic \
		-device loader,file=$(LOADER),addr=0x70000000,cpu-num=0 \
		-device virtio-net-device,netdev=n0,mac=52:54:00:12:34:56,bus=virtio-mmio-bus.31 \
		-netdev user,id=n0,hostfwd=udp:127.0.0.1:$(RUN_PORT)-:51820 \
		-device virtio-net-device,netdev=n1,mac=52:54:00:12:34:57,bus=virtio-mmio-bus.23 \
		-netdev dgram,id=n1,local.type=inet,local.host=127.0.0.1,local.port=45001,remote.type=inet,remote.host=127.0.0.1,remote.port=45002

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
		|| { cat $(counts)/kani.log; exit 1; };)
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
ct_harness := $(BUILD)/ct/target/aarch64-ct-harness/release/ct-harness
ct-harness:
	RUSTFLAGS="-Zunstable-options -Clinker-flavor=gnu-lld-cc -Clink-self-contained=+linker" \
	cargo build --locked --release \
		--manifest-path tools/ct-harness/Cargo.toml \
		-Zjson-target-spec -Z build-std=std,panic_abort \
		--target support/targets/aarch64-ct-harness.json \
		--target-dir $(BUILD)/ct/target

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

bolero_targets := wire/tests::fuzz_parse_never_panics_and_round_trips \
	wg-wire/tests::fuzz_parsers_never_panic_and_round_trip \
	rosenpass-wire/tests::fuzz_parsers_never_panic_and_round_trip \
	tpm2-wire/tests::fuzz_response_parsers_never_panic_and_stay_in_bounds

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
	grep '^AUDIT-ADVISORIES' $(counts)/audit.log > $(counts)/audit

laws: | $(counts)
	cargo run --locked -q -p laws -- check --system $(system) --policy $(policy) --search-path $(BUILD) --no-elf-check
	echo "LAWS-SYSTEMS 1" > $(counts)/laws

pins: | $(counts)
	tools/check-pins > $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
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
	python3 tests/tools/test_verus_pairing.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_mir_gate.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	python3 tests/tools/test_measure.py >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	tools/verus-pairing >> $(counts)/pins.log || { cat $(counts)/pins.log; exit 1; }
	grep -E '^(CHECK-(PINS-RULES|PINS-FIXTURES|SELFTEST-FIXTURES)|PACKAGE-FIXTURES|SECCOMP-FIXTURES|CONFIG-BUILD-FIXTURES|CHECK-MANIFEST-FIXTURES|HARNESS-SIGNAL-FIXTURES|AUDIT-GATE-FIXTURES|RP-COOKIE-TWIN-FIXTURES|CT-RECORD-FIXTURES|CT-SHAPE-FIXTURES|STACK-HEADROOM-FIXTURES|UNIT-COUNTS-FIXTURES|PROOF-LOCK-FIXTURES|VERUS-PAIRING-FIXTURES|VERUS-PAIRED|MIR-GATE-FIXTURES|MEASURE-FIXTURES)' $(counts)/pins.log > $(counts)/pins

# Builds its own deployment (fresh keys, generated config, release package);
# see run.py. Packaging a release kernel needs the C9 pass record, hence
# `ct` first (already made earlier in the same `make check`).
# it_boots (check-selftest only) runs a subset of the boots; such a run
# prints INTEGRATION-CASES-PARTIAL, which this grep does not take.
it_boots :=
test: ct uboot | $(counts)
	SECUREOS_IT_BOOTS="$(it_boots)" python3 tests/integration/run.py > $(counts)/test.log 2>&1 \
		|| { tail -40 $(counts)/test.log; exit 1; }
	grep '^INTEGRATION-CASES ' $(counts)/test.log > $(counts)/test

# M5 plan C8: U-Boot from the image's pinned source, with the repo's config
# fragment and the boot command of support/u-boot/boot.cmd compiled in. The
# measure variant stops after measuring and prints PCR 8 (the C8 acceptance
# boot); both come from the same command lines (tools/uboot-config).
uboot_tarball ?= /opt/u-boot/u-boot-2025.01.tar.bz2
uboot := $(BUILD)/u-boot-shipped/u-boot.bin
uboot_measure := $(BUILD)/u-boot-measure/u-boot.bin
.PHONY: uboot
uboot: $(uboot) $(uboot_measure)

$(BUILD)/u-boot-%/u-boot.bin: support/u-boot/secureos.config support/u-boot/boot.cmd tools/uboot-config $(uboot_tarball)
	rm -rf $(BUILD)/u-boot-$*
	mkdir -p $(BUILD)/u-boot-$*
	tar -xjf $(uboot_tarball) -C $(BUILD)/u-boot-$* --strip-components=1
	tools/uboot-config $* $(BUILD)/u-boot-$*/secureos.frag
	env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* qemu_arm64_defconfig > $(BUILD)/u-boot-$*.log 2>&1
	cd $(BUILD)/u-boot-$* && scripts/kconfig/merge_config.sh -m .config secureos.frag >> ../u-boot-$*.log 2>&1
	env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* olddefconfig >> $(BUILD)/u-boot-$*.log 2>&1
	tools/uboot-config verify $(BUILD)/u-boot-$*/secureos.frag $(BUILD)/u-boot-$*/.config
	SOURCE_DATE_EPOCH=0 env -u MAKEFLAGS -u MAKELEVEL $(MAKE) -C $(BUILD)/u-boot-$* -j$$(nproc) >> $(BUILD)/u-boot-$*.log 2>&1 \
		|| { tail -30 $(BUILD)/u-boot-$*.log; exit 1; }

# M5 plan C4: the MIR each PD ships from a verified crate equals the MIR the
# proof configuration compiles (tools/mir-gate).
mir: | $(counts)
	tools/mir-gate --verus "$(verus_crates)" --kani "$(kani_crates)" --pds "$(pds)" > $(counts)/mir.log 2>&1 \
		|| { cat $(counts)/mir.log; exit 1; }
	grep '^MIR-CRATES ' $(counts)/mir.log > $(counts)/mir

# M5 plan C3: the published (release) image rebuilt from a copy of the tree
# at another path, from a cold PD target directory, equals this one.
repro: | $(counts)
	$(MAKE) image MICROKIT_CONFIG=release
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
	$(MAKE) pins audit lint lint-pds unit kani verus ct ct-shape bolero laws mir repro test
	$(MAKE) manifest

# Requires a prior `make check` (the manifest case reuses build/counts).
check-selftest:
	tools/check-selftest

clean:
	rm -rf $(BUILD) $(HOME)/.cache/secureos
