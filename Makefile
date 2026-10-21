# Run inside the dev container (make -C docker run && make -C docker exec).
# Every gate runs unpiped under pipefail; counts go to build/counts/ and are
# compared with tests/manifest.txt so a gate that silently runs nothing fails.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c

BUILD ?= build
MICROKIT_BOARD := qemu_virt_aarch64
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

pds := eth-out eth-in ingress audit timer key hs inner data pq pqkey
host_crates := wire ring audit-event ingress-core inner-core layout laws config secret-blob mksecrets wg-wire wg-core key-core msgs hs-core data-core cpu rosenpass-wire rosenpass-core pqkey-core
kani_crates := wire ring ingress-core inner-core wg-wire msgs rosenpass-wire

.PHONY: clean-counts
.PHONY: all image package run test check check-selftest audit lint lint-pds unit kani bolero fuzz-long laws pins manifest kernel-config clean
all: image

$(counts):
	mkdir -p $@

# One cargo invocation per PD: features must not unify across PDs (only
# eth-out needs a heap). cargo does its own dependency tracking.
.PHONY: pds
pds:
	$(foreach pd,$(pds),$(call build_pd,$(pd));)

define build_pd
SEL4_INCLUDE_DIRS=$(abspath $(sdk_config_dir)/include) \
	RUSTFLAGS=-Zunstable-options \
	cargo build --locked \
		-Z build-std=core,alloc,compiler_builtins \
		-Z build-std-features=compiler-builtins-mem \
		--target $(target) \
		--release \
		--target-dir $(BUILD)/target \
		--artifact-dir $(BUILD) -Z unstable-options \
		-p pd-$(1) $(if $(features_$(1)),--features $(features_$(1)))
endef

# L11: single core, MCS as shipped by Microkit.
kernel-config:
	grep -q '^#define CONFIG_MAX_NUM_NODES  1$$' $(sdk_config_dir)/include/kernel/gen_config.h
	grep -q '^#define CONFIG_KERNEL_MCS  1$$' $(sdk_config_dir)/include/kernel/gen_config.h

# Zero blob for the secrets region: `make image` is never deployable (`key`
# halts on it); `make package` swaps in a real one (plan C16).
$(BUILD)/secrets-placeholder.bin:
	mkdir -p $(BUILD)
	head -c 4096 /dev/zero > $@

# Same for the pqkey secrets region (`pqkey` halts on it).
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

# Same system with only the secrets prefill_path changed; tools/package
# refuses anything else, and refuses non-debug kernels until SC20.
ifneq ($(filter package,$(MAKECMDGOALS)),)
ifeq ($(and $(SECRETS),$(PQ_SECRETS),$(OUT)),)
$(error package: set SECRETS=<blob> PQ_SECRETS=<blob> OUT=<dir>)
endif
endif
package: image
	tools/package --secrets $(SECRETS) --pq-secrets $(PQ_SECRETS) --out $(OUT) --system $(system) --policy $(policy) \
		--image $(loader) --gen-config $(sdk_config_dir)/include/kernel/gen_config.h \
		--search-path $(BUILD) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		--microkit $(MICROKIT_SDK)/bin/microkit

# Boots an image interactively with both NICs as the integration test does
# (outside on user-net with 51820 forwarded to RUN_PORT, inside on a dgram
# socket). The default image holds the zero placeholder, so `key` halts;
# boot a packaged one with LOADER=<dir>/loader.img.
LOADER ?= $(loader)
RUN_PORT ?= 51820
# Build the default image; a packaged LOADER= is booted as is.
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
	cargo test --locked $(foreach c,$(host_crates),-p $(c)) > $(counts)/unit.log 2>&1 \
		|| { cat $(counts)/unit.log; exit 1; }
	# Per-crate counts too (M2 plan T12): a crate whose tests stop running
	# fails the manifest even if the total still clears its minimum.
	awk '/^ *Running / { c = $$NF; sub(/\)$$/, "", c); sub(/.*\//, "", c); sub(/-[0-9a-f]+$$/, "", c) } \
		/Doc-tests / { c = $$2 } \
		/^test result: ok\./ { n += $$4; per[c] += $$4 } \
		END { print "UNIT-TESTS", n; for (k in per) { u = toupper(k); gsub(/_/, "-", u); print "UNIT-" u, per[k] } }' \
		$(counts)/unit.log > $(counts)/unit

kani: | $(counts)
	rm -f $(counts)/kani.log
	$(foreach c,$(kani_crates),echo "KANI-CRATE $(c)" >> $(counts)/kani.log; \
		tools/kani-gate.sh -p $(c) $(kani_args_$(c)) >> $(counts)/kani.log \
		|| { cat $(counts)/kani.log; exit 1; };)
	# Per-crate counts too (M2 plan T12), keyed KANI-<CRATE>.
	awk '/^KANI-CRATE / { c = toupper($$2) } /^KANI-HARNESSES/ { n += $$2; per[c] += $$2 } \
		END { print "KANI-HARNESSES", n; for (k in per) print "KANI-" k, per[k] }' \
		$(counts)/kani.log > $(counts)/kani

bolero_targets := wire/tests::fuzz_parse_never_panics_and_round_trips \
	wg-wire/tests::fuzz_parsers_never_panic_and_round_trip \
	rosenpass-wire/tests::fuzz_parsers_never_panic_and_round_trip

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
	grep -E '^(CHECK-(PINS-RULES|PINS-FIXTURES|SELFTEST-FIXTURES)|PACKAGE-FIXTURES|SECCOMP-FIXTURES|CONFIG-BUILD-FIXTURES|CHECK-MANIFEST-FIXTURES|HARNESS-SIGNAL-FIXTURES|AUDIT-GATE-FIXTURES|RP-COOKIE-TWIN-FIXTURES)' $(counts)/pins.log > $(counts)/pins

# Builds its own deployment (fresh keys, generated config, package); see run.py.
test: | $(counts)
	python3 tests/integration/run.py > $(counts)/test.log 2>&1 \
		|| { tail -40 $(counts)/test.log; exit 1; }
	grep '^INTEGRATION-CASES' $(counts)/test.log > $(counts)/test

manifest:
	tools/check-manifest tests/manifest.txt $(counts)

# Count files from earlier runs are removed first, so a gate that does not
# run this time is reported missing instead of passing on a stale count.
clean-counts:
	mkdir -p $(counts)
	find $(counts) -maxdepth 1 -type f ! -name '*.log' -delete

check:
	$(MAKE) clean-counts
	$(MAKE) pins audit lint lint-pds unit kani bolero laws test
	$(MAKE) manifest

# Requires a prior `make check` (the manifest case reuses build/counts).
check-selftest:
	tools/check-selftest

clean:
	rm -rf $(BUILD)
