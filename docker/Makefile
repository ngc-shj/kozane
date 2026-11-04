image := kozane-dev
container := kozane-dev
repo := $(abspath ..)
# Hard cap (swap included) so a runaway cbmc is OOM-killed inside the
# container instead of thrashing the host; one Kani proof peaks near 28 GB.
# 64g still froze the host (121 GB, ~38 GB held by other services) in M3b.
memory ?= 40g

.PHONY: build
build:
	docker build \
		--build-arg UID=$(shell id -u) \
		--build-arg GID=$(shell id -g) \
		-t $(image) .

# The same image for an x86_64 host (post-M6 plan P5). Built natively there;
# under emulation on an arm64 host it takes hours.
.PHONY: build-amd64
build-amd64:
	docker build --platform linux/amd64 \
		--build-arg UID=$(shell id -u) \
		--build-arg GID=$(shell id -g) \
		-t $(image):amd64 .

# M9 plan D8: KVM where the host has it (gx10), with the device's group so
# the unprivileged dev user can open it; QEMU's mem-lock needs the memlock
# limit lifted (P14).
kvm_flags := $(if $(wildcard /dev/kvm),--device /dev/kvm --group-add $(shell stat -c %g /dev/kvm))

.PHONY: run
run: build
	# No NET_ADMIN: integration tests create an unprivileged user + network
	# namespace (allowed by seccomp-userns.json) and run QEMU and wireguard-go
	# inside it; /dev/net/tun alone grants nothing in the container's own netns.
	docker run -d --name $(container) \
		--security-opt seccomp=$(abspath seccomp-userns.json) \
		--device /dev/net/tun \
		$(kvm_flags) \
		--ulimit memlock=-1 \
		--memory $(memory) --memory-swap $(memory) \
		--mount type=bind,src=$(repo),dst=/work \
		--mount type=volume,src=kozane-cargo-registry,dst=/home/dev/.cargo/registry \
		$(image) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container) bash

.PHONY: rm
rm:
	docker rm -f $(container)
