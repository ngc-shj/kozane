image := secureos-dev
container := secureos-dev
repo := $(abspath ..)
# Hard cap (swap included) so a runaway cbmc is OOM-killed inside the
# container instead of thrashing the host; one Kani proof peaks near 28 GB.
memory ?= 64g

.PHONY: build
build:
	docker build \
		--build-arg UID=$(shell id -u) \
		--build-arg GID=$(shell id -g) \
		-t $(image) .

.PHONY: run
run: build
	# No NET_ADMIN: integration tests create an unprivileged user + network
	# namespace (allowed by seccomp-userns.json) and run QEMU and wireguard-go
	# inside it; /dev/net/tun alone grants nothing in the container's own netns.
	docker run -d --name $(container) \
		--security-opt seccomp=$(abspath seccomp-userns.json) \
		--device /dev/net/tun \
		--memory $(memory) --memory-swap $(memory) \
		--mount type=bind,src=$(repo),dst=/work \
		--mount type=volume,src=secureos-cargo-registry,dst=/home/dev/.cargo/registry \
		$(image) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container) bash

.PHONY: rm
rm:
	docker rm -f $(container)
