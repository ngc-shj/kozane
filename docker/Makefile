image := secureos-dev
container := secureos-dev
repo := $(abspath ..)

.PHONY: build
build:
	docker build \
		--build-arg UID=$(shell id -u) \
		--build-arg GID=$(shell id -g) \
		-t $(image) .

.PHONY: run
run: build
	docker run -d --name $(container) \
		--mount type=bind,src=$(repo),dst=/work \
		--mount type=volume,src=secureos-cargo-registry,dst=/home/dev/.cargo/registry \
		$(image) sleep inf

.PHONY: exec
exec:
	docker exec -it $(container) bash

.PHONY: rm
rm:
	docker rm -f $(container)
