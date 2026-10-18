# Development image for secureos. Host and target are both aarch64.
# Every downloaded artifact is pinned by sha256; the Microkit SDK is also
# checked against the release key in keys/ (fingerprint pinned below).

# trixie: Kani 0.68 release binaries need glibc >= 2.39.
FROM debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5

# apt resolves against a fixed snapshot so package versions do not drift.
# Plain http is fine: apt verifies Release signatures with the archive keyring,
# and ca-certificates is not installed yet at this point.
ARG DEBIAN_SNAPSHOT=20261015T000000Z
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
        "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main" \
        "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie-updates main" \
        "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} trixie-security main" \
        > /etc/apt/sources.list

RUN apt-get update -q && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    xz-utils \
    # qemu build
    ninja-build \
    pkg-config \
    python3-venv \
    libglib2.0-dev \
    libpixman-1-dev \
    libslirp-dev \
    flex \
    bison \
    # bindgen (sel4-sys)
    libclang-dev \
    # tests
    python3-pexpect \
    iproute2 \
    netcat-openbsd \
    # M2 interop: official userspace WireGuard as the test client
    wireguard-go \
    wireguard-tools \
    iputils-ping \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

ARG ARM_GNU_URL=https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-aarch64-aarch64-none-elf.tar.xz
ARG ARM_GNU_SHA256=c4f0daab43f78e0d56ec2bdad76b98a0223ce12ce7fc51a6ce82f9cc6c6dfba0
RUN set -eux; \
    curl -sSfL -o /tmp/gcc.tar.xz "$ARM_GNU_URL"; \
    echo "$ARM_GNU_SHA256  /tmp/gcc.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/gcc-aarch64-none-elf; \
    tar -xJf /tmp/gcc.tar.xz -C /opt/gcc-aarch64-none-elf --strip-components=1; \
    rm /tmp/gcc.tar.xz
ENV PATH=/opt/gcc-aarch64-none-elf/bin:$PATH

# QEMU 9.0.0 + coliasgroup patch adding 2x sp804 timers to arm virt
# (same pins as seL4/rust-sel4 hacking/nix/scope/qemu).
ARG QEMU_SHA256=32708ac66c30d8c892633ea968c771c1c76d597d70ddead21a0d22ccf386da69
ARG SP804_PATCH_URL=https://github.com/coliasgroup/qemu/commit/7994b0d17da7dbf1cf2da3e6555914e23559b23e.patch
ARG SP804_PATCH_SHA256=a396752d817aa70a811ab3f80183885e685283be70ee6211bb1be3d9908ef876
RUN set -eux; \
    cd /tmp; \
    curl -sSfL -o qemu.tar.xz https://download.qemu.org/qemu-9.0.0.tar.xz; \
    echo "$QEMU_SHA256  qemu.tar.xz" | sha256sum -c -; \
    curl -sSfL -o sp804.patch "$SP804_PATCH_URL"; \
    echo "$SP804_PATCH_SHA256  sp804.patch" | sha256sum -c -; \
    tar -xJf qemu.tar.xz; \
    cd qemu-9.0.0; \
    patch -p1 < ../sp804.patch; \
    ./configure --prefix=/opt/qemu --target-list=aarch64-softmmu \
        --enable-slirp --disable-docs --disable-werror; \
    make -j"$(nproc)"; \
    make install; \
    cd /tmp; rm -rf qemu-9.0.0 qemu.tar.xz sp804.patch
ENV PATH=/opt/qemu/bin:$PATH

ARG MICROKIT_VERSION=2.3.1
ARG MICROKIT_SHA256=979553f288e8e2c099dae8fbec86cbe2cfda2ca006ee36de8234649d6d23bbee
ARG MICROKIT_ASC_SHA256=8c64fcd77ded111654e9df493232ae86891e7940918f80f72b7eaa5ea456f5b4
ARG MICROKIT_KEY_FPR=FE91486443B0F4EB9ECC36524D868A34EDF3FDCA
ENV MICROKIT_SDK=/opt/microkit/sdk
COPY keys/microkit-release.asc /tmp/microkit-release.asc
RUN set -eux; \
    cd /tmp; \
    base="https://github.com/seL4/microkit/releases/download/${MICROKIT_VERSION}/microkit-sdk-${MICROKIT_VERSION}-linux-aarch64.tar.gz"; \
    curl -sSfL -o sdk.tar.gz "$base"; \
    curl -sSfL -o sdk.tar.gz.asc "$base.asc"; \
    echo "$MICROKIT_SHA256  sdk.tar.gz" | sha256sum -c -; \
    echo "$MICROKIT_ASC_SHA256  sdk.tar.gz.asc" | sha256sum -c -; \
    export GNUPGHOME="$(mktemp -d)"; \
    gpg --batch --import microkit-release.asc; \
    gpg --batch --status-fd 1 --verify sdk.tar.gz.asc sdk.tar.gz | grep -q "VALIDSIG $MICROKIT_KEY_FPR"; \
    mkdir -p "$MICROKIT_SDK"; \
    tar -xzf sdk.tar.gz -C "$MICROKIT_SDK" --strip-components=1; \
    chmod -R a+rX "$MICROKIT_SDK"; \
    rm -rf "$GNUPGHOME" sdk.tar.gz sdk.tar.gz.asc microkit-release.asc

ARG UID=1000
ARG GID=1000
RUN set -eux; \
    getent group "$GID" || groupadd --gid "$GID" dev; \
    useradd --uid "$UID" --gid "$GID" --create-home dev; \
    # wireguard-go's UAPI socket directory, for the unprivileged test netns.
    install -d -o "$UID" -g "$GID" -m 0700 /var/run/wireguard
USER dev

# The toolchain itself is selected by rust-toolchain.toml in the repo.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433
RUN set -eux; \
    curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init"; \
    echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --default-toolchain none --profile minimal; \
    rm /tmp/rustup-init; \
    # Pre-create volume mount points so Docker initialises them owned by dev.
    mkdir -p /home/dev/.cargo/registry
ENV PATH=/home/dev/.cargo/bin:$PATH

# Must equal the channel in ../rust-toolchain.toml (checked by tools/check-pins).
ARG PD_TOOLCHAIN=nightly-2026-08-21
RUN rustup toolchain install "$PD_TOOLCHAIN" --profile minimal --component rust-src,rustfmt,clippy

# Kani: verifier binary from crates.io (checksummed via --locked) plus the
# release bundle verified by sha256, so `cargo kani setup` downloads nothing
# except its pinned toolchain through rustup.
ARG KANI_VERSION=0.68.0
ARG KANI_BUNDLE_SHA256=0042d2688bf1550270def4a79c96aaeea138631818cb4ab5480120f2d51a942c
ARG CARGO_BOLERO_VERSION=0.13.5
# Host tools are built with a pinned stable toolchain (no rust-toolchain.toml at build time).
ARG TOOLS_RUST=1.97.1
RUN set -eux; \
    rustup toolchain install "$TOOLS_RUST" --profile minimal; \
    cargo +"$TOOLS_RUST" install --locked kani-verifier --version "$KANI_VERSION"; \
    curl -sSfL -o /tmp/kani.tar.gz "https://github.com/model-checking/kani/releases/download/kani-${KANI_VERSION}/kani-${KANI_VERSION}-aarch64-unknown-linux-gnu.tar.gz"; \
    echo "$KANI_BUNDLE_SHA256  /tmp/kani.tar.gz" | sha256sum -c -; \
    cargo +"$TOOLS_RUST" kani setup --use-local-bundle /tmp/kani.tar.gz; \
    rm /tmp/kani.tar.gz; \
    cargo +"$TOOLS_RUST" install --locked cargo-bolero --version "$CARGO_BOLERO_VERSION"

WORKDIR /work
