# Development image for secureos. Host and target are both aarch64.
# Every downloaded artifact is pinned by sha256; the Microkit SDK is also
# checked against the release key in keys/ (fingerprint pinned below).

# Shared by the oracle stage and the dev image.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433

# trixie: Kani 0.68 release binaries need glibc >= 2.39.
FROM debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 AS base

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

# VE9 interop oracle: upstream rosenpass at master and 0.2.3, built in a stage
# that sees neither /work nor any secret; only the two binaries reach the dev
# image. Sources are GitHub archives of full commits checked by sha256; the
# crates come from each upstream Cargo.lock (`cargo fetch --locked`; master's
# one git dependency, rosenpass/uds, is pinned there by commit) and the build
# itself runs with no network.
# RustSec advisory-db at a pinned commit, verified by sha256, for the
# offline `audit` gate (tools/audit-gate). Refreshing it means bumping both
# ARGs here and AUDIT-ADVISORIES in tests/manifest.txt.
FROM base AS advisory-db
RUN apt-get update -q && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ARG ADVISORY_DB_COMMIT=999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b
ARG ADVISORY_DB_SHA256=503a3f9e3b3976ce96e976fcaec69f90e0be63ce7ba6ad8a6645afc7ca944fa3
RUN set -eux; \
    curl -sSfL -o /tmp/advisory-db.tar.gz "https://github.com/rustsec/advisory-db/archive/${ADVISORY_DB_COMMIT}.tar.gz"; \
    echo "$ADVISORY_DB_SHA256  /tmp/advisory-db.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/advisory-db; \
    tar -xzf /tmp/advisory-db.tar.gz -C /opt/advisory-db --strip-components=1; \
    rm /tmp/advisory-db.tar.gz; \
    echo "$ADVISORY_DB_COMMIT" > /opt/advisory-db/SOURCE

FROM base AS rosenpass-oracle
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    # oqs-sys builds its vendored liboqs with cmake and bindgen
    cmake \
    libclang-dev \
    # 0.2.3 only: its libsodium-sys-stable has use-pkg-config on, so it links
    # the snapshot's libsodium dynamically and never downloads libsodium-stable
    libsodium-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG RUSTUP_VERSION
ARG RUSTUP_SHA256
# master's rust-toolchain.toml; 0.2.3 pins none and builds with the same one.
ARG RP_TOOLCHAIN=1.93.1
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN set -eux; \
    curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init"; \
    echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --default-toolchain none --profile minimal; \
    rm /tmp/rustup-init; \
    rustup toolchain install "$RP_TOOLCHAIN" --profile minimal

ARG RP_MASTER_COMMIT=9e72f1eb871c4c403e99e9b78262fff8dd8d7357
ARG RP_MASTER_SHA256=8e58490971058e778b097147cdbcc4b0c15449ffe01f28e873993c5cd6fc0e5a
ARG RP_023_COMMIT=512fe426be9281366d92a910d391fe8ddd72bd10
ARG RP_023_SHA256=d634faab090db013ad6447d3dc2eec798c117408d57421e179fa8ca77daf04ec
RUN set -eux; \
    base=https://github.com/rosenpass/rosenpass/archive; \
    curl -sSfL -o /tmp/rp-master.tar.gz "$base/${RP_MASTER_COMMIT}.tar.gz"; \
    echo "$RP_MASTER_SHA256  /tmp/rp-master.tar.gz" | sha256sum -c -; \
    curl -sSfL -o /tmp/rp-023.tar.gz "$base/${RP_023_COMMIT}.tar.gz"; \
    echo "$RP_023_SHA256  /tmp/rp-023.tar.gz" | sha256sum -c -; \
    for v in master 023; do \
        mkdir -p "/src/$v"; \
        tar -xzf "/tmp/rp-$v.tar.gz" -C "/src/$v" --strip-components=1; \
        rm "/tmp/rp-$v.tar.gz"; \
        (cd "/src/$v" && cargo +"$RP_TOOLCHAIN" fetch --locked); \
    done

RUN --network=none set -eux; \
    for v in master 023; do \
        (cd "/src/$v" && cargo +"$RP_TOOLCHAIN" build --release --locked --offline -p rosenpass --bin rosenpass); \
        install -D -m 0755 "/src/$v/target/release/rosenpass" "/opt/rosenpass-$v/rosenpass"; \
    done; \
    echo "$RP_MASTER_COMMIT" > /opt/rosenpass-master/SOURCE; \
    echo "$RP_023_COMMIT" > /opt/rosenpass-023/SOURCE

# Verus (M4 plan C1): built from a sha256-checked source tarball, offline
# after `cargo fetch --locked`. No aarch64-linux release binary exists. Z3 is
# the pinned release binary, so Verus's own download script is not used.
FROM base AS verus
RUN apt-get update -q && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256
ARG VERUS_COMMIT=426d8b01e7ffb910a36c15e1f870ff985bb61eef
ARG VERUS_SHA256=40be6fb66e457ca71210cb85b3febf3f43fce106df8db3caf3c18df349ab0b93
ARG Z3_SHA256=87fcd963d3eecb0f12cf1c3ef0ad74e84a3a7bd3caed5d94445645ef94ae6274
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN set -eux; \
    curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init"; \
    echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --default-toolchain none --profile minimal; \
    rm /tmp/rustup-init; \
    curl -sSfL -o /tmp/verus.tar.gz "https://github.com/verus-lang/verus/archive/${VERUS_COMMIT}.tar.gz"; \
    echo "$VERUS_SHA256  /tmp/verus.tar.gz" | sha256sum -c -; \
    mkdir -p /src/verus; \
    tar -xzf /tmp/verus.tar.gz -C /src/verus --strip-components=1; \
    rm /tmp/verus.tar.gz; \
    # Verus's build scripts read git HEAD. A throwaway repo over the
    # sha256-checked tree satisfies them; the version and commit are passed
    # explicitly (VARGO_BUILD_*), so the binary reports the real pin.
    (cd /src/verus && git init -q && git add -A \
        && git -c user.name=build -c user.email=build@localhost commit -q -m "verus ${VERUS_COMMIT}"); \
    # The toolchain and components come from Verus's rust-toolchain.toml.
    (cd /src/verus && rustup toolchain install); \
    (cd /src/verus/tools/vargo && cargo fetch --locked); \
    (cd /src/verus/source && cargo fetch --locked); \
    curl -sSfL -o /tmp/z3.zip https://github.com/Z3Prover/z3/releases/download/z3-4.16.0/z3-4.16.0-arm64-glibc-2.38.zip; \
    echo "$Z3_SHA256  /tmp/z3.zip" | sha256sum -c -; \
    unzip -q /tmp/z3.zip -d /tmp/z3; \
    install -m 0755 /tmp/z3/z3-4.16.0-arm64-glibc-2.38/bin/z3 /src/verus/source/z3; \
    rm -rf /tmp/z3 /tmp/z3.zip
RUN --network=none set -eux; \
    (cd /src/verus/tools/vargo && cargo build --release --locked --offline); \
    cd /src/verus/source; \
    CARGO_NET_OFFLINE=true VARGO_BUILD_VERSION=0.2026.10.04.426d8b0 VARGO_BUILD_SHA="$VERUS_COMMIT" \
        PATH=/src/verus/tools/vargo/target/release:$PATH vargo build --release; \
    rel=/src/verus/source/target-verus/release; \
    mkdir -p /opt/verus; \
    cp -a "$rel"/verus "$rel"/cargo-verus "$rel"/rust_verify "$rel"/z3 "$rel"/verus-root \
        "$rel"/version.txt "$rel"/vstd.vir "$rel"/libvstd.rlib "$rel"/libverus_builtin.rlib \
        "$rel"/libverus_builtin_macros.so "$rel"/libverus_state_machines_macros.so \
        "$rel"/builtin "$rel"/builtin_macros "$rel"/state_machines_macros "$rel"/vstd /opt/verus/; \
    echo "$VERUS_COMMIT" > /opt/verus/SOURCE

FROM base
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
    # M3 interop: rosenpass 0.2.3 (oracle stage) links it
    libsodium23 \
    # M4 C9: the constant-time gate runs the harness under memcheck
    valgrind \
    # M5 C8-C14: software TPM for QEMU, and tpm2-tools to provision it and
    # read PCRs (interop oracle)
    swtpm \
    swtpm-tools \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# M5 C8: U-Boot source, built by `make uboot` with the repo's config
# fragment and compiled-in boot command (so changing the command needs no
# image rebuild).
ARG UBOOT_VERSION=2025.01
ARG UBOOT_SHA256=cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f
RUN set -eux; \
    mkdir -p /opt/u-boot; \
    curl -sSfL -o /opt/u-boot/u-boot-${UBOOT_VERSION}.tar.bz2 "https://ftp.denx.de/pub/u-boot/u-boot-${UBOOT_VERSION}.tar.bz2"; \
    echo "$UBOOT_SHA256  /opt/u-boot/u-boot-${UBOOT_VERSION}.tar.bz2" | sha256sum -c -

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
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256
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
ARG CARGO_AUDIT_VERSION=0.22.2
# Host tools are built with a pinned stable toolchain (no rust-toolchain.toml at build time).
ARG TOOLS_RUST=1.97.1
RUN set -eux; \
    rustup toolchain install "$TOOLS_RUST" --profile minimal; \
    cargo +"$TOOLS_RUST" install --locked kani-verifier --version "$KANI_VERSION"; \
    curl -sSfL -o /tmp/kani.tar.gz "https://github.com/model-checking/kani/releases/download/kani-${KANI_VERSION}/kani-${KANI_VERSION}-aarch64-unknown-linux-gnu.tar.gz"; \
    echo "$KANI_BUNDLE_SHA256  /tmp/kani.tar.gz" | sha256sum -c -; \
    cargo +"$TOOLS_RUST" kani setup --use-local-bundle /tmp/kani.tar.gz; \
    rm /tmp/kani.tar.gz; \
    cargo +"$TOOLS_RUST" install --locked cargo-bolero --version "$CARGO_BOLERO_VERSION"; \
    cargo +"$TOOLS_RUST" install --locked cargo-audit --version "$CARGO_AUDIT_VERSION"

COPY --from=rosenpass-oracle /opt/rosenpass-master /opt/rosenpass-master
COPY --from=rosenpass-oracle /opt/rosenpass-023 /opt/rosenpass-023
COPY --from=advisory-db /opt/advisory-db /opt/advisory-db

# Verus runs with its own pinned stable toolchain (plus rustc-dev and
# llvm-tools), selected per call with RUSTUP_TOOLCHAIN; the project's
# rust-toolchain.toml stays on the PD nightly.
ARG VERUS_RUST=1.98.1
RUN rustup toolchain install "$VERUS_RUST" --profile minimal --component rustc-dev,llvm-tools
COPY --from=verus /opt/verus /opt/verus
# The sources of Verus's syn and prettyplease forks, beside the other
# verified sources, for the C5 pairing check (M5 plan C5).
COPY --from=verus /src/verus/dependencies/syn /opt/verus/syn
COPY --from=verus /src/verus/dependencies/prettyplease /opt/verus/prettyplease

WORKDIR /work
