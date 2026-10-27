# libtcg2-tpm

TCG2-compliant TPM library based on the [TCG PC Client Platform TPM Profile for
TPM 2.0 Specification
v1.06](https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-Version-1p06_pub.pdf).

This library provides a lightweight C interface for interacting with TPM 2.0
devices, specifically targeting platforms compliant with the TCG2 specification.

## Prerequisites

- CMake >= 3.15
- AArch64 Linux GNU toolchain (for cross-compilation)

## Building

### Native Build

```bash
cmake -B build
cmake --build build
```

### Cross Compilation

```bash
CC=aarch64-linux-gnu-gcc cmake -B build -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
cmake --build build
```

## License

This project is licensed under the BSD 3-Clause License. See the
[LICENSE](./LICENSE) file for more information.
