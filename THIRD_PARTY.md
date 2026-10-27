# Third-party code

The project's own code is under the BSD 2-Clause license ([LICENSE](LICENSE)).
This file lists what it contains, derives from, or ships that is not its own.

## In this repository

| Path | Origin | License |
|---|---|---|
| `third_party/verus/` | Parts of [Verus](https://github.com/verus-lang/verus) at commit `426d8b01e7ffb910a36c15e1f870ff985bb61eef` (`vstd` and the macro crates it needs) | MIT, [third_party/verus/LICENSE](third_party/verus/LICENSE) |
| `crates/mce460896/` | A Rust port of Classic McEliece 460896: the decoding core and round-3 key generation from [libmceliece](https://lib.mceliece.org/) 20260622, the round-3 KEM framing as in PQClean `mceliece460896_vec` | libmceliece is in the public domain (`LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`), PQClean's Classic McEliece code likewise; the port is BSD-2-Clause |
| `crates/mce460896/tests/vectors/` | Outputs of liboqs 0.8 and classic-mceliece-rust 2.0.2 (see each file's header) | Test data |

## Rust dependencies

Crates come from crates.io and from git repositories pinned to a commit
(`Cargo.lock` and `tools/*/Cargo.lock`). All are under permissive licenses
(MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, Unlicense,
Unicode-3.0). Where a crate offers a choice that includes LGPL-2.1-or-later
(`r-efi`, a build-host dependency only), the permissive option is used. The
main ones in the shipped images are [rust-sel4](https://github.com/seL4/rust-sel4),
[libcrux](https://github.com/cryspen/libcrux) and
[smoltcp](https://github.com/smoltcp-rs/smoltcp).

## Built into the images, not in this repository

The dev container (`docker/Dockerfile`) downloads these, pinned by version and
SHA-256. A binary image contains them:

| Component | Version | License |
|---|---|---|
| seL4 kernel (from the Microkit SDK) | Microkit 2.3.1 | GPL-2.0-only |
| Microkit loader and monitor | 2.3.1 | BSD-2-Clause |
| U-Boot (measured-boot images) | 2025.01 | GPL-2.0-or-later |

Anyone who distributes a binary image must meet the GPL's source obligations
for the seL4 kernel and U-Boot, for example by naming the exact upstream
source and the configuration in `docker/Dockerfile` and this repository. They
must also reproduce the notices of the Rust crates linked into the image.
