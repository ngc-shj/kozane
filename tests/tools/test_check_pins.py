"""Each check-pins rule must fire on a one-change mutation of the real repo
files and stay silent on the unmodified copy (plan C1/C2 acceptance).

Usage: python3 tests/tools/test_check_pins.py
Prints "CHECK-PINS-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/check-pins"
FILES = ["docker/Dockerfile", "Makefile", "rust-toolchain.toml", "Cargo.toml", "Cargo.lock", "policy/waivers.toml"]
# P7's cases run on a tree whose crates/ is replaced by a synthetic one.
# --enforce-pending is kept so they stay meaningful if P7 is ever pending.
ENFORCE = ["--enforce-pending"]


def rules_fired(tree: pathlib.Path, args=()) -> set:
    out = subprocess.run([sys.executable, str(TOOL), "--root", str(tree), *args], capture_output=True, text=True)
    fired = {line.split()[0] for line in out.stdout.splitlines() if line[:1] == "P"}
    if bool(fired) != (out.returncode == 1):
        raise SystemExit(f"exit status {out.returncode} disagrees with output {fired}")
    return fired


def copy_tree(dst: pathlib.Path):
    for f in FILES:
        (dst / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, dst / f)
    # Sources only: P7-P10 read *.rs and Cargo.toml, P3 reads Cargo.toml.
    for src in (ROOT / "crates").rglob("*"):
        rel = src.relative_to(ROOT)
        if src.is_file() and (src.suffix == ".rs" or src.name == "Cargo.toml") and "target" not in rel.parts:
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst / rel)


def write(path: pathlib.Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def append(path: pathlib.Path, text: str):
    if not path.exists():
        raise SystemExit(f"fixture target missing: {path}")
    path.write_text(path.read_text() + text)


def synthetic_crates(t: pathlib.Path, lib: str = "pub fn f() {}\n"):
    shutil.rmtree(t / "crates")
    write(t / "crates/demo/Cargo.toml", '[package]\nname = "demo"\nversion = "0.1.0"\n')
    write(t / "crates/demo/src/lib.rs", lib)


def drop_cmr(t: pathlib.Path):
    edit(t / "Cargo.lock", '[[package]]\nname = "classic-mceliece-rust"\nversion = "2.0.2"\n',
         '[[package]]\nname = "classic-mceliece-rust-was"\nversion = "2.0.2"\n')


SC23 = '[[waivers]]\nid = "SC23"\nowner = "M4"\nstatus = "open"\n'
SECRET = "\npub struct Secret<const N: usize>([u8; N]);\n"


def edit(path: pathlib.Path, old: str, new: str):
    text = path.read_text()
    if old not in text:
        raise SystemExit(f"fixture anchor not found in {path.name}: {old!r}")
    path.write_text(text.replace(old, new, 1))


CASES = [
    ("clean copy passes", set(), lambda t: None),
    ("P1 download without hash check", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", 'echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c -; \\\n', "")),
    ("P1 hash check names a different file", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", 'echo "$RUSTUP_SHA256  /tmp/rustup-init" | sha256sum -c -',
                    'echo "$RUSTUP_SHA256  /tmp/other" | sha256sum -c -')),
    ("P1 download without -o", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", "WORKDIR /work",
                    "RUN curl -sSfLO https://example.invalid/x; \\\n    echo 0  x | sha256sum -c -\nWORKDIR /work")),
    ("P1 curl with URL before options", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", 'curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org',
                    'curl "https://example.invalid/x" -o /tmp/x; curl -sSfL -o /tmp/rustup-init "https://static.rust-lang.org')),
    ("P1 ADD from URL", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", "WORKDIR /work", "ADD https://example.invalid/x /x\nWORKDIR /work")),
    ("P1 git clone", {"P1"},
     lambda t: edit(t / "docker/Dockerfile", "WORKDIR /work", "RUN git clone https://example.invalid/r\nWORKDIR /work")),
    ("P2 download piped to shell", {"P2"},
     lambda t: edit(t / "docker/Dockerfile", "WORKDIR /work",
                    "RUN curl -sSf https://example.invalid/x.sh | sh; \\\n    sha256sum -c /dev/null\nWORKDIR /work")),
    ("P3 git dep without rev", {"P3"},
     lambda t: edit(t / "Cargo.toml", 'rev = "86a0dbf4f53e6766734331c5df61851489ed38a1", default-features', "default-features")),
    ("P3 git dep with branch", {"P3"},
     lambda t: edit(t / "Cargo.toml", 'rev = "86a0dbf4f53e6766734331c5df61851489ed38a1", default-features',
                    'rev = "86a0dbf4f53e6766734331c5df61851489ed38a1", branch = "main", default-features')),
    ("P4 toolchain mismatch", {"P4"},
     lambda t: edit(t / "rust-toolchain.toml", "nightly-2026-08-21", "nightly-2026-08-22")),
    ("P5 shell not bash", {"P5"}, lambda t: edit(t / "Makefile", "SHELL := bash", "SHELL := sh")),
    ("P5 no pipefail", {"P5"},
     lambda t: edit(t / "Makefile", ".SHELLFLAGS := -euo pipefail -c", ".SHELLFLAGS := -c")),
    ("P5 masked exit", {"P5"},
     lambda t: edit(t / "Makefile", "\ttools/check-manifest tests/manifest.txt $(counts)",
                    "\ttools/check-manifest tests/manifest.txt $(counts) || true")),
    ("P5 '|| :' at end of line", {"P5"},
     lambda t: edit(t / "Makefile", "\ttools/check-manifest tests/manifest.txt $(counts)",
                    "\ttools/check-manifest tests/manifest.txt $(counts) || :")),
    ("P5 '||:'", {"P5"},
     lambda t: edit(t / "Makefile", "\ttools/check-manifest tests/manifest.txt $(counts)",
                    "\ttools/check-manifest tests/manifest.txt $(counts) ||:")),
    ("P5 '+-' prefix", {"P5"}, lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\t+-rm -rf $(BUILD)")),
    ("P5 whitespace before '@-'", {"P5"}, lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\t @-rm -rf $(BUILD)")),
    ("P5 '(cmd || true)'", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\t(rm -rf $(BUILD) || true)")),
    ("P5 '-' after a backslash followed by a space", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\techo x \\ \n\t-rm -rf $(BUILD)")),
    ("P5 '-' after an even number of backslashes", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\techo x \\\\\n\t-rm -rf $(BUILD)")),
    ("allow '-' on a true continuation line", set(),
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf \\\n\t\t-- $(BUILD)")),
    ("P5 '|| \\' then 'true' on the next line", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) || \\\n\t\ttrue")),
    ("P5 MAKEFLAGS -i on a continuation line", {"P5"},
     lambda t: edit(t / "Makefile", "BUILD ?= build", "MAKEFLAGS += \\\n\t-i\nBUILD ?= build")),
    ("P5 '|' split across a continuation", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) |\\\n\t| true")),
    ("P5 'true' split across a continuation", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) || tr\\\n\tue")),
    ("P5 '|| exit 00'", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) || exit 00")),
    ("P5 .RECIPEPREFIX", {"P5"}, lambda t: edit(t / "Makefile", "BUILD ?= build", ".RECIPEPREFIX = >\nBUILD ?= build")),
    ("P5 inline recipe '; -cmd'", {"P5"}, lambda t: edit(t / "Makefile", "clean:\n", "x: ; -false\nclean:\n")),
    ("allow inline recipe without prefix", set(), lambda t: edit(t / "Makefile", "clean:\n", "x: ; echo ok\nclean:\n")),
    ("P5 MAKEFLAGS -k after a backslash with no space", {"P5"},
     lambda t: edit(t / "Makefile", "BUILD ?= build", "MAKEFLAGS += -s\\\n-k\nBUILD ?= build")),
    ("P5 '|| exit 0'", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) || exit 0")),
    ("allow '|| exit 1' and ':' in a URL", set(),
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\trm -rf $(BUILD) || exit 1\n\t@echo http://x:80")),
    ("P5 ignore prefix", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\t-rm -rf $(BUILD)")),
    ("P5 .IGNORE", {"P5"}, lambda t: edit(t / "Makefile", "clean:\n", ".IGNORE:\nclean:\n")),
    # P6: SC23 bound to cmr (any version) in Cargo.lock; waivers.toml must parse.
    ("allow cmr locked and SC23 open", set(), lambda t: edit(t / "policy/waivers.toml", SC23, SC23)),
    ("P6 cmr locked and SC23 absent", {"P6"}, lambda t: edit(t / "policy/waivers.toml", SC23, "")),
    ("P6 cmr locked and SC23 closed", {"P6"},
     lambda t: edit(t / "policy/waivers.toml", SC23, SC23.replace('"open"', '"closed"'))),
    ("allow neither cmr nor SC23", set(),
     lambda t: (drop_cmr(t), edit(t / "policy/waivers.toml", SC23, ""))),
    ("P6 cmr at another version and SC23 absent", {"P6"},
     lambda t: (edit(t / "Cargo.lock", 'name = "classic-mceliece-rust"\nversion = "2.0.2"',
                     'name = "classic-mceliece-rust"\nversion = "2.0.3"'),
                edit(t / "policy/waivers.toml", SC23, ""))),
    ("P6 Cargo.lock without [[package]] tables", {"P6"},
     lambda t: (t / "Cargo.lock").write_text("version = 4\n")),
    ("P6 waivers.toml missing", {"P6"}, lambda t: (t / "policy/waivers.toml").unlink()),
    ("P6 waivers.toml unparsable", {"P6"}, lambda t: edit(t / "policy/waivers.toml", SC23, SC23 + "status = \n")),
    ("P6 waiver status neither open nor closed", {"P6"},
     lambda t: edit(t / "policy/waivers.toml", SC23, SC23.replace('"open"', '"waived"'))),
    ("P6 waiver with an unknown key", {"P6"},
     lambda t: edit(t / "policy/waivers.toml", SC23, SC23 + 'expires = "never"\n')),
    ("P6 waiver id listed twice", {"P6"}, lambda t: edit(t / "policy/waivers.toml", SC23, SC23 + "\n" + SC23)),
    # P7: on synthetic crates.
    ("allow synthetic crates without psk_mix", set(), lambda t: synthetic_crates(t), ENFORCE),
    ("P7 psk_mix identifier", {"P7"}, lambda t: synthetic_crates(t, "pub fn psk_mix() {}\n"), ENFORCE),
    ("P7 PSK_MIX constant", {"P7"}, lambda t: synthetic_crates(t, "pub const LABEL_PSK_MIX: u64 = 2;\n"), ENFORCE),
    ("P7 PskMix in a comment", {"P7"}, lambda t: synthetic_crates(t, "// then PskMix on accept\n"), ENFORCE),
    ("P7 psk_mix in a Cargo.toml", {"P7"},
     lambda t: (synthetic_crates(t), append(t / "crates/demo/Cargo.toml", "[features]\npsk-mix = []\npsk_mix = []\n")),
     ENFORCE),
    # P8: crate sources and manifests, never Cargo.lock.
    ("P8 getrandom in a crate source", {"P8"},
     lambda t: append(t / "crates/wire/src/lib.rs", "\nuse getrandom::fill;\n")),
    ("P8 thread_rng in a crate source", {"P8"},
     lambda t: append(t / "crates/hs-core/src/lib.rs", "\nfn r() { let _ = rand::thread_rng(); }\n")),
    ("P8 OsRng in a crate source", {"P8"},
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", "\nuse rand_core::OsRng;\n")),
    ("P8 getrandom feature in a crate Cargo.toml", {"P8"},
     lambda t: append(t / "crates/pqkey-core/Cargo.toml", '\n[features]\nstd = ["rand_core/getrandom"]\n')),
    ("allow getrandom in Cargo.lock", set(),
     lambda t: append(t / "Cargo.lock", '\n[[package]]\nname = "getrandom"\nversion = "0.2.15"\n')),
    # P9: Secret<- or Zeroizing<-wrapping types in the secret crates.
    ("P9 derive(Clone) on a Secret wrapper", {"P9"},
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", SECRET + "#[derive(Clone)]\npub struct Osk(Secret<32>);\n")),
    ("P9 derive(Debug) behind another attribute", {"P9"},
     lambda t: append(t / "crates/pqkey-core/src/lib.rs",
                      SECRET + "#[derive(PartialEq, Debug)]\n#[repr(C)]\npub struct Reply {\n    shk: Secret<32>,\n}\n")),
    ("P9 cfg_attr derive(Copy) in pds/pq", {"P9"},
     lambda t: write(t / "crates/pds/pq/src/main.rs",
                     SECRET + "#[cfg_attr(test, derive(Copy))]\nenum Slot {\n    Live(Secret<32>),\n    Empty,\n}\n")),
    ("P9 derive(Clone) on a Zeroizing wrapper in pqkey-core", {"P9"},
     lambda t: append(t / "crates/pqkey-core/src/lib.rs",
                      "\n#[derive(Clone)]\npub struct Seed(zeroize::Zeroizing<[u8; 32]>);\n")),
    ("P9 derive(Debug) on a Secret wrapper in pds/pqkey", {"P9"},
     lambda t: write(t / "crates/pds/pqkey/src/main.rs", SECRET + "#[derive(Debug)]\nstruct Shk(Secret<32>);\n")),
    # P10: by-value secret copies.
    ("P10 from_bytes(*..) in hs-core", {"P10"},
     lambda t: append(t / "crates/hs-core/src/lib.rs", "\nfn f(k: &[u8; 32]) -> Key32 { Key32::from_bytes(*k) }\n")),
    ("P10 from_bytes( *..) in rosenpass-core", {"P10"},
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", "\nfn f(k: &[u8; 32]) -> Secret<32> { Secret::from_bytes( *k) }\n")),
    ("allow from_bytes on an owned array", set(),
     lambda t: append(t / "crates/hs-core/src/lib.rs", "\nfn f() -> Key32 { Key32::from_bytes([0; 32]) }\n")),
    ("allow from_bytes(*..) outside the secret crates", set(),
     lambda t: append(t / "crates/wire/src/lib.rs", "\nfn f(k: &[u8; 4]) -> u32 { u32::from_le_bytes(*k) }\nfn g(k: &[u8; 4]) -> X { X::from_bytes(*k) }\n")),
    ("P9 derive(Debug) on Secret itself", {"P9"},
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", "\n#[derive(Debug)]\npub struct Secret<const N: usize>([u8; N]);\n")),
    ("allow derive(Clone) on a type without a Secret", set(),
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs",
                      SECRET + "#[derive(Clone)]\npub struct Header {\n    len: u8,\n}\npub struct Osk(Secret<32>);\n")),
    ("allow derive(PartialEq) on a Secret wrapper", set(),
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", SECRET + "#[derive(PartialEq)]\npub struct Osk(Secret<32>);\n")),
    ("allow derive(Debug) on a Secret wrapper outside the secret crates", set(),
     lambda t: append(t / "crates/wg-core/src/lib.rs", SECRET + "#[derive(Debug)]\npub struct Osk(Secret<32>);\n")),
    ("allow derive(Clone) in a comment", set(),
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs", SECRET + "// no #[derive(Clone)]: L12\npub struct Osk(Secret<32>);\n")),
]


def main() -> int:
    failures = 0
    for name, want, mutate, *args in CASES:
        with tempfile.TemporaryDirectory() as d:
            tree = pathlib.Path(d)
            copy_tree(tree)
            mutate(tree)
            got = rules_fired(tree, *args)
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: got {sorted(got)} want {sorted(want)}")
    print(f"CHECK-PINS-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
