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
FILES = ["docker/Dockerfile", "Makefile", "rust-toolchain.toml", "Cargo.toml", "Cargo.lock", "policy/waivers.toml",
         "policy/verus-trusted.toml", ".cargo/config.toml",
         # P23: the allowlist and the files it lists that are not *.rs.
         "policy/old-name-allowlist", "tests/integration/run.py", "tests/tools/test_config_build.py",
         "tools/check-pins", "tests/tools/test_check_pins.py"]
# P7's cases run on a tree whose crates/ is replaced by a synthetic one.
# P7 is enforced, so they need no --enforce-pending.
ENFORCE: list = []


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
    # Sources only: P7-P10 read *.rs and Cargo.toml, P3 reads Cargo.toml;
    # P13 and P15 also read tools/ (its *.rs and the tool workspaces' locks).
    for top in ("crates", "tools"):
        for src in (ROOT / top).rglob("*"):
            rel = src.relative_to(ROOT)
            wanted = src.suffix == ".rs" or src.name == "Cargo.toml" or (top == "tools" and src.name == "Cargo.lock")
            if src.is_file() and wanted and "target" not in rel.parts:
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


def lock_cmr(t: pathlib.Path, version: str = "2.0.2"):
    """Locks cmr again (the live tree no longer does, after the M4 cut-over)."""
    lock_cmr_at(t / "Cargo.lock", version)


def lock_cmr_at(lock: pathlib.Path, version: str = "2.0.2"):
    append(lock, f'\n[[package]]\nname = "classic-mceliece-rust"\nversion = "{version}"\n'
                 'source = "registry+https://github.com/rust-lang/crates.io-index"\n')


# SC23 as the live policy lists it (closed since M4).
SC23 = '[[waivers]]\nid = "SC23"\nowner = "M4"\nstatus = "closed"\n'
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
    # The live tree no longer locks cmr (M4 cut-over), so the locked cases
    # inject it, and P13 (cmr is gone) fires on each of them too.
    ("cmr locked and SC23 open: only P13", {"P13"},
     lambda t: (lock_cmr(t), edit(t / "policy/waivers.toml", SC23, SC23.replace('"closed"', '"open"')))),
    ("P6 cmr locked and SC23 absent", {"P6", "P13"},
     lambda t: (lock_cmr(t), edit(t / "policy/waivers.toml", SC23, ""))),
    ("P6 cmr locked and SC23 closed", {"P6", "P13"},
     lambda t: (lock_cmr(t), edit(t / "policy/waivers.toml", SC23, SC23))),
    ("allow neither cmr nor SC23", set(), lambda t: edit(t / "policy/waivers.toml", SC23, "")),
    ("P6 cmr at another version and SC23 absent", {"P6", "P13"},
     lambda t: (lock_cmr(t, "2.0.3"), edit(t / "policy/waivers.toml", SC23, ""))),
    # P13 on its own: a dependency key and a `use`.
    ("P13 cmr as a dependency key", {"P13"},
     lambda t: edit(t / "crates/pqkey-core/Cargo.toml", "[dependencies]\n",
                    '[dependencies]\nclassic-mceliece-rust = "=2.0.2"\n')),
    ("P13 use classic_mceliece_rust", {"P13"},
     lambda t: append(t / "crates/pqkey-core/src/lib.rs", "\nuse classic_mceliece_rust as cmr;\n")),
    ("allow classic_mceliece_rust in a comment", set(),
     lambda t: append(t / "crates/pqkey-core/src/lib.rs", "\n// once classic_mceliece_rust::decapsulate\n")),
    # P13 reaches tools/ too (M4 plan C11): rp-vectors' own lock, and code.
    ("P13 cmr in rp-vectors' lock", {"P13"}, lambda t: lock_cmr_at(t / "tools/rp-vectors/Cargo.lock")),
    ("P13 extern crate classic_mceliece_rust in a tool", {"P13"},
     lambda t: append(t / "tools/rp-vectors/src/main.rs", "\nextern crate classic_mceliece_rust;\n")),
    ("P13 a classic_mceliece_rust:: path in a tool", {"P13"},
     lambda t: append(t / "tools/mksecrets/src/main.rs", "\nfn f() { classic_mceliece_rust::x(); }\n")),
    ("allow classic_mceliece_rust in a tool's comment", set(),
     lambda t: append(t / "tools/mksecrets/src/main.rs", "\n// replaced classic_mceliece_rust::decapsulate in M4\n")),
    # P16 fails closed too: it cannot find what it binds.
    ("P6 Cargo.lock without [[package]] tables", {"P6", "P16"},
     lambda t: (t / "Cargo.lock").write_text("version = 4\n")),
    ("P6 Cargo.lock not UTF-8", {"P6", "P16"}, lambda t: (t / "Cargo.lock").write_bytes(b"version = 4\n\xff\n")),
    ("P6 Cargo.lock package without a name", {"P6", "P16"},
     lambda t: (t / "Cargo.lock").write_text('version = 4\n[[package]]\nversion = "1"\n')),
    ("P6 waivers.toml missing", {"P6"}, lambda t: (t / "policy/waivers.toml").unlink()),
    ("P6 waivers.toml unparsable", {"P6"}, lambda t: edit(t / "policy/waivers.toml", SC23, SC23 + "status = \n")),
    ("P6 waiver status neither open nor closed", {"P6"},
     lambda t: edit(t / "policy/waivers.toml", SC23, SC23.replace('"closed"', '"waived"'))),
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
     lambda t: append(t / "crates/pds/pqkey/src/main.rs", SECRET + "#[derive(Debug)]\nstruct Shk(Secret<32>);\n")),
    # P9, M3b: pds/ingress joins, and a named secret type counts (A1).
    ("P9 derive(Clone) on a CookieSecret holder in pds/ingress", {"P9"},
     lambda t: append(t / "crates/pds/ingress/src/cookie.rs", "\n#[derive(Clone)]\npub struct Held {\n    secret: CookieSecret,\n}\n")),
    ("P9 derive(Debug) on an Option<Secret<..>> holder in pds/ingress", {"P9"},
     lambda t: append(t / "crates/pds/ingress/src/rp_cookie.rs", "\n#[derive(Debug)]\npub struct Pair {\n    current: Option<Secret<16>>,\n}\n")),
    # P11: cookie values compared without ct_eq (S3).
    ("P11 == on a cookie in rosenpass-core", {"P11"},
     lambda t: append(t / "crates/rosenpass-core/src/cookie.rs", "\npub fn bad(want: [u8; 16], cookie: [u8; 16]) -> bool {\n    cookie == want\n}\n")),
    ("P11 != against a cookie field in pds/ingress", {"P11"},
     lambda t: append(t / "crates/pds/ingress/src/rp_cookie.rs", "\nfn bad(want: [u8; 16], got: [u8; 16]) -> bool {\n    want != cookie_field(got)\n}\n")),
    ("P11 the cookie adapter removed", {"P11"},
     lambda t: (t / "crates/pds/ingress/src/rp_cookie.rs").unlink()),
    # P11, M5 plan I10.1: tpm2's Unseal response tag.
    ("P11 == on an HMAC tag in tpm2's client", {"P11"},
     lambda t: append(t / "crates/tpm2/src/client.rs",
                      "\nfn bad(expected: &[u8; 32], hmac: &[u8]) -> bool {\n    hmac == &expected[..]\n}\n")),
    ("P11 == on an HMAC tag in another tpm2 file", {"P11"},
     lambda t: append(t / "crates/tpm2/src/boot.rs",
                      "\nfn bad(expected: &[u8; 32], tag: &[u8]) -> bool {\n    tag == &expected[..]\n}\n")),
    ("P11 tpm2's client removed", {"P11"},
     lambda t: (t / "crates/tpm2/src/client.rs").unlink()),
    ("allow ct_eq on an HMAC tag in tpm2's client", set(),
     lambda t: append(t / "crates/tpm2/src/client.rs",
                      "\nfn ok(expected: &[u8; 32], hmac: &[u8]) -> bool {\n    ct_eq(expected, hmac)\n}\n")),
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
    ("P11 a cookie compare inside a comment, and ct_eq", set(),
     lambda t: append(t / "crates/rosenpass-core/src/cookie.rs", "\n// cookie == want would be wrong here\npub fn ok(a: &[u8], cookie: &[u8]) -> bool {\n    crypto::ct_eq(a, cookie)\n}\n")),
    # P12 (M4 C1, C11): a trusted Verus construct not on the allowlist, in
    # the cfg_attr spelling; the allowlisted one (msgs' chunk_ref) and
    # Kani's own `kani::assume` stay silent.
    ("P12 unlisted external_body via cfg_attr in wg-wire", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "#[inline]\n#[cfg_attr(verus_keep_ghost, verifier::external_body)]\nfn below_window(")),
    ("P12 an assume_specification item in wg-wire", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "pub assume_specification [ core::cmp::max::<u64> ](a: u64, b: u64) -> (r: u64);\n\n"
                    "#[inline]\nfn below_window(")),
    ("P12 a path-qualified admit in wg-wire", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "proof fn l() ensures false { verus_builtin::admit(); }\n\n#[inline]\nfn below_window(")),
    ("P12 the expanded assume_ in wg-wire", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "proof fn l() ensures false { assume_(false); }\n\n#[inline]\nfn below_window(")),
    ("P12 external_body after a quote char literal", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "const Q: char = '\"';\n#[inline]\n#[verifier::external_body]\nfn below_window(")),
    ("P12 external_body after a raw string holding a quote", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "const R: &str = r#\"a\"b\"#;\n#[inline]\n#[verifier::external_body]\nfn below_window(")),
    # P12 after Phase 3 (M4): constructs counted per item, cfg splits, the
    # whole file, and code the scan cannot read.
    ("P12 a second external_body in the allowlisted msgs file", {"P12"},
     lambda t: edit(t / "crates/msgs/src/lib.rs", "/// The `N` bytes of `b` at `at`, borrowed in place",
                    "#[verifier::external_body]\nfn extra() {}\n\n/// The `N` bytes of `b` at `at`, borrowed in place")),
    ("P12 the allowlist entry bound to another item", {"P12"},
     lambda t: edit(t / "policy/verus-trusted.toml", 'item = "chunk_ref"', 'item = "decode"')),
    ("P12 a cfg(verus_keep_ghost) fn", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(verus_keep_ghost)]\nfn ghost_only() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg!(verus_keep_ghost) branch", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "fn split() -> bool { cfg!(verus_keep_ghost) }\n" + "#[inline]\nfn below_window(")),
    ("allow a cfg(verus_keep_ghost) use of a vstd lemma", set(),
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(verus_keep_ghost)]\nuse vstd::arithmetic::mul::lemma_mul_is_associative;\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg(verus_keep_ghost) use of a vstd exec item", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(verus_keep_ghost)]\nuse vstd::seq::Seq;\n" + "#[inline]\nfn below_window(")),
    ("P12 admit in a macro_rules outside verus!", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmacro_rules! m { () => { admit() } }\n")),
    ("P12 a #[path] module", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\n#[path = "../../x.rs"]\nmod x;\n')),
    ("P12 an include!", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\ninclude!("../../x.rs");\n')),
    ("allow an include_bytes!", set(),
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\n#[cfg(test)]\nconst B: &[u8] = include_bytes!("lib.rs");\n')),
    ("P12 an external_trait_specification", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[verifier::external_trait_specification]\npub trait ExT {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a Tracked::assume_new", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "proof fn t() { let x = Tracked::<u8>::assume_new(); }\n" + "#[inline]\nfn below_window(")),
    ("P12 a hand-written verus::internal attribute", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[verus::internal(verus_macro)]\nfn hidden() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a verus crate without a verus! block", {"P12"},
     lambda t: [f.write_text(f.read_text().replace("verus!", "not_verus!")) for f in (t / "crates/ring/src").rglob("*.rs")]),
    # P12, Phase 3 round 2: cfg names beyond test/kani, the one vstd-use
    # exemption, aliased builtins, a shadowed kani, the verus_verify
    # attribute macro, cfg_attr(path), and what cargo compiles.
    ("P12 a shadow use under cfg(not(verus_keep_ghost))", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\n#[cfg(not(verus_keep_ghost))]\nuse crate::Transport as Shadow;\n")),
    ("P12 a cfg(verus_keep_ghost) use of a crate path", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\n#[cfg(verus_keep_ghost)]\nuse crate::Transport as Shadow;\n")),
    ("P12 an inner cfg(verus_keep_ghost) over a module", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "use vstd::prelude::*;\n",
                    "use vstd::prelude::*;\n#![cfg(verus_keep_ghost)]\n")),
    ("P12 a cfg(target_os) fn", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(target_os = \"none\")]\nfn on_target() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg!(debug_assertions) branch", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "fn dbg() -> bool { cfg!(debug_assertions) }\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg![verus_keep_ghost] branch", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "fn g2() -> bool { cfg![verus_keep_ghost] }\n" + "#[inline]\nfn below_window(")),
    ("allow cfg(any(test, kani))", set(), lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(any(test, kani))]\nfn harness_only() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 admit aliased by use", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nuse vstd::prelude::admit as ok;\n")),
    ("P12 admit handed to a macro as an ident", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmacro_rules! call { ($f:ident) => { $f() } }\nfn h() { call!(admit); }\n")),
    ("P12 kani::assume inside verus!", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "proof fn k() { kani::assume(false); }\n" + "#[inline]\nfn below_window(")),
    ("P12 a module named kani", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmod kani { pub fn f() {} }\n")),
    ("P12 external_body through verus_verify", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[verus_verify(external_body)]\nfn ext() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a verifier::$meta attribute in a macro", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmacro_rules! tr { ($a:ident) => { #[verifier::$a] fn x() {} } }\n")),
    ("P12 a path inside cfg_attr", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\n#[cfg_attr(all(), path = "../evil.rs")]\nmod evil;\n')),
    ("P12 two external_body on one line count twice", {"P12"},
     lambda t: edit(t / "crates/msgs/src/lib.rs", "#[verifier::external_body]\n#[inline]",
                    "#[verifier::external_body] #[verifier::external_body]\n#[inline]")),
    ("P12 a [lib] path in a verus crate", {"P12"},
     lambda t: append(t / "crates/wg-wire/Cargo.toml", '\n[lib]\npath = "real/lib.rs"\n')),
    ("P12 a build script in a verus crate", {"P12"},
     lambda t: write(t / "crates/wg-wire/build.rs", "fn main() {}\n")),
    # P12, Phase 3 round 3: cfg produced by cfg_attr, attributes from macro
    # metavariables, TRUSTED names outside attributes, literals that desync
    # the lexer, and the vstd-use exemption's shape.
    ("P12 a cfg produced by cfg_attr", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg_attr(all(), cfg(not(verus_keep_ghost)))]\nfn split() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg nested two cfg_attrs deep", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg_attr(all(), cfg_attr(all(), cfg(debug_assertions)))]\nfn split2() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 an attribute from a macro metavariable", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmacro_rules! at { ($a:meta) => { #[$a] fn x() {} } }\n")),
    ("P12 external_body passed to a macro", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nmac!(verifier::external_body; fn f() {});\n")),
    ("P12 verus_verify aliased by use", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nuse verus_builtin_macros::verus_verify as vv;\n")),
    ("P12 external_body after a raw C string", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "const C: &core::ffi::CStr = cr#\"\"\"#;\n#[verifier::external_body]\n" + "#[inline]\nfn below_window(")),
    # P18 lexes every crate and tool source too.
    ("P12 an unterminated string", {"P12", "P13", "P18", "P20"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\nconst S: &str = "never closed;\n')),
    ("allow a nested block comment", set(),
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\n/* outer /* inner */ still a comment */\n")),
    # Read without nesting, the comment ends at the first `*/` and the quote
    # after it opens a string that hides the real external_body.
    ("P12 external_body after a nested comment", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs",
                      '\n/* a /* b */ " */\n#[verifier::external_body]\nfn hid() {}\n// "\n')),
    ("allow verus ! with a space", set(),
     lambda t: [f.write_text(f.read_text().replace("verus! {", "verus ! {")) for f in (t / "crates/ring/src").rglob("*.rs")]),
    ("P12 a vstd lemma use aliased", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#[cfg(verus_keep_ghost)]\nuse vstd::arithmetic::mul::lemma_mul_is_associative as f;\n" + "#[inline]\nfn below_window(")),
    ("P12 a later attribute cannot steer the item", {"P12"},
     lambda t: edit(t / "crates/msgs/src/lib.rs", "#[verifier::external_body]\n#[inline]",
                    "#[verifier::external_body]\n#[cfg_attr(any(), x(fn chunk_ref))]\n#[inline]\nfn other() {}\n\n#[inline]")),
    ("P12 a [[bin]] path escaping src/", {"P12"},
     lambda t: append(t / "crates/wg-wire/Cargo.toml", '\n[[bin]]\nname = "x"\npath = "src/../other/main.rs"\n')),
    # The other source rules read Rust with the same lexer (R48): a "//" in
    # a string, a nested comment and a raw C string no longer hide code.
    ("P9 a derive after a URL string on its line", {"P9"},
     lambda t: append(t / "crates/rosenpass-core/src/lib.rs",
                      SECRET + 'const U: &str = "https://x"; #[derive(Clone)] pub struct Osk(Secret<32>);\n')),
    ("P10 from_bytes(*..) after a URL string on its line", {"P10"},
     lambda t: append(t / "crates/hs-core/src/lib.rs",
                      '\nconst U: &str = "https://x"; fn f(k: &[u8; 32]) -> Key32 { Key32::from_bytes(*k) }\n')),
    ("P11 a cookie compare after a URL string on its line", {"P11"},
     lambda t: append(t / "crates/rosenpass-core/src/cookie.rs",
                      '\nfn g(cookie: &[u8; 16], b: &[u8; 16]) -> bool { let _u = "https://x"; cookie == b }\n')),
    ("P13 a cmr use after a URL string on its line", {"P13"},
     lambda t: append(t / "crates/pqkey-core/src/lib.rs", '\nconst U: &str = "https://x"; use classic_mceliece_rust::x;\n')),
    ("P14 unsafe after a URL string on its line", {"P14"},
     lambda t: append(t / "crates/mce460896/src/gf.rs",
                      '\nconst U: &str = "https://x"; pub fn g(p: *const u8) -> u8 { unsafe { *p } }\n')),
    ("an unterminated string in mce460896 fails every rule that lexes it", {"P9", "P10", "P13", "P14", "P18", "P20"},
     lambda t: append(t / "crates/mce460896/src/gf.rs", '\nconst S: &str = "never closed;\n')),
    ("P12 a crate outside verus_crates depending on vstd", {"P12"},
     lambda t: edit(t / "Cargo.lock", 'name = "mce460896"\nversion = "0.1.0"\ndependencies = [\n',
                    'name = "mce460896"\nversion = "0.1.0"\ndependencies = [\n "vstd",\n')),
    # P12, round 4: `#`, `!` and `[` are separate tokens (spaces or a
    # comment between them), and cfg/include outside an attribute.
    ("P12 a spaced attribute's cfg split", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "# [cfg(not(verus_keep_ghost))]\nfn split3() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a cfg after a comment between # and [", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "#/**/[cfg(debug_assertions)]\nfn split4() {}\n" + "#[inline]\nfn below_window(")),
    ("P12 a spaced inner attribute", {"P12"},
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "use vstd::prelude::*;\n", "use vstd::prelude::*;\n# ! [cfg(debug_assertions)]\n")),
    ("P12 a spaced cfg! branch", {"P12"}, lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "fn g5() -> bool { cfg ! (verus_keep_ghost) }\n" + "#[inline]\nfn below_window(")),
    ("P12 cfg aliased by use", {"P12"}, lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nuse core::cfg as k;\n")),
    ("P12 a spaced include!", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs", '\ninclude ! ("../../x.rs");\n')),
    ("P12 a spaced #[path] in msgs", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs", '\n# [path = "../x.rs"]\nmod x;\n')),
    # The spaced macro form must be recognised as cfg! (not caught as a
    # stray `cfg` identifier): an allowed predicate passes.
    ("allow a spaced cfg ! (test) branch", set(),
     lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(",
                    "fn t7() -> bool { cfg ! (test) }\n#[inline]\nfn below_window(")),
    ("allow a cfg!(test) branch", set(), lambda t: edit(t / "crates/wg-wire/src/replay.rs", "#[inline]\nfn below_window(", "fn t6() -> bool { cfg!(test) }\n" + "#[inline]\nfn below_window(")),
    # P12, round 4 security: lexer edge cases rustc accepts, a trusted
    # construct inside a macro definition, build-environment reads, and a
    # zero-count allowlist entry.
    ("P12 external_body after an underscored unicode escape", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs",
                      "\nconst Q: [char; 2] = ['\\u{2_2}','\"'];\n#[verifier::external_body]\nfn evil() {}\n// \"\n")),
    ("P12 external_body after a shebang line", {"P12"},
     lambda t: (t / "crates/wg-wire/src/replay.rs").write_text(
         '#! "\n' + (t / "crates/wg-wire/src/replay.rs").read_text() + '\n#[verifier::external_body]\nfn evil() {}\n// "\n')),
    # The allowlisted attribute moved into a macro: still one occurrence,
    # bound to chunk_ref, but every invocation makes a trusted fn.
    ("P12 the allowlisted external_body inside a macro definition", {"P12"},
     lambda t: (edit(t / "crates/msgs/src/lib.rs", "#[verifier::external_body]\n#[inline]", "#[inline]"),
                append(t / "crates/msgs/src/lib.rs",
                       "\nmacro_rules! m { () => { verus! { #[verifier::external_body] fn chunk_ref() {} } } }\n"))),
    ("P12 option_env! in a verified crate", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\nconst P: Option<&str> = option_env!("CARGO_PRIMARY_PACKAGE");\n')),
    ("P12 env! outside test code", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", '\nconst D: &str = env!("CARGO_MANIFEST_DIR");\n')),
    ("P12 a zero-count allowlist entry", {"P12"},
     lambda t: append(t / "policy/verus-trusted.toml",
                      '\n[[trusted]]\ncrate = "wg-wire"\nfile = "src/replay.rs"\nconstruct = "external_body"\n'
                      'item = "below_window"\ncount = 0\ndeviation = "x"\n')),
    # P12, round 5: env reads by alias, shebangs, long escapes, a test
    # module also declared for non-test builds, raw macro names, and a
    # trusted construct handed to a macro.
    ("P12 option_env aliased by use", {"P12"},
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\nuse core::option_env as oe;\n")),
    ("P12 a shebang line", {"P12"},
     lambda t: (t / "crates/wg-wire/src/replay.rs").write_text("#!/usr/bin/env x\n" + (t / "crates/wg-wire/src/replay.rs").read_text())),
    ("P12 external_body after a long underscored escape", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs",
                      "\nconst Q: [char; 2] = ['\\u{4___________1}','\"'];\n#[verifier::external_body]\nfn evil() {}\n// \"\n")),
    ("P12 env! in a test module also declared for other builds", {"P12"},
     lambda t: edit(t / "crates/rosenpass-wire/src/lib.rs", "#[cfg(test)]\nmod tests;", "#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\nmod tests;")),
    ("P12 the allowlisted external_body inside a raw-named macro", {"P12"},
     lambda t: (edit(t / "crates/msgs/src/lib.rs", "#[verifier::external_body]\n#[inline]", "#[inline]"),
                append(t / "crates/msgs/src/lib.rs",
                       "\nmacro_rules! r#m { () => { verus! { #[verifier::external_body] fn chunk_ref() {} } } }\n"))),
    ("P12 the allowlisted external_body handed to a macro", {"P12"},
     lambda t: (edit(t / "crates/msgs/src/lib.rs", "#[verifier::external_body]\n#[inline]", "#[inline]"),
                append(t / "crates/msgs/src/lib.rs", "\ntwice! { #[verifier::external_body] fn chunk_ref() {} }\n"))),
    # Round 6: raw names in test-module declarations, and a shadowed verus.
    ("P12 env! in a test module also declared under a raw name", {"P12"},
     lambda t: edit(t / "crates/rosenpass-wire/src/lib.rs", "#[cfg(test)]\nmod tests;",
                    "#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\nmod r#tests;")),
    ("P12 a macro named verus", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs", "\nmacro_rules! verus { ($($t:tt)*) => { $($t)* } }\n")),
    ("P12 something used as verus", {"P12"},
     lambda t: append(t / "crates/msgs/src/lib.rs", "\nuse crate::twice as verus;\n")),
    ("P12 kani::assume outside verus! is not Verus's assume", set(),
     lambda t: append(t / "crates/wg-wire/src/replay.rs", "\n#[cfg(kani)]\nfn h() { kani::assume(true); }\n")),
    # P14 (M4 C7): unsafe only in the barrier module.
    ("P14 unsafe in mce460896 outside barrier.rs", {"P14"},
     lambda t: append(t / "crates/mce460896/src/vec.rs", "\npub fn f(p: *const u8) -> u8 { unsafe { *p } }\n")),
    ("P14 unsafe in barrier.rs", set(),
     lambda t: append(t / "crates/mce460896/src/barrier.rs", "\n#[allow(unsafe_code)]\npub fn g(p: *const u8) -> u8 { unsafe { *p } }\n")),
    # P15 (M4 C9): valgrind client requests only in the harness's vg.rs.
    ("P15 a client-request preamble in a crate", {"P15"},
     lambda t: append(t / "crates/wire/src/lib.rs", '\n// asm!("ror x12, x12, #3")\n')),
    ("P15 a client-request preamble in the harness outside vg.rs", {"P15"},
     lambda t: append(t / "tools/ct-harness/src/ct.rs", '\nfn f() { unsafe { core::arch::asm!("ror x12, x12, #3") } }\n')),
    ("P15 a client-request preamble in another tool", {"P15"},
     lambda t: append(t / "tools/mksecrets/src/main.rs", '\n// asm!("ror x12, x12, #3")\n')),
    ("P15 the preamble in tools/ct-harness/src/vg.rs", set(),
     lambda t: write(t / "tools/ct-harness/src/vg.rs", '// asm!("ror x12, x12, #3")\n')),
    # P16 (M4 C7): mce460896 depends on sha3 and zeroize only.
    ("P16 an extra dependency in mce460896", {"P16"},
     lambda t: edit(t / "crates/mce460896/Cargo.toml", "[dependencies]\n", '[dependencies]\nlibc = "=0.2.177"\n')),
    ("P16 a dev-dependency in mce460896", set(),
     lambda t: append(t / "crates/mce460896/Cargo.toml", '\n[dev-dependencies]\nzeroize = "=1.8.1"\n')),
    ("P16 a dependency renamed onto another package", {"P16"},
     lambda t: (edit(t / "crates/mce460896/Cargo.toml", 'sha3 = { version = "=0.10.9"',
                     'sha3 = { package = "sha2", version = "=0.10.9"'),
                edit(t / "Cargo.lock", 'name = "mce460896"\nversion = "0.1.0"\ndependencies = [\n "sha3",',
                     'name = "mce460896"\nversion = "0.1.0"\ndependencies = [\n "sha2",'))),
    ("P16 a path dependency under the right name", {"P16"},
     lambda t: edit(t / "crates/mce460896/Cargo.toml", 'sha3 = { version = "=0.10.9"',
                    'sha3 = { path = "../sha3", version = "=0.10.9"')),
    ("P16 a build-dependency in mce460896", {"P16"},
     lambda t: append(t / "crates/mce460896/Cargo.toml", '\n[build-dependencies]\ncc = "=1.0.0"\n')),
    ("P16 a target-specific dependency in mce460896", {"P16"},
     lambda t: append(t / "crates/mce460896/Cargo.toml", "\n[target.'cfg(unix)'.dependencies]\nlibc = \"=0.2.191\"\n")),
    ("P16 a feature on sha3", {"P16"},
     lambda t: edit(t / "crates/mce460896/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                    'sha3 = { version = "=0.10.9", default-features = false, features = ["asm"] }')),
    ("P16 default features on zeroize", {"P16"},
     lambda t: edit(t / "crates/mce460896/Cargo.toml", 'zeroize = { version = "=1.8.1", default-features = false }',
                    'zeroize = { version = "=1.8.1" }')),
    ("P16 a source replacement in .cargo/config.toml", {"P16"},
     lambda t: append(t / ".cargo/config.toml", '\n[source.crates-io]\nreplace-with = "vendored"\n')),
    ("P16 a [patch] in the legacy .cargo/config", {"P16"},
     lambda t: write(t / ".cargo/config", '[patch.crates-io]\nsha3 = { path = "x" }\n')),
    ("P16 a [features] table in mce460896", {"P16"},
     lambda t: append(t / "crates/mce460896/Cargo.toml", '\n[features]\nasm = ["sha3/asm"]\n')),
    ("P16 another member's sha3 with a feature", {"P16"},
     lambda t: edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                    'sha3 = { version = "=0.10.9", default-features = false, features = ["asm"] }')),
    ("P16 another member's zeroize as a bare version", {"P16"},
     lambda t: edit(t / "crates/hs-core/Cargo.toml", 'zeroize = { version = "=1.8.1", default-features = false }',
                    'zeroize = "=1.8.1"')),
    ("P16 another member's sha3 in a target table", {"P16"},
     lambda t: append(t / "crates/wg-core/Cargo.toml", '\n[target.\'cfg(unix)\'.dependencies]\nsha3 = "=0.10.9"\n')),
    ("P16 a member feature turning on zeroize's", {"P16"},
     lambda t: append(t / "crates/wg-core/Cargo.toml", '\n[features]\nx = ["zeroize/alloc"]\n')),
    ("P16 a sha3 with features in [workspace.dependencies]", {"P16"},
     lambda t: edit(t / "Cargo.toml", "[workspace.dependencies]\n",
                    '[workspace.dependencies]\nsha3 = { version = "=0.10.9", features = ["asm"] }\n')),
    ("P16 rustflags in .cargo/config.toml", {"P16"},
     lambda t: append(t / ".cargo/config.toml", '\n[build]\nrustflags = ["--cfg", "feature=\\"asm\\""]\n')),
    ("P16 an inherited sha3 with member features", {"P16"},
     lambda t: (edit(t / "Cargo.toml", "[workspace.dependencies]\n",
                     '[workspace.dependencies]\nsha3 = { version = "=0.10.9", default-features = false }\n'),
                edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                     'sha3 = { workspace = true, features = ["asm"] }'))),
    ("P16 an inherited renamed sha3 with member features", {"P16"},
     lambda t: (edit(t / "Cargo.toml", "[workspace.dependencies]\n",
                     '[workspace.dependencies]\nh = { package = "sha3", version = "=0.10.9", default-features = false }\n'),
                edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                     'h = { workspace = true, features = ["asm"] }'))),
    ("allow an inherited sha3 restating default-features = false", set(),
     lambda t: (edit(t / "Cargo.toml", "[workspace.dependencies]\n",
                     '[workspace.dependencies]\nsha3 = { version = "=0.10.9", default-features = false }\n'),
                edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                     'sha3 = { workspace = true, default-features = false }'))),
    ("allow an inherited sha3 without features", set(),
     lambda t: (edit(t / "Cargo.toml", "[workspace.dependencies]\n",
                     '[workspace.dependencies]\nsha3 = { version = "=0.10.9", default-features = false }\n'),
                edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                     'sha3 = { workspace = true }'))),
    ("P16 a renamed sha3's feature turned on", {"P16"},
     lambda t: (edit(t / "crates/rosenpass-core/Cargo.toml", 'sha3 = { version = "=0.10.9", default-features = false }',
                     'h = { package = "sha3", version = "=0.10.9", default-features = false }'),
                append(t / "crates/rosenpass-core/Cargo.toml", '\n[features]\nx = ["h/asm"]\n'))),
    ("P16 rustflags in a [target] table", {"P16"},
     lambda t: append(t / ".cargo/config.toml", "\n[target.aarch64-unknown-linux-gnu]\nrustflags = [\"-C\", \"x\"]\n")),
    ("P16 a workspace member without a Cargo.toml", {"P16"},
     lambda t: (t / "crates/wg-core/Cargo.toml").rename(t / "crates/wg-core/Cargo.toml.gone")),
    ("P16 a closure package without a checksum", {"P16"},
     lambda t: edit(t / "Cargo.lock", 'checksum = "cb26cec98cce3a3d96cbb7bced3c4b16e3d13f27ec56dbd62cbc8f39cfb9d653"\n', "")),
    ("P16 a [patch] in .cargo/config.toml", {"P16"},
     lambda t: append(t / ".cargo/config.toml", '\n[patch.crates-io]\nsha3 = { path = "x" }\n')),
    ("P16 a [patch] in the workspace", {"P16"},
     lambda t: edit(t / "Cargo.toml", "[patch.crates-io]\n", '[patch.crates-io]\nsha3 = { path = "vendor/sha3" }\n')),
    ("P16 a Verus patch to another path", {"P16"},
     lambda t: edit(t / "Cargo.toml", 'vstd = { path = "third_party/verus/vstd" }', 'vstd = { path = "vendor/vstd" }')),
    ("P16 a Verus patch from git", {"P16"},
     lambda t: edit(t / "Cargo.toml", 'vstd = { path = "third_party/verus/vstd" }',
                    'vstd = { git = "https://example.invalid/verus", rev = "' + "0" * 40 + '" }')),
    ("P16 a patch of another registry", {"P16"},
     lambda t: append(t / "Cargo.toml", '\n[patch."https://example.invalid/index"]\nvstd = { path = "third_party/verus/vstd" }\n')),
    ("P16 a workspace [replace]", {"P16"},
     lambda t: append(t / "Cargo.toml", '\n[replace]\n"sha3:0.10.9" = { path = "vendor/sha3" }\n')),
    ("P16 a new package in the closure", {"P16"},
     lambda t: edit(t / "Cargo.lock", 'name = "keccak"\nversion = "0.1.6"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum = "cb26cec98cce3a3d96cbb7bced3c4b16e3d13f27ec56dbd62cbc8f39cfb9d653"\ndependencies = [\n',
                    'name = "keccak"\nversion = "0.1.6"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum = "cb26cec98cce3a3d96cbb7bced3c4b16e3d13f27ec56dbd62cbc8f39cfb9d653"\ndependencies = [\n "memchr",\n')),
    ("P16 a closure package from another source", {"P16"},
     lambda t: edit(t / "Cargo.lock", 'name = "keccak"\nversion = "0.1.6"\nsource = "registry+https://github.com/rust-lang/crates.io-index"',
                    'name = "keccak"\nversion = "0.1.6"\nsource = "git+https://example.invalid/keccak#0"')),
    # P9/P10 (M4 C11): mce460896 joins the secret crates.
    ("P9 derive(Clone) on a Zeroizing holder in mce460896", {"P9"},
     lambda t: append(t / "crates/mce460896/src/lib.rs", "\n#[derive(Clone)]\npub struct Seed(Zeroizing<[u8; 32]>);\n")),
    ("P9 derive(Debug) on a plain-array state struct in mce460896", {"P9"},
     lambda t: append(t / "crates/mce460896/src/encrypt.rs", "\n#[derive(Debug)]\nstruct Leak {\n    e: [u8; 8],\n}\n")),
    ("P9 the RngError exception is by exact name", {"P9"},
     lambda t: append(t / "crates/mce460896/src/lib.rs", "\n#[derive(Debug)]\npub struct RngErrorX([u8; 4]);\n")),
    ("P10 from_bytes(*..) in mce460896", {"P10"},
     lambda t: append(t / "crates/mce460896/src/lib.rs", "\nfn f(k: &[u8; 32]) -> S { S::from_bytes(*k) }\n")),
    # P12 fails closed when it cannot find what to check (R50).
    ("P12 no verus_crates list in the Makefile", {"P12"},
     lambda t: edit(t / "Makefile", "verus_crates :=", "verus_crates =")),
    ("P12 a listed crate without sources", {"P12"},
     lambda t: shutil.rmtree(t / "crates/wg-wire/src")),
    ("P9 a CookieSecret holder without the derive", set(),
     lambda t: append(t / "crates/pds/ingress/src/cookie.rs", "\npub struct Held {\n    secret: CookieSecret,\n}\n")),
    # P9/P10/P11 (M6 plan S9): tls-core, pds/tls and key-core join.
    ("P9 derive(Debug) on a Secret wrapper in tls-core", {"P9"},
     lambda t: append(t / "crates/tls-core/src/lib.rs", "\n#[derive(Debug)]\nstruct Leak(Secret<32>);\n")),
    ("P9 derive(Clone) on a Secret wrapper in pds/tls", {"P9"},
     lambda t: append(t / "crates/pds/tls/src/main.rs", SECRET + "#[derive(Clone)]\nstruct Keys(Secret<32>);\n")),
    ("P9 derive(Copy) on a Secret wrapper in key-core", {"P9"},
     lambda t: append(t / "crates/key-core/src/lib.rs", "\n#[derive(Clone, Copy)]\nstruct Nonce(Secret<32>);\n")),
    ("P10 from_bytes(*..) in tls-core", {"P10"},
     lambda t: append(t / "crates/tls-core/src/record.rs", "\nfn f(k: &[u8; 32]) -> K { K::from_bytes(*k) }\n")),
    ("P10 from_bytes(*..) in pds/tls", {"P10"},
     lambda t: append(t / "crates/pds/tls/src/main.rs", "\nfn f(k: &[u8; 32]) -> K { K::from_bytes(*k) }\n")),
    ("P11 the Finished compared with == in tls-core's handshake", {"P11"},
     lambda t: edit(t / "crates/tls-core/src/handshake.rs", "ct::ct_eq(&expected_verify_data, finished)",
                    "expected_verify_data == finished")),
    ("P11 != on a verify_data in another tls-core file", {"P11"},
     lambda t: append(t / "crates/tls-core/src/record.rs",
                      "\nfn bad(a: &[u8; 32], verify_data: &[u8; 32]) -> bool {\n    *a != *verify_data\n}\n")),
    ("P11 tls-core's handshake removed", {"P11"},
     lambda t: (t / "crates/tls-core/src/handshake.rs").unlink()),
    ("allow ct_eq on a Finished in tls-core", set(),
     lambda t: append(t / "crates/tls-core/src/record.rs",
                      "\nfn ok(a: &[u8; 32], finished: &[u8]) -> bool {\n    ct::ct_eq(a, finished)\n}\n")),
    # P9/P10/P11 (M6 plan C12): tlskey-core and pds/tlskey join; the RFC
    # 6979 HMAC's anchor moved from key-core to tlskey-core.
    ("P9 derive(Debug) on a Secret wrapper in tlskey-core", {"P9"},
     lambda t: append(t / "crates/tlskey-core/src/lib.rs", "\n#[derive(Debug)]\nstruct Leak(Secret<32>);\n")),
    ("P9 derive(Clone) on a Secret wrapper in pds/tlskey", {"P9"},
     lambda t: append(t / "crates/pds/tlskey/src/main.rs", SECRET + "#[derive(Clone)]\nstruct Keys(Secret<32>);\n")),
    ("P10 from_bytes(*..) in tlskey-core", {"P10"},
     lambda t: append(t / "crates/tlskey-core/src/lib.rs", "\nfn f(k: &[u8; 32]) -> K { K::from_bytes(*k) }\n")),
    ("P10 from_bytes(*..) in pds/tlskey", {"P10"},
     lambda t: append(t / "crates/pds/tlskey/src/main.rs", "\nfn f(k: &[u8; 32]) -> K { K::from_bytes(*k) }\n")),
    ("P11 == on an HMAC tag in tlskey-core", {"P11"},
     lambda t: append(t / "crates/tlskey-core/src/lib.rs",
                      "\nfn bad(expected: &[u8; 32], hmac: &[u8; 32]) -> bool {\n    hmac == expected\n}\n")),
    ("P11 != on a tag in pds/tlskey", {"P11"},
     lambda t: append(t / "crates/pds/tlskey/src/main.rs",
                      "\nfn bad(expected: &[u8; 32], tag: &[u8; 32]) -> bool {\n    tag != expected\n}\n")),
    ("P11 tlskey-core's lib removed", {"P11"}, lambda t: (t / "crates/tlskey-core/src/lib.rs").unlink()),
    ("P11 == on a Finished in pds/tls", {"P11"},
     lambda t: append(t / "crates/pds/tls/src/main.rs",
                      "\nfn bad(expected: &[u8; 32], finished: &[u8; 32]) -> bool {\n    finished == expected\n}\n")),
    # P21 anchors in the same file and fails closed without it.
    ("P11 pds/tls's main removed", {"P11", "P21"}, lambda t: (t / "crates/pds/tls/src/main.rs").unlink()),
    # P9/P10 (M6 Phase 2 self-check): the shared `secret` crate joins.
    ("P9 derive(Clone) on Secret in crates/secret", {"P9"},
     lambda t: edit(t / "crates/secret/src/lib.rs", "pub struct Secret<const N: usize>([u8; N]);",
                    "#[derive(Clone)]\npub struct Secret<const N: usize>([u8; N]);")),
    ("P10 from_bytes(*..) in crates/secret", {"P10"},
     lambda t: append(t / "crates/secret/src/lib.rs", "\nfn f(k: &[u8; 32]) -> Secret<32> { Secret::from_bytes(*k) }\n")),
    # P18 (M6 plan L14, C7): HybridSecret is made only by exchange.
    ("P18 a second constructor in hybrid.rs", {"P18"},
     lambda t: append(t / "crates/tls-core/src/hybrid.rs",
                      "\nimpl HybridSecret {\n    pub fn forge() -> HybridSecret {\n        HybridSecret(Secret::zero())\n    }\n}\n")),
    ("P18 Self(..) in hybrid.rs", {"P18"},
     lambda t: append(t / "crates/tls-core/src/hybrid.rs",
                      "\nimpl HybridSecret {\n    pub fn forge() -> HybridSecret {\n        Self(Secret::zero())\n    }\n}\n")),
    ("P18 impl Default for HybridSecret", {"P18"},
     lambda t: append(t / "crates/tls-core/src/hybrid.rs",
                      "\nimpl Default for HybridSecret {\n    fn default() -> HybridSecret {\n        todo!()\n    }\n}\n")),
    ("P18 impl From for HybridSecret in another file", {"P18"},
     lambda t: append(t / "crates/tls-core/src/schedule.rs",
                      "\nimpl From<[u8; 64]> for crate::hybrid::HybridSecret {\n    fn from(_: [u8; 64]) -> Self {\n        todo!()\n    }\n}\n")),
    ("P18 a struct literal outside its module", {"P18"},
     lambda t: append(t / "crates/tls-core/src/schedule.rs",
                      "\nfn forge() -> HybridSecret {\n    crate::hybrid::HybridSecret(Secret::zero())\n}\n")),
    ("P18 a construction in pds/tls", {"P18"},
     lambda t: append(t / "crates/pds/tls/src/main.rs", "\nfn forge() -> HybridSecret {\n    HybridSecret { 0: z() }\n}\n")),
    # P9 too: HybridSecret wraps a Secret in a secret crate.
    ("P18 derive(Clone) on HybridSecret", {"P18", "P9"},
     lambda t: edit(t / "crates/tls-core/src/hybrid.rs", "pub struct HybridSecret(", "#[derive(Clone)]\npub struct HybridSecret(")),
    ("P18 exchange_with_randomness renamed", {"P18"},
     lambda t: edit(t / "crates/tls-core/src/hybrid.rs", "pub fn exchange_with_randomness(", "pub fn exchange_inner(")),
    ("allow HybridSecret in types and calls", set(),
     lambda t: append(t / "crates/tls-core/src/schedule.rs",
                      "\nfn f(s: HybridSecret) -> Result<(HybridSecret, [u8; 1]), ()> {\n"
                      "    let _ = HybridSecret::exchange;\n    Ok((s, [0]))\n}\n")),
    # P19 (L14, S6): classical group code points in tls-core.
    ("P19 x25519 as 0x001D", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 0x001D;\n")),
    ("P19 x25519 as 0x1d", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u8 = 0x1d;\n")),
    ("P19 x25519 as 29", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 29;\n")),
    ("P19 x25519 as the bytes [0x00, 0x1d]", {"P19"},
     lambda t: append(t / "crates/tls-core/src/hybrid.rs", "\nconst G: [u8; 2] = [0x00, 0x1d];\n")),
    ("P19 secp256r1 as 0x0017", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 0x0017;\n")),
    ("P19 secp384r1 as 0x0018", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 0x0018;\n")),
    ("P19 secp256r1 as 23u16", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 23u16;\n")),
    ("P19 ffdhe2048 as 0x0100", {"P19"}, lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 0x0100;\n")),
    ("P19 x448 as the bytes 0, 30 in a test file", {"P19"},
     lambda t: append(t / "crates/tls-core/src/tests.rs", "\nconst G: [u8; 2] = [0, 30];\n")),
    ("allow X25519MLKEM768, a content type and 290 in tls-core", set(),
     lambda t: append(t / "crates/tls-core/src/lib.rs", "\nconst G: u16 = 0x11ec;\nconst T: u8 = 0x17;\nconst L: usize = 290;\n")),
    ("allow a classical code point in a comment or outside tls-core", set(),
     lambda t: (append(t / "crates/tls-core/src/lib.rs", "\n// x25519 is 0x001d; refused by tls-wire\n"),
                append(t / "crates/tls-wire/src/lib.rs", "\nconst G: u16 = 0x001d;\n"))),
    # P20 (M6 code review S2): the caller-randomness exchange stays with
    # its shim, tls-core's tests and the ct-harness.
    ("P20 exchange_with_randomness called in pds/tls", {"P20"},
     lambda t: append(t / "crates/pds/tls/src/main.rs",
                      "\nfn ex(s: &[u8; 1216]) {\n    let _ = tls_core::exchange_with_randomness(s, &[0; 64]);\n}\n")),
    ("P20 exchange_with_randomness imported under an alias in tls-core", {"P20"},
     lambda t: append(t / "crates/tls-core/src/handshake.rs", "\nuse crate::hybrid::exchange_with_randomness as ex;\n")),
    ("P20 exchange_with_randomness called in tls-core's lib beside the re-export", {"P20"},
     lambda t: append(t / "crates/tls-core/src/lib.rs",
                      "\nfn ex(s: &[u8; 1216]) {\n    let _ = hybrid::exchange_with_randomness(s, &[0; 64]);\n}\n")),
    ("allow exchange_with_randomness in the ct-harness and in comments", set(),
     lambda t: (append(t / "tools/ct-harness/src/residue.rs",
                       "\nfn again(s: &[u8; 1216]) {\n    let _ = exchange_with_randomness(s, &[0; 64]);\n}\n"),
                append(t / "crates/pds/tls/src/main.rs", "\n// exchange_with_randomness is the harness's root.\n"))),
    ("allow exchange_with_randomness in tls-core's tests", set(),
     lambda t: append(t / "crates/tls-core/src/tests.rs",
                      "\nfn again(s: &[u8; 1216]) {\n    let _ = exchange_with_randomness(s, &[0; 64]);\n}\n")),
    # P20 (external review E2): hello_keys, pub for the ct-harness, stays
    # with handshake.rs and the harness; tls-core's tests may not name it.
    ("P20 hello_keys called in pds/tls", {"P20"},
     lambda t: append(t / "crates/pds/tls/src/main.rs",
                      "\nfn hk() {\n    let _ = tls_core::handshake::hello_keys::<Hedged<Hw>>;\n}\n")),
    ("P20 hello_keys imported in tls-core's tests", {"P20"},
     lambda t: append(t / "crates/tls-core/src/tests.rs", "\nuse crate::handshake::hello_keys as hk;\n")),
    # P20 (code review round 2, S-N3): no alias, the re-export included.
    ("P20 exchange_with_randomness re-exported under an alias in tls-core's lib", {"P20"},
     lambda t: edit(t / "crates/tls-core/src/lib.rs", "exchange_with_randomness, scrub_session_stack}",
                    "exchange_with_randomness as exchange_fixed, scrub_session_stack}")),
    ("P20 hello_keys imported under an alias in the ct-harness", {"P20"},
     lambda t: append(t / "tools/ct-harness/src/residue.rs", "\nuse tls_core::handshake::hello_keys as hk;\n")),
    ("allow hello_keys in the ct-harness and in comments", set(),
     lambda t: (append(t / "tools/ct-harness/src/residue.rs", "\nfn again() {\n    let _ = handshake::hello_keys::<Fixed>;\n}\n"),
                append(t / "crates/pds/tls/src/main.rs", "\n// hello_keys is the harness's hello-depth root.\n"))),
    # P21 (M6 plan C13): Pass::serve's return keeps the hello turn's pass.
    ("P21 && in place of || in the pass's return", {"P21"},
     lambda t: edit(t / "crates/pds/tls/src/main.rs", "PASS_PACKETS) || tls_core::conn::pass_due(",
                    "PASS_PACKETS) && tls_core::conn::pass_due(")),
    ("P21 pass_due dropped from the pass's return", {"P21"},
     lambda t: edit(t / "crates/pds/tls/src/main.rs", " || tls_core::conn::pass_due(consumed, waiting)", "")),
    ("P21 the Pass impl renamed away", {"P21"},
     lambda t: edit(t / "crates/pds/tls/src/main.rs", "impl ring::pass::Pass for Pass<'_> {",
                    "impl ring::pass::Pass for Passes<'_> {")),
    ("P21 a constant as pass_due's second argument", {"P21"},
     lambda t: edit(t / "crates/pds/tls/src/main.rs", "tls_core::conn::pass_due(consumed, waiting)",
                    "tls_core::conn::pass_due(consumed, true)")),
    ("allow the pass's return split over lines around a comment", set(),
     lambda t: edit(t / "crates/pds/tls/src/main.rs", "PASS_PACKETS) || tls_core::conn::pass_due(",
                    "PASS_PACKETS)\n            // the hello turn\n            || tls_core::conn::pass_due(")),
    # P22 (post-M6 plan P3): every key PD waits at the cap barrier.
    ("P22 the barrier call removed from unseal", {"P22"},
     lambda t: edit(t / "crates/tpm2/src/boot.rs", "=> cap_barrier(tpm, &mut rsp),", "=> Ok(()),")),
    ("P22 the barrier call left only in a comment", {"P22"},
     lambda t: edit(t / "crates/tpm2/src/boot.rs", "=> cap_barrier(tpm, &mut rsp),",
                    "=> Ok(()), // cap_barrier(tpm, &mut rsp)")),
    ("P22 the barrier no longer asks the cap status", {"P22"},
     lambda t: edit(t / "crates/tpm2/src/boot.rs", "ipc::label(ipc::REQ_CAP_STATUS, 0)", "ipc::label(ipc::REQ_DONE, 0)")),
    ("P22 a key PD unseals around tpm2::boot::unseal", {"P22"},
     lambda t: edit(t / "crates/pds/pqkey/src/main.rs", "tpm2::boot::unseal(", "tpm2::boot::unseal_unbarred(")),
    ("allow the barrier call split over lines", set(),
     lambda t: edit(t / "crates/tpm2/src/boot.rs", "=> cap_barrier(tpm, &mut rsp),",
                    "=> cap_barrier(\n            tpm,\n            &mut rsp,\n        ),")),
    # P23 (post-M6 plan P7): the old name stays only where it is listed.
    ("P23 the old name in an unlisted source file", {"P23"},
     lambda t: append(t / "crates/wire/src/lib.rs", "// the secureos wire parser\n")),
    ("P23 an old variable name in an unlisted file", {"P23"},
     lambda t: append(t / "crates/wire/src/lib.rs", "// read SECUREOS_DEBUG\n")),
    ("P23 a listed file that no longer names it", {"P23"},
     lambda t: append(t / "policy/old-name-allowlist", "crates/wire/src/lib.rs  # stale\n")),
    ("allow an archive document cited by its file name", set(),
     lambda t: append(t / "crates/wire/src/lib.rs", "// docs/archive/review/secureos-m5-measured-release-plan.md\n")),
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
