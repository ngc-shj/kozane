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
FILES = ["docker/Dockerfile", "Makefile", "rust-toolchain.toml", "Cargo.toml"]


def rules_fired(tree: pathlib.Path) -> set:
    out = subprocess.run([sys.executable, str(TOOL), "--root", str(tree)], capture_output=True, text=True)
    fired = {line.split()[0] for line in out.stdout.splitlines() if line[:1] == "P"}
    if bool(fired) != (out.returncode == 1):
        raise SystemExit(f"exit status {out.returncode} disagrees with output {fired}")
    return fired


def copy_tree(dst: pathlib.Path):
    for f in FILES:
        (dst / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, dst / f)


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
    ("P5 ignore prefix", {"P5"},
     lambda t: edit(t / "Makefile", "\trm -rf $(BUILD)", "\t-rm -rf $(BUILD)")),
    ("P5 .IGNORE", {"P5"}, lambda t: edit(t / "Makefile", "clean:\n", ".IGNORE:\nclean:\n")),
]


def main() -> int:
    failures = 0
    for name, want, mutate in CASES:
        with tempfile.TemporaryDirectory() as d:
            tree = pathlib.Path(d)
            copy_tree(tree)
            mutate(tree)
            got = rules_fired(tree)
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: got {sorted(got)} want {sorted(want)}")
    print(f"CHECK-PINS-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
