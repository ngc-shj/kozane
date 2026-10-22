"""tools/unit-counts on canned `cargo test` output: per-stem keys, and the
refusals for a stem shared by two crates and an unreadable owner.

Usage: python3 tests/tools/test_unit_counts.py
Prints "UNIT-COUNTS-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("unit_counts", str(ROOT / "tools/unit-counts"))
spec = importlib.util.spec_from_loader("unit_counts", loader)
uc = importlib.util.module_from_spec(spec)
loader.exec_module(uc)


def run(binary: str, passed: int) -> list:
    return [f"     Running {binary.split('|')[0]} ({binary.split('|')[1]})", f"test result: ok. {passed} passed; 0 failed"]


LIB_A = run("unittests src/lib.rs|target/debug/build/a/1a/out/a-1a2b", 2)
BIN_A = run("unittests src/main.rs|target/debug/build/a/2b/out/a-3c4d", 1)
VEC_A = run("tests/vectors.rs|target/debug/build/a/3c/out/vectors-5e6f", 3)
VEC_B = run("tests/vectors.rs|target/debug/build/b/4d/out/vectors-7a8b", 4)
DOC_A = ["   Doc-tests a", "test result: ok. 0 passed; 0 failed"]
OLD_LAYOUT = run("tests/vectors.rs|target/debug/deps/vectors-9c0d", 5)

# (name, log lines, expected output)
CASES = [
    ("a crate's lib and bin share its key", LIB_A + BIN_A + DOC_A, ["UNIT-TESTS 3", "UNIT-A 3"]),
    ("one crate's test stem has its own key", LIB_A + VEC_A, ["UNIT-TESTS 5", "UNIT-A 2", "UNIT-VECTORS 3"]),
    ("two crates' tests/vectors.rs collide", VEC_A + VEC_B,
     ["UNIT-TESTS 7", "UNIT-VECTORS 7", "UNIT-KEY-COLLISION-VECTORS 1"]),
    ("a path without the owning crate is refused", OLD_LAYOUT,
     ["UNIT-TESTS 5", "UNIT-VECTORS 5", "UNIT-KEY-OWNER-UNKNOWN-VECTORS 1"]),
]


def main() -> int:
    failures = 0
    for name, lines, want in CASES:
        got = uc.counts(lines)
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got}")
    print(f"UNIT-COUNTS-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
