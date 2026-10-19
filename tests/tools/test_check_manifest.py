"""tools/check-manifest must accept exactly matching counts and reject each
kind of drift with its own message (code review R4-T1, T5-1, T5-3).

Usage: python3 tests/tools/test_check_manifest.py
Prints "CHECK-MANIFEST-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/check-manifest"
MANIFEST = "# comment\nA-TESTS 5\nB-TESTS 2\n"
MANIFEST_WITH_ZERO = MANIFEST + "Z-TESTS 0\n"

# (name, counts file text, expected message or None for accept)
CASES = [
    ("equal counts accepted", "A-TESTS 5\nB-TESTS 2\n", None),
    ("fewer than listed refused", "A-TESTS 4\nB-TESTS 2\n", "A-TESTS: 4 < manifest 5"),
    ("more than listed refused", "A-TESTS 6\nB-TESTS 2\n", "A-TESTS: 6 > manifest 5 (raise the manifest to 6)"),
    ("missing key refused", "A-TESTS 5\n", "B-TESTS: missing (gate did not run)"),
    ("zero refused", "A-TESTS 0\nB-TESTS 2\n", "A-TESTS: 0 < manifest 5"),
    # A manifest line of 0 does not make a count of 0 acceptable.
    ("zero refused even when listed as zero", "A-TESTS 5\nB-TESTS 2\nZ-TESTS 0\n", "Z-TESTS: 0 < manifest 0"),
    ("unlisted key refused", "A-TESTS 5\nB-TESTS 2\nC-TESTS 3\n", "C-TESTS: 3 not in the manifest (add it)"),
    ("key repeated within one counts file refused", "A-TESTS 5\nB-TESTS 2\nA-TESTS 7\n",
     "A-TESTS: reported by both gate and gate"),
    ("duplicate key across counts files refused", "A-TESTS 5\nB-TESTS 2\n", "A-TESTS: reported by both"),
    ("unlisted zero gets actionable advice", "A-TESTS 5\nB-TESTS 2\nC-TESTS 0\n",
     "C-TESTS: 0, the gate counted nothing"),
]


def main() -> int:
    failures = 0
    for name, counts, want in CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "manifest.txt").write_text(MANIFEST_WITH_ZERO if "Z-TESTS" in counts else MANIFEST)
            if name.startswith("duplicate"):
                (d / "counts").mkdir()
                (d / "counts" / "other").write_text("A-TESTS 4\n")
            (d / "counts").mkdir(exist_ok=True)
            (d / "counts" / "gate").write_text(counts)
            (d / "counts" / "gate.log").write_text("X-IGNORED 99\n")  # logs are not counts
            r = subprocess.run([sys.executable, str(TOOL), str(d / "manifest.txt"), str(d / "counts")],
                               capture_output=True, text=True)
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    print(f"CHECK-MANIFEST-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
