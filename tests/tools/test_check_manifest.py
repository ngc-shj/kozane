"""tools/check-manifest must accept exactly matching counts and reject each
kind of drift with its own message (code review R4-T1, T5-1, T5-3), and
require one IMAGE and one QEMU record per counts directory (M9 plan C6).

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
MANIFEST_WITH_DUP = MANIFEST + "A-TESTS 5\n"

IDENTITY = "IMAGE 1111\nQEMU aaaa\n"

# (name, counts file text, expected message or None for accept). Each case
# also gets IDENTITY in a file of its own, unless it sets `identity`.
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
     "A-TESTS: reported twice by gate"),
    ("duplicate key across counts files refused", "A-TESTS 5\nB-TESTS 2\n", "A-TESTS: reported by both"),
    ("manifest key listed twice refused", "A-TESTS 5\nB-TESTS 2\n", "A-TESTS: listed twice in the manifest"),
    ("unlisted zero gets actionable advice", "A-TESTS 5\nB-TESTS 2\nC-TESTS 0\n",
     "C-TESTS: 0, the gate counted nothing"),
]

# (name, identity file texts, expected message or None for accept); the
# counts themselves match the manifest.
IDENTITY_CASES = [
    ("the same identity written twice is one record", [IDENTITY, IDENTITY], None),
    ("a missing IMAGE refused", ["QEMU aaaa\n"], "check-manifest: IMAGE missing"),
    ("a missing QEMU refused", ["IMAGE 1111\n"], "check-manifest: QEMU missing"),
    ("two IMAGE values refused", [IDENTITY, "IMAGE 2222\n"], "check-manifest: IMAGE: two values"),
    ("two QEMU values in one file refused", [IDENTITY + "QEMU bbbb\n"], "check-manifest: QEMU: two values"),
]

# --compare-identity over two counts directories' identity files.
COMPARE_CASES = [
    ("equal identities compare equal", IDENTITY, IDENTITY, None),
    ("another image refused", IDENTITY, "IMAGE 2222\nQEMU aaaa\n", "ran on different images"),
    ("another QEMU refused", IDENTITY, "IMAGE 1111\nQEMU bbbb\n", "ran on different images"),
    ("a directory without records refused", IDENTITY, "", "IMAGE missing"),
]


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True)


def main() -> int:
    failures = 0
    for name, counts, want in CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            text = MANIFEST_WITH_ZERO if "Z-TESTS" in counts else MANIFEST_WITH_DUP if name.startswith("manifest") else MANIFEST
            (d / "manifest.txt").write_text(text)
            if name.startswith("duplicate"):
                (d / "counts").mkdir()
                (d / "counts" / "other").write_text("A-TESTS 4\n")
            (d / "counts").mkdir(exist_ok=True)
            (d / "counts" / "gate").write_text(counts)
            (d / "counts" / "gate.log").write_text("X-IGNORED 99\n")  # logs are not counts
            (d / "counts" / "identity").write_text(IDENTITY)
            r = run(d / "manifest.txt", d / "counts")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    for name, idents, want in IDENTITY_CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "manifest.txt").write_text(MANIFEST)
            (d / "counts").mkdir()
            (d / "counts" / "gate").write_text("A-TESTS 5\nB-TESTS 2\n")
            for i, text in enumerate(idents):
                (d / "counts" / f"identity-{i}").write_text(text)
            r = run(d / "manifest.txt", d / "counts")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    for name, a, b, want in COMPARE_CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            for sub, text in (("x", a), ("y", b)):
                (d / sub).mkdir()
                (d / sub / "identity").write_text(text)
            r = run("--compare-identity", d / "x", d / "y")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    print(f"CHECK-MANIFEST-FIXTURES {len(CASES) + len(IDENTITY_CASES) + len(COMPARE_CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
