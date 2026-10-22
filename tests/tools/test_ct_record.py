"""tools/ct_record.py: a C9 pass record is found only for the exact harness,
policy, vectors and valgrind it was written for (M4 plan C9, R4: T-Q1).

Usage: python3 tests/tools/test_ct_record.py
Prints "CT-RECORD-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))
import ct_record  # noqa: E402

VG = "valgrind-3.24.0"
RECORD = "CT-CASES 28\nCT-MARKED-BYTES 1\nCT-DECLASSIFY 3\nRESIDUE-CASES 25\n"


def tree(tmp: pathlib.Path) -> pathlib.Path:
    (tmp / "policy").mkdir()
    (tmp / ct_record.POLICY).write_text('[[site]]\nid = "ss-out"\n')
    (tmp / ct_record.VECTORS).mkdir(parents=True)
    (tmp / ct_record.VECTORS / "liboqs.txt").write_text("mce.0.ss 00\n")
    (tmp / "harness").write_bytes(b"\x7fELF harness")
    (tmp / "tests").mkdir()
    (tmp / ct_record.MANIFEST).write_text("CT-CASES 28\nCT-MARKED-BYTES 1\nRESIDUE-CASES 25\n")
    return tmp


def edit_manifest(root):
    (root / ct_record.MANIFEST).write_text("CT-CASES 29\nCT-MARKED-BYTES 1\nRESIDUE-CASES 25\n")


def written(root: pathlib.Path, text: str = RECORD) -> pathlib.Path:
    path = ct_record.record_path(root, ct_record.record_key(root, root / "harness", VG))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def edit_policy(root):
    (root / ct_record.POLICY).write_text('[[site]]\nid = "e-bytes"\n')


def edit_vectors(root):
    (root / ct_record.VECTORS / "liboqs.txt").write_text("mce.0.ss 01\n")


def edit_harness(root):
    (root / "harness").write_bytes(b"\x7fELF harness, rebuilt")


# (name, change after the record is written, valgrind version checked,
#  expected message fragment or None for accept)
CASES = [
    ("record for the same inputs accepted", None, VG, None),
    ("record written under an old policy refused after a policy edit", edit_policy, VG, "no C9 pass record"),
    ("vector edit refused", edit_vectors, VG, "no C9 pass record"),
    ("rebuilt harness refused", edit_harness, VG, "no C9 pass record"),
    ("other valgrind refused", None, "valgrind-3.25.0", "no C9 pass record"),
    ("record with fewer cases than the manifest pins refused", edit_manifest, VG,
     "CT-CASES 28, tests/manifest.txt pins 29"),
    ("missing manifest refused", lambda root: (root / ct_record.MANIFEST).unlink(), VG,
     "tests/manifest.txt: unreadable"),
]


def main() -> int:
    failures = 0
    n = 0
    for name, change, vg, want in CASES:
        with tempfile.TemporaryDirectory() as d:
            root = tree(pathlib.Path(d))
            written(root)
            if change:
                change(root)
            why = ct_record.check_record(root, root / "harness", vg)
            ok = (not why) if want is None else any(want in w for w in why)
            n += 1
            if not ok:
                failures += 1
                print(f"FAIL {name}: {why}")
    # Each required line, dropped on its own, is refused by name. Listed
    # here, not read from ct_record.REQUIRED: a key dropped there must fail.
    for key in ("CT-CASES", "CT-MARKED-BYTES", "RESIDUE-CASES"):
        line = next(l for l in RECORD.splitlines(keepends=True) if l.startswith(key + " "))
        with tempfile.TemporaryDirectory() as d:
            root = tree(pathlib.Path(d))
            written(root, RECORD.replace(line, ""))
            why = ct_record.check_record(root, root / "harness", VG)
            n += 1
            if not any(f"no {key} line" in w for w in why):
                failures += 1
                print(f"FAIL record without {key} refused: {why}")
    print(f"CT-RECORD-FIXTURES {n}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
