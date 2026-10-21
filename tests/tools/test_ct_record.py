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
    return tmp


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
    with tempfile.TemporaryDirectory() as d:
        root = tree(pathlib.Path(d))
        written(root, RECORD.replace("RESIDUE-CASES 25\n", ""))
        why = ct_record.check_record(root, root / "harness", VG)
        n += 1
        if not any("no RESIDUE-CASES line" for w in why):
            failures += 1
            print(f"FAIL record without RESIDUE-CASES refused: {why}")
    print(f"CT-RECORD-FIXTURES {n}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
