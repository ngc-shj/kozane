"""tools/measure.py: the PCR 8 chain against known values, and the I8.2
range checks on both sides of each boundary (M5 plan C8).

Usage: python3 tests/tools/test_measure.py
Prints "MEASURE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402

IMG = 0x10000
GOOD = [(0x2000, 0x1000), (0x4000, 0x4000)]


def raises(f) -> str:
    try:
        f()
    except measure.DescriptorError as e:
        return str(e)
    return ""


def chain() -> bool:
    image = bytes(range(256)) * (IMG // 256)
    desc = measure.pack(IMG, GOOD)
    want = hashlib.sha256(hashlib.sha256(bytes(32) + hashlib.sha256(desc).digest()).digest()
                          + hashlib.sha256(image).digest()).digest()
    return measure.expected_pcr8(desc, image) == want


# (name, check returning True on the expected outcome)
CASES = [
    # The swtpm probe observed sha256(0^32 || 0^32) after extending a zero digest.
    ("extend matches the TPM's PCR_Extend", lambda: measure.extend(bytes(32), bytes(32)).hex()
     == "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    ("PCR 8 is descriptor then image", chain),
    ("a range ending exactly at image_len is allowed",
     lambda: not measure.check_ranges(IMG, [(0x2000, 0x1000), (IMG - 0x4000, 0x4000)])),
    ("a range past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, [(0x2000, 0x1000), (IMG - 0x3000, 0x4000)]))),
    ("an offset past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, [(IMG + 1, 0), (0x4000, 0x10)]))),
    ("a range that wraps 64 bits is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, [(2**64 - 0x10, 0x20), (0x4000, 0x10)]))),
    ("overlapping ranges are refused",
     lambda: "overlap" in "".join(measure.check_ranges(IMG, [(0x2000, 0x3000), (0x4000, 0x1000)]))),
    ("adjacent ranges are allowed", lambda: not measure.check_ranges(IMG, [(0x2000, 0x2000), (0x4000, 0x1000)])),
    ("ranges other than the prefill ranges are refused",
     lambda: "prefill" in "".join(measure.check_ranges(IMG, GOOD, expected=[(0x2000, 0x1000), (0x5000, 0x4000)]))),
    ("the prefill ranges themselves are allowed", lambda: not measure.check_ranges(IMG, GOOD, expected=GOOD)),
    ("a range longer than its load slot is refused",
     lambda: "load slot" in "".join(measure.check_ranges(0x400000, [(0, 0x100001), (0x200000, 0x10)]))),
    ("an empty image is refused", lambda: "image_len" in "".join(measure.check_ranges(0, [(0, 0), (0, 0)]))),
    ("a bad magic is refused", lambda: "header" in raises(
        lambda: measure.parse(b"X" + measure.pack(IMG, GOOD)[1:]))),
    ("a non-zero reserved word is refused", lambda: "header" in raises(
        lambda: measure.parse(measure.pack(IMG, GOOD)[:-1] + b"\x01"))),
    ("an envelope longer than its range is refused", lambda: "envelope" in raises(
        lambda: measure.assemble(bytes(IMG), measure.pack(IMG, GOOD), [bytes(0x1001), bytes(0x4000)]))),
    ("assembly writes each envelope at its range only", lambda: measure.assemble(
        bytes(IMG), measure.pack(IMG, GOOD), [b"\x01" * 0x1000, b"\x02" * 0x4000])
     == bytes(0x2000) + b"\x01" * 0x1000 + bytes(0x1000) + b"\x02" * 0x4000 + bytes(IMG - 0x8000)),
]


def main() -> int:
    failures = 0
    for name, check in CASES:
        ok = bool(check())
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"MEASURE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
