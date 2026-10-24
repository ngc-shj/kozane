"""tools/measure.py: the PCR 8 chain against known values, and the I8.2
range checks on both sides of each boundary (M5 plan C8).

Usage: python3 tests/tools/test_measure.py
Prints "MEASURE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402

IMG = 0x10000
GOOD = [(0x2000, 0x1000), (0x4000, 0x4000), (0x9000, 0x1000)]
IMAGE = bytes(range(256)) * (IMG // 256)


def raises(f) -> str:
    try:
        f()
    except measure.DescriptorError as e:
        return str(e)
    return ""


def chain() -> bool:
    desc = measure.pack(IMG, GOOD)
    want = hashlib.sha256(hashlib.sha256(bytes(32) + hashlib.sha256(desc).digest()).digest()
                          + hashlib.sha256(IMAGE).digest()).digest()
    return measure.expected_pcr8(desc, IMAGE) == want


def with_range(i: int, rng: tuple) -> list:
    return GOOD[:i] + [rng] + GOOD[i + 1:]


def overlaps(i: int, j: int, rng: tuple) -> bool:
    """Range `j` moved to `rng` is refused as overlapping range `i`, and only so."""
    errors = measure.check_ranges(IMG, with_range(j, rng))
    return len(errors) == 1 and f"ranges {i} and {j} overlap" in errors[0]


def raw(version: int, count: int, fields: list) -> bytes:
    """A descriptor as written, past pack()'s checks."""
    return struct.pack(f"<8sII{len(fields)}Q", measure.MAGIC, version, count, *fields)


def pcr_moves(i: int, rng: tuple) -> bool:
    """A valid move of range `i` changes PCR 8: the descriptor is measured.
    The measure variant prints what expected_pcr8 computes (C8)."""
    return measure.expected_pcr8(measure.pack(IMG, with_range(i, rng)), IMAGE) \
        != measure.expected_pcr8(measure.pack(IMG, GOOD), IMAGE)


# (name, check returning True on the expected outcome)
CASES = [
    # The swtpm probe observed sha256(0^32 || 0^32) after extending a zero digest.
    ("extend matches the TPM's PCR_Extend", lambda: measure.extend(bytes(32), bytes(32)).hex()
     == "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    ("PCR 8 is descriptor then image", chain),
    ("a range ending exactly at image_len is allowed",
     lambda: not measure.check_ranges(IMG, with_range(2, (IMG - 0x4000, 0x4000)))),
    ("a range past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(1, (IMG - 0x3000, 0x4000))))),
    ("an offset past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(0, (IMG + 1, 0))))),
    ("a range that wraps 64 bits is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(0, (2**64 - 0x10, 0x20))))),
    ("range 2 past image_len is refused",
     lambda: "range 2 (0xe000, 0x4000) is outside the image" in "".join(
         measure.check_ranges(IMG, with_range(2, (IMG - 0x2000, 0x4000))))),
    ("range 2 wrapping 64 bits is refused",
     lambda: "range 2" in "".join(measure.check_ranges(IMG, with_range(2, (2**64 - 0x10, 0x20))))),
    # Each pair on its own: the third range stays clear of both.
    ("ranges 0 and 1 overlapping are refused", lambda: overlaps(0, 1, (0x2fff, 0x1000))),
    ("ranges 0 and 1 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(1, (0x3000, 0x1000)))),
    ("ranges 0 and 2 overlapping are refused", lambda: overlaps(0, 2, (0x1001, 0x1000))),
    ("ranges 0 and 2 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(2, (0x1000, 0x1000)))),
    ("ranges 1 and 2 overlapping are refused", lambda: overlaps(1, 2, (0x7fff, 0x1000))),
    ("ranges 1 and 2 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(2, (0x8000, 0x1000)))),
    ("ranges other than the prefill ranges are refused",
     lambda: "prefill" in "".join(measure.check_ranges(IMG, GOOD, expected=with_range(2, (0xa000, 0x1000))))),
    ("the prefill ranges themselves are allowed", lambda: not measure.check_ranges(IMG, GOOD, expected=GOOD)),
    ("a range longer than its load slot is refused",
     lambda: "load slot" in "".join(measure.check_ranges(0x400000, [(0, 0x100001), (0x200000, 0x10), (0x300000, 0x10)]))),
    ("two ranges are refused", lambda: "2 ranges, expected 3" in "".join(measure.check_ranges(IMG, GOOD[:2]))),
    ("an empty image is refused", lambda: "image_len" in "".join(measure.check_ranges(0, [(0, 0)] * 3))),
    ("a v2 descriptor with three ranges is allowed",
     lambda: measure.parse(raw(2, 3, [IMG, *[v for r in GOOD for v in r], 0])) == (IMG, GOOD)),
    # Version 1 (M5's two-envelope form) is refused, at its own length too.
    ("an 80-byte version-1 descriptor is refused", lambda: "header" in raises(
        lambda: measure.parse(raw(1, 3, [IMG, *[v for r in GOOD for v in r], 0])))),
    ("a v2 descriptor with count 2 is refused", lambda: "header" in raises(
        lambda: measure.parse(raw(2, 2, [IMG, *[v for r in GOOD for v in r], 0])))),
    ("a 64-byte descriptor is refused", lambda: "64 bytes, expected 80" in raises(
        lambda: measure.parse(raw(1, 2, [IMG, *[v for r in GOOD[:2] for v in r], 0])))),
    ("a bad magic is refused", lambda: "header" in raises(
        lambda: measure.parse(b"X" + measure.pack(IMG, GOOD)[1:]))),
    ("a non-zero reserved word is refused", lambda: "header" in raises(
        lambda: measure.parse(measure.pack(IMG, GOOD)[:-1] + b"\x01"))),
    ("an envelope longer than its range is refused", lambda: "envelope" in raises(
        lambda: measure.assemble(bytes(IMG), measure.pack(IMG, GOOD), [bytes(0x1001), bytes(0x4000), bytes(0x1000)]))),
    ("ranges over the zero placeholder are allowed",
     lambda: not measure.check_placeholder(bytes(IMG), measure.pack(IMG, GOOD))),
    ("a range over non-zero image bytes (loader code) is refused", lambda: "zero placeholder" in "".join(
        measure.check_placeholder(bytes(0x2fff) + b"\x01" + bytes(IMG - 0x3000), measure.pack(IMG, GOOD)))),
    ("range 2 over non-zero image bytes is refused",
     lambda: ["measure: range 2 (0x9000, 0x1000) is not the zero placeholder in the published image"]
     == measure.check_placeholder(bytes(0x9fff) + b"\x01" + bytes(IMG - 0xa000), measure.pack(IMG, GOOD))),
    ("assembly writes each envelope at its range only", lambda: measure.assemble(
        bytes(IMG), measure.pack(IMG, GOOD), [b"\x01" * 0x1000, b"\x02" * 0x4000, b"\x03" * 0x1000])
     == bytes(0x2000) + b"\x01" * 0x1000 + bytes(0x1000) + b"\x02" * 0x4000 + bytes(0x1000) + b"\x03" * 0x1000
     + bytes(IMG - 0xa000)),
    ("moving range 2's offset changes PCR 8", lambda: pcr_moves(2, (0xa000, 0x1000))),
    ("changing range 2's length changes PCR 8", lambda: pcr_moves(2, (0x9000, 0x800))),
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
