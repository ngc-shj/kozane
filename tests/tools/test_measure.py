"""tools/measure.py: the PCR 8 chain against known values, and the I8.2
range checks on both sides of each boundary (M5 plan C8); the PCR 0 chain
over the FIP's closed list and its refusals (M7 plan C3, C4); descriptor v3's
six ranges and per-kind rooms, PCR 9 over the two bundle slots, and the NV
index twins (M8 plan C3, C4).

Usage: python3 tests/tools/test_measure.py
Prints "MEASURE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402
import fip_fixture  # noqa: E402

SLOT = measure.BUNDLE_MAX
# Four envelopes in the first 0x10000 bytes, then the two slots.
IMG = 0x10000 + 2 * SLOT
GOOD = [(0x2000, 0x1000), (0x4000, 0x4000), (0x9000, 0x1000), (0xb000, 0x1000), (0x10000, SLOT),
        (0x10000 + SLOT, SLOT)]
IMAGE = bytes(range(256)) * (IMG // 256)
BOOT_CMD = (ROOT / "support/u-boot/boot.cmd").read_text()
SLOT_A = bytes(range(256)) * (SLOT // 256)
SLOT_B = bytes(reversed(range(256))) * (SLOT // 256)


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


def wide_envelope(length: int, i: int = 1) -> tuple:
    """(image_len, ranges) with envelope `i` `length` long and room for it."""
    envelopes = [(0x10 * n, 0x10) for n in range(measure.ENVELOPES)]
    envelopes[i] = (0xf0000, length)
    return 0x200000 + 2 * SLOT, envelopes + [(0x200000, SLOT), (0x200000 + SLOT, SLOT)]


def pair_overlap(i: int, j: int) -> bool:
    """Pair (i, j), i < j, with j the audit envelope or a slot: range i
    moved to overlap range j alone (an envelope onto range j's start; slot A
    one byte into slot B) is refused as that pair's overlap, and only so."""
    oi, li = GOOD[i]
    oj, _ = GOOD[j]
    moved = (oj - 1, li) if i >= measure.ENVELOPES else (oj, li)
    errors = measure.check_ranges(IMG, with_range(i, moved))
    return errors == [f"measure: ranges {i} and {j} overlap ({moved[0]:#x}+{li:#x}, {oj:#x}+{GOOD[j][1]:#x})"]


def boot_cmd_lines() -> list:
    """What boot.cmd must hold for measure's model: one disjointness line a
    pair, each range's room, and slot A then slot B hashed over BUNDLE_MAX
    at its load address and extended into PCR 9 (U-Boot's half of C4)."""
    missing = []
    for i, j in measure.PAIRS:
        line = f"if test 0x$e{i} -gt 0x$o{j} && test 0x$e{j} -gt 0x$o{i}; then REFUSE; fi\n"
        if BOOT_CMD.count(line) != 1:
            missing.append(line)
    for i, room in enumerate(measure.ROOMS):
        # Envelopes fit their room; a slot is exactly BUNDLE_MAX.
        op = "-gt" if i < measure.ENVELOPES else "-ne"
        line = f"if test 0x$l{i} {op} {room:#x}; then REFUSE; fi\n"
        if BOOT_CMD.count(line) != 1:
            missing.append(line)
    slots = re.findall(r"^hash sha256 (0x[0-9a-f]+) (0x[0-9a-f]+) \*(0x[0-9a-f]+) \|\| REFUSE\n"
                       r"tpm2 pcr_extend 9 (0x[0-9a-f]+) \|\| REFUSE$", BOOT_CMD, re.M)
    if [(int(a, 16), int(n, 16)) for a, n, at, ext in slots if at == ext] \
            != [(load, measure.BUNDLE_MAX) for load in measure.LOAD_SLOTS]:
        missing.append(f"slot A then slot B into PCR 9: {slots}")
    if len(measure.PAIRS) != measure.COUNT * (measure.COUNT - 1) // 2:
        missing.append(f"{len(measure.PAIRS)} pairs")
    return missing


def boot_cmd_layout() -> list:
    """boot.cmd reads the descriptor measure packs: its length hashed, its
    count, its reserved word's offset, every field 32-bit checked, and each
    range copied from its load address (measure.LOADS)."""
    fields = " ".join(f"$o{i} $l{i}" for i in range(measure.COUNT))
    lines = [f"hash sha256 {measure.LOAD_DESC:#x} {measure.DESC_LEN:#x} *0x6fb00000 || REFUSE\n",
             f"setexpr.l cnt *0x6ff0000c; if test 0x$cnt -ne {measure.COUNT}; then REFUSE; fi\n",
             f"setexpr.q rsv *{measure.LOAD_DESC + measure.DESC_LEN - 8:#x}; if test 0x$rsv -ne 0; then REFUSE; fi\n",
             f"for v in {fields}; do setexpr hi 0x$v / 0x100000000; if test 0x$hi -ne 0; then REFUSE; fi; done\n"]
    lines += [f"setexpr d{i} 0x70000000 + 0x$o{i}\ncp.b {load:#x} $d{i} $l{i} || REFUSE\n"
              for i, load in enumerate(measure.LOADS)]
    return [line for line in lines if BOOT_CMD.count(line) != 1]


def load_slots_apart() -> bool:
    """Every load slot at its room, the descriptor, the digest scratch and
    the image: no two overlap."""
    spans = list(zip(measure.LOADS, measure.ROOMS)) + [
        (measure.LOAD_DESC, measure.DESC_LEN), (0x6FB00000, 0x100), (measure.LOAD_IMAGE, measure.MAX_IMAGE)]
    return all(a + n <= b or b + m <= a for k, (a, n) in enumerate(spans) for b, m in spans[k + 1:])


def pcr0_chain() -> bool:
    pcr = bytes(32)
    for _, data in fip_fixture.payloads():
        pcr = hashlib.sha256(pcr + hashlib.sha256(data).digest()).digest()
    return measure.expected_pcr0(fip_fixture.flash()) == pcr


# (name, check returning True on the expected outcome)
CASES = [
    # The swtpm probe observed sha256(0^32 || 0^32) after extending a zero digest.
    ("extend matches the TPM's PCR_Extend", lambda: measure.extend(bytes(32), bytes(32)).hex()
     == "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    ("PCR 8 is descriptor then image", chain),
    ("a range ending exactly at image_len is allowed",
     lambda: not measure.check_ranges(IMG, with_range(5, (IMG - SLOT, SLOT)))),
    ("a range past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(1, (IMG - 0x3000, 0x4000))))),
    ("an offset past image_len is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(0, (IMG + 1, 0))))),
    ("a range that wraps 64 bits is refused",
     lambda: "outside the image" in "".join(measure.check_ranges(IMG, with_range(0, (2**64 - 0x10, 0x20))))),
    ("range 2 past image_len is refused",
     lambda: f"range 2 ({IMG - 0x800:#x}, 0x1000) is outside the image" in "".join(
         measure.check_ranges(IMG, with_range(2, (IMG - 0x800, 0x1000))))),
    ("range 2 wrapping 64 bits is refused",
     lambda: "range 2" in "".join(measure.check_ranges(IMG, with_range(2, (2**64 - 0x10, 0x20))))),
    # Each pair on its own: the other ranges stay clear of both.
    ("ranges 0 and 1 overlapping are refused", lambda: overlaps(0, 1, (0x2fff, 0x1000))),
    ("ranges 0 and 1 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(1, (0x3000, 0x1000)))),
    ("ranges 0 and 2 overlapping are refused", lambda: overlaps(0, 2, (0x1001, 0x1000))),
    ("ranges 0 and 2 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(2, (0x1000, 0x1000)))),
    ("ranges 1 and 2 overlapping are refused", lambda: overlaps(1, 2, (0x7fff, 0x1000))),
    ("ranges 1 and 2 adjacent are allowed", lambda: not measure.check_ranges(IMG, with_range(2, (0x8000, 0x1000)))),
    # The twelve pairs since v2: each with the audit envelope (3) or a slot.
    *((f"ranges {i} and {j} overlapping are refused", lambda i=i, j=j: pair_overlap(i, j))
      for i, j in measure.PAIRS if j >= 3),
    ("an envelope ending exactly where slot A starts is allowed",
     lambda: not measure.check_ranges(IMG, with_range(1, (0x10000 - 0x4000, 0x4000)))),
    ("the audit envelope adjacent to range 2 is allowed",
     lambda: not measure.check_ranges(IMG, with_range(3, (0xa000, 0x1000)))),
    ("slot B starting exactly where slot A ends is allowed",
     lambda: GOOD[4][0] + GOOD[4][1] == GOOD[5][0] and not measure.check_ranges(IMG, GOOD)),
    ("boot.cmd holds each pair's line, each room and the PCR 9 slot measurements",
     lambda: not boot_cmd_lines()),
    ("boot.cmd hashes, counts, checks and copies all six ranges", lambda: not boot_cmd_layout()),
    ("the slot load addresses stay below boot.cmd's digest scratch (P3)",
     lambda: all(load + measure.BUNDLE_MAX <= 0x6FB00000 for load in measure.LOAD_SLOTS)
     and measure.LOAD_SLOTS[0] + measure.BUNDLE_MAX <= measure.LOAD_SLOTS[1]),
    ("no two load slots overlap each other, the descriptor, the scratch or the image", load_slots_apart),
    ("ranges other than the prefill ranges are refused",
     lambda: "prefill" in "".join(measure.check_ranges(IMG, GOOD, expected=with_range(2, (0xa000, 0x1000))))),
    ("the prefill ranges themselves are allowed", lambda: not measure.check_ranges(IMG, GOOD, expected=GOOD)),
    ("an envelope range longer than ENVELOPE_ROOM is refused",
     lambda: ["measure: range 1 length 0x100001 exceeds its load slot (0x100000)"]
     == measure.check_ranges(*wide_envelope(0x100001))),
    ("an envelope range of exactly ENVELOPE_ROOM is allowed",
     lambda: not measure.check_ranges(*wide_envelope(0x100000))),
    ("the audit envelope range longer than ENVELOPE_ROOM is refused",
     lambda: ["measure: range 3 length 0x100001 exceeds its load slot (0x100000)"]
     == measure.check_ranges(*wide_envelope(0x100001, 3))),
    ("a slot range longer than BUNDLE_MAX is refused",
     lambda: [f"measure: range 4 length {SLOT + 1:#x} exceeds its load slot ({SLOT:#x})",
              f"measure: slot range 4 length {SLOT + 1:#x} is not BUNDLE_MAX ({SLOT:#x})"]
     == measure.check_ranges(IMG + 1, GOOD[:4] + [(0x10000, SLOT + 1), (0x10001 + SLOT, SLOT)])),
    ("a slot range shorter than BUNDLE_MAX is refused",
     lambda: [f"measure: slot range 4 length {SLOT - 1:#x} is not BUNDLE_MAX ({SLOT:#x})"]
     == measure.check_ranges(IMG, GOOD[:4] + [(GOOD[4][0], SLOT - 1), GOOD[5]])),
    ("five ranges are refused", lambda: "5 ranges, expected 6" in "".join(measure.check_ranges(IMG, GOOD[:5]))),
    ("an empty image is refused", lambda: "image_len" in "".join(measure.check_ranges(0, [(0, 0)] * 6))),
    ("a v3 descriptor with six ranges is allowed",
     lambda: measure.parse(raw(3, 6, [IMG, *[v for r in GOOD for v in r], 0])) == (IMG, GOOD)),
    # Version 2 (M6's three-envelope form) is refused, at v3's length too.
    ("a 128-byte version-2 descriptor is refused", lambda: "header" in raises(
        lambda: measure.parse(raw(2, 6, [IMG, *[v for r in GOOD for v in r], 0])))),
    ("a v3 descriptor with count 5 is refused", lambda: "header" in raises(
        lambda: measure.parse(raw(3, 5, [IMG, *[v for r in GOOD for v in r], 0])))),
    # Slice 2's five-range v3, without the audit envelope (deviation D-5).
    ("a 112-byte (five-range) v3 descriptor is refused", lambda: "112 bytes, expected 128" in raises(
        lambda: measure.parse(raw(3, 5, [IMG, *[v for r in GOOD[:3] + GOOD[4:] for v in r], 0])))),
    ("an 80-byte (v2) descriptor is refused", lambda: "80 bytes, expected 128" in raises(
        lambda: measure.parse(raw(2, 3, [IMG, *[v for r in GOOD[:3] for v in r], 0])))),
    ("a bad magic is refused", lambda: "header" in raises(
        lambda: measure.parse(b"X" + measure.pack(IMG, GOOD)[1:]))),
    ("a non-zero reserved word is refused", lambda: "header" in raises(
        lambda: measure.parse(measure.pack(IMG, GOOD)[:-1] + b"\x01"))),
    ("an envelope longer than its range is refused", lambda: "envelope" in raises(
        lambda: measure.assemble(bytes(IMG), measure.pack(IMG, GOOD),
                                 [bytes(0x1001), bytes(0x4000), bytes(0x1000), bytes(0x1000), bytes(SLOT),
                                  bytes(SLOT)]))),
    ("ranges over the zero placeholder are allowed",
     lambda: not measure.check_placeholder(bytes(IMG), measure.pack(IMG, GOOD))),
    ("a range over non-zero image bytes (loader code) is refused", lambda: "zero placeholder" in "".join(
        measure.check_placeholder(bytes(0x2fff) + b"\x01" + bytes(IMG - 0x3000), measure.pack(IMG, GOOD)))),
    ("range 2 over non-zero image bytes is refused",
     lambda: ["measure: range 2 (0x9000, 0x1000) is not the zero placeholder in the published image"]
     == measure.check_placeholder(bytes(0x9fff) + b"\x01" + bytes(IMG - 0xa000), measure.pack(IMG, GOOD))),
    ("the audit range over non-zero image bytes is refused",
     lambda: ["measure: range 3 (0xb000, 0x1000) is not the zero placeholder in the published image"]
     == measure.check_placeholder(bytes(0xbfff) + b"\x01" + bytes(IMG - 0xc000), measure.pack(IMG, GOOD))),
    ("assembly writes each envelope and slot at its range only", lambda: measure.assemble(
        bytes(IMG), measure.pack(IMG, GOOD),
        [b"\x01" * 0x1000, b"\x02" * 0x4000, b"\x03" * 0x1000, b"\x04" * 0x1000, SLOT_A, SLOT_B])
     == bytes(0x2000) + b"\x01" * 0x1000 + bytes(0x1000) + b"\x02" * 0x4000 + bytes(0x1000) + b"\x03" * 0x1000
     + bytes(0x1000) + b"\x04" * 0x1000 + bytes(0x10000 - 0xc000) + SLOT_A + SLOT_B),
    ("moving range 2's offset changes PCR 8", lambda: pcr_moves(2, (0xa000, 0x1000))),
    ("changing range 2's length changes PCR 8", lambda: pcr_moves(2, (0x9000, 0x800))),
    # M8 plan C4, D3: PCR 9 is slot A then slot B, each over BUNDLE_MAX.
    ("PCR 9 is slot A then slot B", lambda: measure.expected_pcr9(SLOT_A, SLOT_B) == hashlib.sha256(
        hashlib.sha256(bytes(32) + hashlib.sha256(SLOT_A).digest()).digest()
        + hashlib.sha256(SLOT_B).digest()).digest()),
    ("the slots' order moves PCR 9", lambda: measure.expected_pcr9(SLOT_A, SLOT_B)
     != measure.expected_pcr9(SLOT_B, SLOT_A)),
    ("a slot shorter than BUNDLE_MAX is refused", lambda: f"slot B is {SLOT - 1} bytes" in raises(
        lambda: measure.expected_pcr9(SLOT_A, SLOT_B[:-1]))),
    # The seal policy stays PCRs 0-8 (owner scope, M8 plan C4): PCR 9 is
    # measured, never sealed to. Fails if PCR 9 enters the selection.
    ("PCR 9 is outside the seal selection", lambda: measure.POLICY_PCRS == 9
     and measure.SLOT_PCR not in range(measure.POLICY_PCRS)
     and len(measure.expected_pcrs(fip_fixture.flash(), measure.pack(IMG, GOOD), IMAGE)) == measure.POLICY_PCRS),
    ("BUNDLE_MAX is crates/limits' value", lambda: measure.BUNDLE_MAX == int(re.search(
        r"^pub const BUNDLE_MAX: usize = (0x[0-9a-f_]+);$", (ROOT / "crates/limits/src/lib.rs").read_text(),
        re.M).group(1).replace("_", ""), 16)),
    # M8 plan C3: the NV Names swtpm 0.7.1 reported for the C3 attributes
    # with an authPolicy of 32 bytes 0x11 (unwritten counter; counter after
    # one increment; base written and write-locked).
    ("the counter's Name, unwritten, is swtpm's", lambda: measure.nv_name(
        measure.NV_POLICY_CTR, measure.NV_CTR_ATTRS, b"\x11" * 32).hex()
     == "000bb87e79fa5ceef51728daffc8f3e9fca00dd7b8e581da3874e0f5e5823f0b85bb"),
    ("the provisioned Names (WRITTEN; WRITTEN and WRITELOCKED) are swtpm's",
     lambda: [n.hex() for n in measure.expected_nv_names(b"\x11" * 32)]
     == ["000b54b17a038bcf600bb8c0c8216c58ee792962b34bb7e98f83aacb51fb1da72dc6",
         "000b0c574c02a145a914593a66ecfb685721df6a20373dad9974683efc84e5addd1f"]),
    ("the delete policy binds both key Names, in order, and the policyRef", lambda: len({
        measure.delete_policy([b"a", b"b"]), measure.delete_policy([b"b", b"a"]), measure.delete_policy([b"a"]),
        measure.delete_policy([b"a", b"b"], b"other-ref")}) == 4),
    # M7 plan C3, C4: PCR 0 is BL2, then BL31, then BL33, each the entry's bytes.
    ("PCR 0 is BL2 then BL31 then BL33", pcr0_chain),
    ("PCRs 0-8: PCR 0, seven zeros, PCR 8", lambda: measure.expected_pcrs(
        fip_fixture.flash(), measure.pack(IMG, GOOD), IMAGE)
     == [measure.expected_pcr0(fip_fixture.flash())] + [bytes(32)] * 7
     + [measure.expected_pcr8(measure.pack(IMG, GOOD), IMAGE)]),
    ("entries out of the ToC's order are measured in TF-A's order", lambda: measure.expected_pcr0(
        fip_fixture.flash(fip_fixture.payloads()[::-1])) == measure.expected_pcr0(fip_fixture.flash())),
    ("a changed BL31 byte changes PCR 0", lambda: measure.expected_pcr0(fip_fixture.flash(
        [(u, d + b"!" if n == 1 else d) for n, (u, d) in enumerate(fip_fixture.payloads())]))
     != measure.expected_pcr0(fip_fixture.flash())),
    ("a FIP entry outside the measured list is refused", lambda: "is not on the measured list" in raises(
        lambda: measure.expected_pcr0(fip_fixture.flash(fip_fixture.payloads() + [(b"\x01" * 16, b"x")])))),
    ("a FIP entry twice is refused", lambda: "appears twice" in raises(
        lambda: measure.expected_pcr0(fip_fixture.flash(fip_fixture.payloads() + fip_fixture.payloads()[:1])))),
    ("a FIP without BL31 is refused", lambda: "has no BL31" in raises(
        lambda: measure.expected_pcr0(fip_fixture.flash([fip_fixture.payloads()[0], fip_fixture.payloads()[2]])))),
    ("a FIP entry leaving the FIP is refused", lambda: "leaves the FIP" in raises(
        lambda: measure.expected_pcr0(fip_fixture.flash()[:-1]))),
    ("a flash with no FIP at the FIP offset is refused", lambda: "no FIP" in raises(
        lambda: measure.expected_pcr0(fip_fixture.flash()[:measure.FIP_OFFSET] + bytes(64)))),
    ("a ToC without its terminator is refused", lambda: "runs off its end" in raises(
        lambda: measure.expected_pcr0(bytes(measure.FIP_OFFSET) + measure.FIP_HEADER.pack(measure.FIP_TOC_NAME, 0, 0)))),
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
