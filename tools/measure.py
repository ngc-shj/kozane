"""The measured-boot model (M5 plan C8), shared by every host-side consumer:
the expected-PCR tool, tools/package and tests/integration/run.py. U-Boot's
side is support/u-boot/boot.cmd; this module is its host twin, pinned by the
C8 integration cases (a boot of the measure variant must print the PCR 8
this module computes).

Boot descriptor v2 (80 bytes, little-endian; M6 plan Re-plan R1): magic
"SOSBOOT1", version u32 2, count u32 3, image_len u64, then (offset u64,
len u64) for the secrets, pq_secrets and tls_secrets envelopes, then a
reserved u64 0. Version 1 (the 64-byte, two-envelope form) is refused.

PCR 8 starts at zero and is extended with sha256(descriptor), then with
sha256(image[0, image_len)); TPM2_PCR_Extend sets pcr = sha256(pcr || digest).

PCR 0 is TF-A's (M7 plan C3, C4): BL1 extends it with sha256(BL2), then BL2
with sha256(BL31) and sha256(BL33), each the FIP entry's bytes, before each
runs. That is the closed list: a FIP holding any other entry is refused.
PCRs 1-7 stay at zero. The seal policy names PCRs 0-8.
"""

import hashlib
import struct

MAGIC = b"SOSBOOT1"
VERSION = 2
COUNT = 3
DESC_LEN = 80
_FMT = "<8sIIQQQQQQQQ"
# U-Boot refuses an image larger than this (boot.cmd), and so does the host.
MAX_IMAGE = 0x10000000
# Where QEMU loads each file and U-Boot reads it (boot.cmd's layout).
LOAD_IMAGE = 0x70000000
LOAD_DESC = 0x6FF00000
LOAD_ENVELOPES = (0x6FC00000, 0x6FD00000, 0x6FE00000)
ENVELOPE_ROOM = 0x100000
PCR_ZERO = bytes(32)
POLICY_PCRS = 9

# flash.bin (tools/flash-image): the FIP at the qemu platform's FIP offset.
FIP_OFFSET = 0x40000
FIP_TOC_NAME = 0xAA640001
FIP_HEADER = struct.Struct("<IIQ")
FIP_ENTRY = struct.Struct("<16sQQQ")
# The closed list, in the order TF-A measures it (TF-A's
# include/tools_share/firmware_image_package.h, uuid_t's bytes in order).
FIP_MEASURED = (
    ("BL2", bytes.fromhex("5ff9ec0b4d223e4da544c39d81c73f0a")),
    ("BL31", bytes.fromhex("47d4086d4cfe98469b952950cbbd5a00")),
    ("BL33", bytes.fromhex("d6d0eea7fcead54b97829934f234b6e4")),
)


class DescriptorError(ValueError):
    pass


def check_ranges(image_len: int, ranges: list, expected=None) -> list:
    """I8.2: each range lies in [0, image_len) without wrap (the end may be
    exactly image_len), every two ranges are disjoint, every length fits its load
    slot, and, when given, they equal the system file's prefill ranges."""
    errors = []
    if not 0 < image_len <= MAX_IMAGE:
        errors.append(f"measure: image_len {image_len:#x} outside (0, {MAX_IMAGE:#x}]")
    if len(ranges) != COUNT:
        return errors + [f"measure: {len(ranges)} ranges, expected {COUNT}"]
    for i, (off, length) in enumerate(ranges):
        if off > image_len or length > image_len - off:
            errors.append(f"measure: range {i} ({off:#x}, {length:#x}) is outside the image ({image_len:#x})")
        if length > ENVELOPE_ROOM:
            errors.append(f"measure: range {i} length {length:#x} exceeds its load slot ({ENVELOPE_ROOM:#x})")
    for i, j in ((0, 1), (0, 2), (1, 2)):
        (oi, li), (oj, lj) = ranges[i], ranges[j]
        if oi + li > oj and oj + lj > oi:
            errors.append(f"measure: ranges {i} and {j} overlap ({oi:#x}+{li:#x}, {oj:#x}+{lj:#x})")
    if expected is not None and list(ranges) != list(expected):
        errors.append(f"measure: ranges {[(hex(o), hex(n)) for o, n in ranges]} differ from the system file's "
                      f"prefill ranges {[(hex(o), hex(n)) for o, n in expected]}")
    return errors


def pack(image_len: int, ranges: list, expected=None) -> bytes:
    errors = check_ranges(image_len, ranges, expected)
    if errors:
        raise DescriptorError("; ".join(errors))
    (o0, l0), (o1, l1), (o2, l2) = ranges
    return struct.pack(_FMT, MAGIC, VERSION, COUNT, image_len, o0, l0, o1, l1, o2, l2, 0)


def parse(desc: bytes, expected=None) -> tuple:
    """(image_len, ranges), refusing what boot.cmd refuses."""
    if len(desc) != DESC_LEN:
        raise DescriptorError(f"measure: descriptor is {len(desc)} bytes, expected {DESC_LEN}")
    magic, version, count, image_len, o0, l0, o1, l1, o2, l2, reserved = struct.unpack(_FMT, desc)
    if magic != MAGIC or version != VERSION or count != COUNT or reserved != 0:
        raise DescriptorError("measure: bad descriptor header")
    ranges = [(o0, l0), (o1, l1), (o2, l2)]
    errors = check_ranges(image_len, ranges, expected)
    if errors:
        raise DescriptorError("; ".join(errors))
    return image_len, ranges


def check_placeholder(image: bytes, desc: bytes) -> list:
    """The published image holds the zero placeholder over every envelope
    range: a descriptor cannot name loader code as an envelope slot (I8.2,
    checked from public files alone, so the release verifier runs it too)."""
    image_len, ranges = parse(desc)
    if len(image) < image_len:
        return [f"measure: image is {len(image)} bytes, descriptor says {image_len}"]
    return [f"measure: range {i} ({off:#x}, {length:#x}) is not the zero placeholder in the published image"
            for i, (off, length) in enumerate(ranges) if any(image[off:off + length])]


def extend(pcr: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(pcr + digest).digest()


def expected_pcr8(desc: bytes, image: bytes) -> bytes:
    image_len, _ = parse(desc)
    if len(image) < image_len:
        raise DescriptorError(f"measure: image is {len(image)} bytes, descriptor says {image_len}")
    pcr = extend(PCR_ZERO, hashlib.sha256(desc).digest())
    return extend(pcr, hashlib.sha256(image[:image_len]).digest())


def fip_images(flash: bytes) -> list:
    """[(name, bytes)] of the FIP in `flash`, in FIP_MEASURED's order,
    refusing a bad header, an entry outside the closed list, a duplicate,
    one that leaves the FIP, or a missing one."""
    fip = flash[FIP_OFFSET:]
    if len(fip) < FIP_HEADER.size or FIP_HEADER.unpack_from(fip)[0] != FIP_TOC_NAME:
        raise DescriptorError("measure: no FIP at the flash's FIP offset")
    names = {uuid: name for name, uuid in FIP_MEASURED}
    found = {}
    at = FIP_HEADER.size
    while True:
        if at + FIP_ENTRY.size > len(fip):
            raise DescriptorError("measure: the FIP's table of contents runs off its end")
        uuid, offset, size, _ = FIP_ENTRY.unpack_from(fip, at)
        at += FIP_ENTRY.size
        if uuid == bytes(16):
            break
        name = names.get(uuid)
        if name is None:
            raise DescriptorError(f"measure: FIP entry {uuid.hex()} is not on the measured list")
        if name in found:
            raise DescriptorError(f"measure: FIP entry {name} appears twice")
        if size == 0 or offset > len(fip) or size > len(fip) - offset:
            raise DescriptorError(f"measure: FIP entry {name} ({offset:#x}, {size:#x}) leaves the FIP")
        found[name] = fip[offset:offset + size]
    missing = [name for name, _ in FIP_MEASURED if name not in found]
    if missing:
        raise DescriptorError(f"measure: the FIP has no {', '.join(missing)}")
    return [(name, found[name]) for name, _ in FIP_MEASURED]


def expected_pcr0(flash: bytes) -> bytes:
    pcr = PCR_ZERO
    for _, image in fip_images(flash):
        pcr = extend(pcr, hashlib.sha256(image).digest())
    return pcr


def expected_pcrs(flash: bytes, desc: bytes, image: bytes) -> list:
    """PCRs 0-8 after the shipped boot of `flash`, before the cap."""
    return [expected_pcr0(flash)] + [PCR_ZERO] * 7 + [expected_pcr8(desc, image)]


def assemble(image: bytes, desc: bytes, envelopes: list) -> bytes:
    """What U-Boot runs: the image with each envelope copied into its range."""
    image_len, ranges = parse(desc)
    out = bytearray(image[:image_len])
    if len(out) != image_len:
        raise DescriptorError("measure: image shorter than image_len")
    for (off, length), env in zip(ranges, envelopes, strict=True):
        if len(env) != length:
            raise DescriptorError(f"measure: envelope is {len(env)} bytes, its range {length}")
        out[off:off + length] = env
    return bytes(out)
