"""The measured-boot model (M5 plan C8), shared by every host-side consumer:
the expected-PCR tool, tools/package and tests/integration/run.py. U-Boot's
side is support/u-boot/boot.cmd; this module is its host twin, pinned by the
C8 integration cases (a boot of the measure variant must print the PCR 8
this module computes).

Boot descriptor v3 (128 bytes, little-endian; M8 plan C4, deviation D-5):
magic "SOSBOOT1", version u32 3, count u32 6, image_len u64, then (offset
u64, len u64) for the four envelopes (secrets, pq_secrets, tls_secrets,
audit_secrets) and the policy_a and policy_b bundle slots, then a reserved
u64 0. Each range fits its kind's room (ENVELOPE_ROOM, BUNDLE_MAX), and
every two are disjoint. Versions 1 and 2 are refused.

PCR 8 starts at zero and is extended with sha256(descriptor), then with
sha256(image[0, image_len)); TPM2_PCR_Extend sets pcr = sha256(pcr || digest).
PCR 9 is extended with sha256(slot A), then sha256(slot B), each over the
full BUNDLE_MAX at its load address (M8 plan D3); it is measured, not
sealed to.

Nothing runs before U-Boot (M9 plan D1, C2: no TF-A), so nothing extends
PCRs 0-7: they stay at zero, and the seal policy names PCRs 0-8 with 0-7 at
zero. That guards the firmware the operator runs; it does not measure it
(RM9-1).

The NV anti-rollback indices (M8 plan C3) have twins here too: the delete
policy their authPolicy holds and the Names the `tpm` PD compares.
"""

import hashlib
import itertools
import pathlib
import re
import struct

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _limit(name: str) -> int:
    """A `pub const NAME: usize` of crates/limits, the one source the PDs
    and tools/policy build against: never a second copy here."""
    m = re.search(rf"^pub const {name}: usize = (0x[0-9a-fA-F_]+|[0-9_]+);$",
                  (ROOT / "crates/limits/src/lib.rs").read_text(), re.M)
    if not m:
        raise SystemExit(f"measure: crates/limits/src/lib.rs has no `pub const {name}: usize`")
    return int(m.group(1).replace("_", ""), 0)


MAGIC = b"SOSBOOT1"
VERSION = 3
ENVELOPES = 4
SLOTS = 2
COUNT = ENVELOPES + SLOTS
DESC_LEN = 8 + 4 + 4 + 8 + 16 * COUNT + 8
_FMT = "<8sIIQ" + "QQ" * COUNT + "Q"
# U-Boot refuses an image larger than this (boot.cmd), and so does the host.
MAX_IMAGE = 0x10000000
# Where QEMU loads each file and U-Boot reads it (boot.cmd's layout).
LOAD_IMAGE = 0x70000000
LOAD_DESC = 0x6FF00000
# The audit envelope's slot sits below slot A (M8 plan C10).
LOAD_ENVELOPES = (0x6FC00000, 0x6FD00000, 0x6FE00000, 0x6F000000)
# Below boot.cmd's digest scratch at 0x6fb00000 (M8 plan P3).
LOAD_SLOTS = (0x6F100000, 0x6F600000)
ENVELOPE_ROOM = 0x100000
BUNDLE_MAX = _limit("BUNDLE_MAX")
# Each range's room, in descriptor order: what its load slot holds.
ROOMS = (ENVELOPE_ROOM,) * ENVELOPES + (BUNDLE_MAX,) * SLOTS
LOADS = LOAD_ENVELOPES + LOAD_SLOTS
# Every two ranges, each checked on its own (boot.cmd has one line a pair).
PAIRS = tuple(itertools.combinations(range(COUNT), 2))
PCR_ZERO = bytes(32)
# The seal policy's PCRs, 0 to POLICY_PCRS - 1: PCR 9 (the slots) stays out
# (M8 plan D3, C4).
POLICY_PCRS = 9
SLOT_PCR = 9

class DescriptorError(ValueError):
    pass


def check_ranges(image_len: int, ranges: list, expected=None) -> list:
    """I8.2: each range lies in [0, image_len) without wrap (the end may be
    exactly image_len), every two ranges are disjoint, every length fits its
    kind's load slot (ROOMS), and, when given, they equal the system file's
    prefill ranges."""
    errors = []
    if not 0 < image_len <= MAX_IMAGE:
        errors.append(f"measure: image_len {image_len:#x} outside (0, {MAX_IMAGE:#x}]")
    if len(ranges) != COUNT:
        return errors + [f"measure: {len(ranges)} ranges, expected {COUNT}"]
    for i, (off, length) in enumerate(ranges):
        if off > image_len or length > image_len - off:
            errors.append(f"measure: range {i} ({off:#x}, {length:#x}) is outside the image ({image_len:#x})")
        if length > ROOMS[i]:
            errors.append(f"measure: range {i} length {length:#x} exceeds its load slot ({ROOMS[i]:#x})")
        # A slot is exactly BUNDLE_MAX, as boot.cmd requires: PCR 9 hashes
        # the whole load slot, so a shorter range would copy less than it
        # measures (M8 plan C1, F8).
        if i >= ENVELOPES and length != BUNDLE_MAX:
            errors.append(f"measure: slot range {i} length {length:#x} is not BUNDLE_MAX ({BUNDLE_MAX:#x})")
    for i, j in PAIRS:
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
    return struct.pack(_FMT, MAGIC, VERSION, COUNT, image_len, *(v for r in ranges for v in r), 0)


def parse(desc: bytes, expected=None) -> tuple:
    """(image_len, ranges), refusing what boot.cmd refuses."""
    if len(desc) != DESC_LEN:
        raise DescriptorError(f"measure: descriptor is {len(desc)} bytes, expected {DESC_LEN}")
    magic, version, count, image_len, *fields, reserved = struct.unpack(_FMT, desc)
    if magic != MAGIC or version != VERSION or count != COUNT or reserved != 0:
        raise DescriptorError("measure: bad descriptor header")
    ranges = list(zip(fields[0::2], fields[1::2]))
    errors = check_ranges(image_len, ranges, expected)
    if errors:
        raise DescriptorError("; ".join(errors))
    return image_len, ranges


def check_placeholder(image: bytes, desc: bytes) -> list:
    """The published image holds the zero placeholder over every range
    (envelopes and bundle slots): a descriptor cannot name loader code as a
    load slot (I8.2, checked from public files alone, so the release
    verifier runs it too)."""
    image_len, ranges = parse(desc)
    if len(image) < image_len:
        return [f"measure: image is {len(image)} bytes, descriptor says {image_len}"]
    return [f"measure: range {i} ({off:#x}, {length:#x}) is not the zero placeholder in the published image"
            for i, (off, length) in enumerate(ranges) if any(image[off:off + length])]


# What every PD built with `fault-inject` holds (M7 plan C8).
FAULT_INJECT_MARKER = b"KOZANE-FAULT-INJECT-VARIANT"


def check_not_fault_inject(image: bytes) -> list:
    """The image holds no PD built with the fault-inject selftest feature
    (public files alone, so the release verifier runs it too)."""
    return (["measure: the image holds a PD built with the fault-inject feature (a selftest variant)"]
            if FAULT_INJECT_MARKER in image else [])


def extend(pcr: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(pcr + digest).digest()


def expected_pcr8(desc: bytes, image: bytes) -> bytes:
    image_len, _ = parse(desc)
    if len(image) < image_len:
        raise DescriptorError(f"measure: image is {len(image)} bytes, descriptor says {image_len}")
    pcr = extend(PCR_ZERO, hashlib.sha256(desc).digest())
    return extend(pcr, hashlib.sha256(image[:image_len]).digest())


def expected_pcr9(slot_a: bytes, slot_b: bytes) -> bytes:
    """PCR 9 after U-Boot measured both slots, A then B, each its full
    BUNDLE_MAX bytes (M8 plan D3)."""
    for name, slot in (("A", slot_a), ("B", slot_b)):
        if len(slot) != BUNDLE_MAX:
            raise DescriptorError(f"measure: slot {name} is {len(slot)} bytes, expected {BUNDLE_MAX:#x}")
    return extend(extend(PCR_ZERO, hashlib.sha256(slot_a).digest()), hashlib.sha256(slot_b).digest())


def expected_pcrs(desc: bytes, image: bytes) -> list:
    """PCRs 0-8 after the shipped boot, before the cap."""
    return [PCR_ZERO] * 8 + [expected_pcr8(desc, image)]


def assemble(image: bytes, desc: bytes, contents: list) -> bytes:
    """What U-Boot runs: the image with each envelope and each slot copied
    into its range, in descriptor order."""
    image_len, ranges = parse(desc)
    out = bytearray(image[:image_len])
    if len(out) != image_len:
        raise DescriptorError("measure: image shorter than image_len")
    for (off, length), env in zip(ranges, contents, strict=True):
        if len(env) != length:
            raise DescriptorError(f"measure: envelope is {len(env)} bytes, its range {length}")
        out[off:off + length] = env
    return bytes(out)


# M8 plan C3: the two anti-rollback NV indices, their attributes (P1: the
# counter TPM_NT_COUNTER, AUTHWRITE, AUTHREAD, NO_DA, POLICY_DELETE,
# PLATFORMCREATE; the base the same with WRITEDEFINE instead of the
# counter type), the bits the TPM sets once written and locked, and the
# delete policy's fixed policyRef.
NV_POLICY_CTR = 0x01500100
NV_POLICY_BASE = 0x01500101
NV_CTR_ATTRS = 0x42040414
NV_BASE_ATTRS = 0x42042404
NV_WRITTEN = 0x20000000
NV_WRITELOCKED = 0x00000800
NV_SIZE = 8
NV_DELETE_REF = b"kozane-nv-delete"
TPM_ALG_SHA256 = 0x000B
CC_POLICY_COMMAND_CODE = 0x16C
CC_POLICY_SIGNED = 0x160
CC_NV_UNDEFINE_SPACE_SPECIAL = 0x11F
TPM_RH_PLATFORM = 0x4000000C


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def delete_policy(key_names: list, ref: bytes = NV_DELETE_REF) -> bytes:
    """PolicyCommandCode(NV_UndefineSpaceSpecial) then one PolicySigned per
    operator key Name (TPM 2.0 Part 3, 23.3 and 23.11), the authPolicy of
    both indices."""
    digest = _sha256(PCR_ZERO + struct.pack(">II", CC_POLICY_COMMAND_CODE, CC_NV_UNDEFINE_SPACE_SPECIAL))
    for name in key_names:
        digest = _sha256(_sha256(digest + struct.pack(">I", CC_POLICY_SIGNED) + name) + ref)
    return digest


def nv_name(index: int, attrs: int, policy: bytes, size: int = NV_SIZE) -> bytes:
    """nameAlg || sha256(TPMS_NV_PUBLIC) of an sha256 NV index."""
    public = struct.pack(">IHI", index, TPM_ALG_SHA256, attrs) + struct.pack(">H", len(policy)) + policy \
        + struct.pack(">H", size)
    return struct.pack(">H", TPM_ALG_SHA256) + _sha256(public)


def expected_nv_names(policy: bytes) -> tuple:
    """(counter, base) Names once provisioned: the counter written, the base
    written and write-locked."""
    return (nv_name(NV_POLICY_CTR, NV_CTR_ATTRS | NV_WRITTEN, policy),
            nv_name(NV_POLICY_BASE, NV_BASE_ATTRS | NV_WRITTEN | NV_WRITELOCKED, policy))


def undefine_special_cphash(index_name: bytes) -> bytes:
    """cpHashA of TPM2_NV_UndefineSpaceSpecial(index, TPM_RH_PLATFORM): the
    command code and both handles' Names (a permanent handle's Name is the
    handle), no parameters."""
    return _sha256(struct.pack(">I", CC_NV_UNDEFINE_SPACE_SPECIAL) + index_name + struct.pack(">I", TPM_RH_PLATFORM))
