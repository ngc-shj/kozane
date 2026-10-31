"""tools/release.py end to end with ephemeral keys and a synthetic package
(M5 plan C13, C12). The envelope check is mksecrets' own test.

Usage: python3 tests/tools/test_release.py   (after `make release-tool`)
Prints "RELEASE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import hashlib
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402
import fip_fixture  # noqa: E402

RELEASE = [sys.executable, str(ROOT / "tools/release.py")]
SEQ = re.search(r"^pub const RELEASE_SEQ: u32 = (\d+);$", (ROOT / "crates/release-seq/src/lib.rs").read_text(), re.M)[1]
BIN = str(ROOT / "build/release/target/release/release")
SLOT = measure.BUNDLE_MAX
# The three envelopes, then the two bundle slots (descriptor v3).
RANGES = [(0x1000, 0x400), (0x2000, 0x800), (0x3000, 0x400), (0x4000, SLOT), (0x4000 + SLOT, SLOT)]


def run(*args) -> tuple:
    r = subprocess.run(list(args), cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def setup(d: pathlib.Path) -> None:
    for name in ("keys", "other"):
        rc, out = run(BIN, "keygen", "--dir", str(d / name), "--forbid", str(ROOT))
        if rc:
            raise SystemExit(f"keygen failed: {out}")
    pkg = d / "pkg"
    pkg.mkdir()
    # Code-like bytes everywhere except the five ranges, which hold the zero
    # placeholder as a published image does.
    image = bytearray(bytes(range(1, 256)) * 65)[:0x4000] + bytes(2 * SLOT) + bytes(range(1, 256))
    for at, length in RANGES:
        image[at:at + length] = bytes(length)
    image = bytes(image)
    desc = measure.pack(len(image), RANGES)
    (pkg / "published.img").write_bytes(image)
    (pkg / "boot.desc").write_bytes(desc)
    (pkg / "flash.bin").write_bytes(fip_fixture.flash())
    write_pcrs(pkg)


def write_pcrs(pkg: pathlib.Path):
    pcrs = measure.expected_pcrs((pkg / "flash.bin").read_bytes(), (pkg / "boot.desc").read_bytes(),
                                 (pkg / "published.img").read_bytes())
    (pkg / "pcrs").write_text("".join(p.hex() + "\n" for p in pcrs))


def make(d, out="rel"):
    return run(*RELEASE, "make", "--keys", str(d / "keys"), "--pkg", str(d / "pkg"), "--out", str(d / out),
               "--allow-dirty")


def verify(d, pub="keys", rel="rel", *extra):
    # The test tree may be dirty, so its releases may carry -dirty.
    return run(*RELEASE, "verify", "--pub", str(d / pub), "--release", str(d / rel), "--allow-dirty", *extra)


def flip(path: pathlib.Path, at: int = 100):
    b = bytearray(path.read_bytes())
    b[at] ^= 1
    path.write_bytes(bytes(b))


def case_allow(d):
    rc, out = make(d)
    rc2, out2 = verify(d)
    signed = (d / "rel/manifest").read_text().splitlines() if rc == 0 else []
    return rc == 0 and rc2 == 0 and "release: verified" in out2 and f"release_seq={SEQ}" in signed, out + out2


def case_image(d):
    make(d)
    flip(d / "rel/published.img")
    rc, out = verify(d)
    return rc == 1 and "loader_img_sha256" in out, out


def case_desc(d):
    make(d)
    flip(d / "rel/boot.desc", 20)
    rc, out = verify(d)
    return rc == 1 and ("boot_desc_sha256" in out or "measure:" in out), out


def case_firmware(d):
    """M7 plan C4, C11: a firmware byte changed after signing (BL2's, so PCR 0
    moves too) is refused."""
    make(d)
    flash = d / "rel/flash.bin"
    flip(flash, measure.FIP_OFFSET + measure.FIP_HEADER.size + measure.FIP_ENTRY.size * 4 + 1)
    rc, out = verify(d)
    return rc == 1 and ("firmware_sha256" in out or "pcrs" in out), out


def case_manifest(d):
    make(d)
    m = d / "rel/manifest"
    m.write_text(m.read_text().replace("version=m5-dev", "version=m5-forged"))
    rc, out = verify(d)
    return rc == 1 and "does not verify" in out, out


def case_other_key(d):
    make(d)
    rc, out = verify(d, pub="other")
    return rc == 1 and "does not verify" in out, out


def case_pkg_pcrs(d):
    """M7 plan C4: a package whose PCR 0 (TF-A's) disagrees with its flash.bin."""
    lines = (d / "pkg/pcrs").read_text().split()
    (d / "pkg/pcrs").write_text("".join(l + "\n" for l in ["00" * 32] + lines[1:]))
    rc, out = make(d)
    return rc == 1 and "pcrs differ" in out and not (d / "rel").exists(), out


def case_pkg_firmware_swapped(d):
    """M7 plan C4: another firmware beside the pcrs computed from the first."""
    other = [(u, data + b"!") for u, data in fip_fixture.payloads()]
    (d / "pkg/flash.bin").write_bytes(fip_fixture.flash(other))
    rc, out = make(d)
    return rc == 1 and "pcrs differ" in out and not (d / "rel").exists(), out


def case_pkg_firmware_extra_entry(d):
    """M7 plan C3: a FIP with an entry outside the measured list is refused."""
    extra = fip_fixture.payloads() + [(bytes.fromhex("9766fd3d89bee849ae5d78a140608213"), b"scp")]
    (d / "pkg/flash.bin").write_bytes(fip_fixture.flash(extra))
    rc, out = make(d)
    return rc == 1 and "not on the measured list" in out and not (d / "rel").exists(), out


def case_existing_out(d):
    (d / "rel").mkdir()
    rc, out = make(d)
    return rc == 1 and "already exists" in out, out


def case_keys_in_repo(d):
    rc, out = run(BIN, "keygen", "--dir", str(ROOT / "build/release/keys-in-repo"), "--forbid", str(ROOT))
    return rc == 1 and "keys must live elsewhere" in out and not (ROOT / "build/release/keys-in-repo").exists(), out


def case_sign_fails_leaves_nothing(d):
    bad = d / "badkeys"
    bad.mkdir()
    for f in ("ed25519.pub", "ml-dsa-65.pub", "ml-dsa-65.key"):
        (bad / f).write_bytes((d / "keys" / f).read_bytes())
    (bad / "ed25519.key").write_text("00\n")
    rc, out = run(*RELEASE, "make", "--keys", str(bad), "--pkg", str(d / "pkg"), "--out", str(d / "rel"),
                  "--allow-dirty")
    leftovers = [p.name for p in d.iterdir() if p.name.startswith(".rel.")]
    rc2, out2 = make(d)
    return rc == 1 and not leftovers and rc2 == 0 and (d / "rel/manifest.sig").exists(), out + out2


def signed_release(d, commit: str, image: bytes = None, seq: str = SEQ) -> bool:
    """A release signed by hand, bypassing `make`'s own refusals, so each of
    verify's checks can be met on its own: OUT is d/rel."""
    rel = d / "rel"
    rel.mkdir()
    img = image if image is not None else (d / "pkg/published.img").read_bytes()
    desc = (d / "pkg/boot.desc").read_bytes()
    fields = {"version": "m5-dev", "commit": commit, "dev_image": "x",
              "loader_img_sha256": hashlib.sha256(img).hexdigest(),
              "boot_desc_sha256": hashlib.sha256(desc).hexdigest(),
              "firmware_sha256": hashlib.sha256(fip_fixture.flash()).hexdigest(),
              "pcrs": ",".join(p.hex() for p in measure.expected_pcrs(fip_fixture.flash(), desc, img)),
              "cargo_lock_sha256": "x", "release_seq": seq, "verus": "x", "kani": "x"}
    rc, manifest = run(BIN, "render", *(f"{k}={v}" for k, v in fields.items()))
    (rel / "manifest").write_text(manifest)
    rc2, _ = run(BIN, "sign", "--keys", str(d / "keys"), "--manifest", str(rel / "manifest"),
                 "--out", str(rel / "manifest.sig"))
    (rel / "published.img").write_bytes(img)
    (rel / "boot.desc").write_bytes(desc)
    (rel / "flash.bin").write_bytes(fip_fixture.flash())
    return rc == 0 and rc2 == 0


def verify_default(d):
    return run(*RELEASE, "verify", "--pub", str(d / "keys"), "--release", str(d / "rel"))


def case_dirty_refused(d):
    made = signed_release(d, "0" * 40 + "-dirty")
    rc1, out1 = verify_default(d)
    rc2, out2 = verify(d)
    return made and rc1 == 1 and "dirty tree" in out1 and rc2 == 0, out1 + out2


def case_clean_default_verify(d):
    made = signed_release(d, "0" * 40)
    rc, out = verify_default(d)
    return made and rc == 0 and "release: verified" in out, out


def case_verify_placeholder(d):
    img = bytearray((d / "pkg/published.img").read_bytes())
    img[0x1000] = 1
    made = signed_release(d, "0" * 40, bytes(img))
    rc, out = verify_default(d)
    return made and rc == 1 and "zero placeholder" in out, out


def case_range_over_code(d, at=0x1000):
    img = bytearray((d / "pkg/published.img").read_bytes())
    img[at] = 1
    (d / "pkg/published.img").write_bytes(bytes(img))
    desc = (d / "pkg/boot.desc").read_bytes()
    write_pcrs(d / "pkg")
    rc, out = make(d)
    return rc == 1 and "zero placeholder" in out, out


def case_range2_over_code(d):
    ok, out = case_range_over_code(d, at=0x33ff)
    return ok and "range 2" in out, out


def case_slot_over_code(d):
    """A bundle slot's range is checked like an envelope's (M8 plan C4)."""
    ok, out = case_range_over_code(d, at=0x4000 + 2 * SLOT - 1)
    return ok and "range 4" in out, out


def case_v2_descriptor(d):
    """M6's 80-byte, three-envelope descriptor is refused (M8 plan C4)."""
    image = (d / "pkg/published.img").read_bytes()
    desc = struct.pack("<8sIIQQQQQQQQ", measure.MAGIC, 2, 3, len(image), *RANGES[0], *RANGES[1], *RANGES[2], 0)
    (d / "pkg/boot.desc").write_bytes(desc)
    rc, out = make(d)
    return rc == 1 and "descriptor is 80 bytes, expected 112" in out and not (d / "rel").exists(), out


def fault_inject_image(d) -> bytes:
    """The package's image with the fault-inject marker in its code bytes."""
    img = bytearray((d / "pkg/published.img").read_bytes())
    img[0x100:0x100 + len(measure.FAULT_INJECT_MARKER)] = measure.FAULT_INJECT_MARKER
    return bytes(img)


def case_make_fault_inject(d):
    """M7 plan C8: a package built from fault-inject PDs is no release."""
    (d / "pkg/published.img").write_bytes(fault_inject_image(d))
    write_pcrs(d / "pkg")
    rc, out = make(d)
    return rc == 1 and "fault-inject feature" in out and not (d / "rel").exists(), out


def case_verify_fault_inject(d):
    made = signed_release(d, "0" * 40, fault_inject_image(d))
    rc, out = verify_default(d)
    return made and rc == 1 and "fault-inject feature" in out, out


def case_release_seq_other(d):
    """M8 plan C9: a release signed with another release_seq than the
    source's is refused, though every other field and both signatures hold."""
    made = signed_release(d, "0" * 40, seq=str(int(SEQ) + 1))
    rc, out = verify_default(d)
    return made and rc == 1 and f"release_seq: crates/release-seq says {SEQ}" in out, out


def case_release_seq_missing(d):
    """A manifest without release_seq does not render, so it cannot be
    signed (the tool's canonical key set)."""
    rc, out = run(BIN, "render", "version=x", "commit=x", "dev_image=x", "loader_img_sha256=x", "boot_desc_sha256=x",
                  "firmware_sha256=x", "pcrs=x", "cargo_lock_sha256=x", "verus=x", "kani=x")
    return rc == 1 and "manifest key release_seq is missing" in out, out


def case_kind_tls(d):
    """`--kind tls` is a choice: only the --envelope pairing refuses it."""
    rc, out = verify(d, "keys", "rel", "--kind", "tls")
    rc2, out2 = verify(d, "keys", "rel", "--kind", "bogus")
    return rc == 2 and "--envelope and --kind go together" in out and rc2 == 2 and "invalid choice" in out2, \
        out + out2


CASES = [
    ("a release made and verified with its own key", case_allow),
    ("a published image changed after signing is refused", case_image),
    ("a boot descriptor changed after signing is refused", case_desc),
    ("a firmware image changed after signing is refused", case_firmware),
    ("an edited manifest is refused", case_manifest),
    ("another key's public half refuses the release", case_other_key),
    ("a package whose pcrs disagree with measure.py is refused", case_pkg_pcrs),
    ("a package whose flash.bin is not the one its pcrs came from is refused", case_pkg_firmware_swapped),
    ("a package whose FIP has an unmeasured entry is refused", case_pkg_firmware_extra_entry),
    ("an existing OUT is refused", case_existing_out),
    ("release keys inside the repo are refused", case_keys_in_repo),
    ("a failed signing leaves no OUT and no staging, and the retry succeeds", case_sign_fails_leaves_nothing),
    ("a release from a dirty tree is refused unless accepted", case_dirty_refused),
    ("a clean release verifies by default, no flag", case_clean_default_verify),
    ("verify refuses a release_seq other than the source's", case_release_seq_other),
    ("a manifest without release_seq does not render", case_release_seq_missing),
    ("verify refuses a signed range over non-zero image bytes", case_verify_placeholder),
    ("make refuses an image holding a fault-inject PD", case_make_fault_inject),
    ("verify refuses a signed image holding a fault-inject PD", case_verify_fault_inject),
    ("a descriptor range over non-zero image bytes is refused", case_range_over_code),
    ("a descriptor range 2 over non-zero image bytes is refused", case_range2_over_code),
    ("a bundle slot range over non-zero image bytes is refused", case_slot_over_code),
    ("a version-2 descriptor is refused", case_v2_descriptor),
    ("verify takes --kind tls", case_kind_tls),
]


def main() -> int:
    failures = 0
    for name, case in CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            setup(d)
            ok, out = case(d)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {out.strip()[-300:]}"))
    print(f"RELEASE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
