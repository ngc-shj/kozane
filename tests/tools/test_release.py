"""tools/release.py end to end with ephemeral keys and a synthetic package
(M5 plan C13, C12). The envelope check is mksecrets' own test.

Usage: python3 tests/tools/test_release.py   (after `make release-tool`)
Prints "RELEASE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import measure  # noqa: E402

RELEASE = [sys.executable, str(ROOT / "tools/release.py")]
BIN = str(ROOT / "build/release/target/release/release")


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
    image = bytes(range(256)) * 64
    desc = measure.pack(len(image), [(0x1000, 0x400), (0x2000, 0x800)])
    (pkg / "published.img").write_bytes(image)
    (pkg / "boot.desc").write_bytes(desc)
    (pkg / "pcr8").write_text(measure.expected_pcr8(desc, image).hex() + "\n")


def make(d, out="rel"):
    return run(*RELEASE, "make", "--keys", str(d / "keys"), "--pkg", str(d / "pkg"), "--out", str(d / out),
               "--allow-dirty")


def verify(d, pub="keys", rel="rel"):
    return run(*RELEASE, "verify", "--pub", str(d / pub), "--release", str(d / rel))


def flip(path: pathlib.Path, at: int = 100):
    b = bytearray(path.read_bytes())
    b[at] ^= 1
    path.write_bytes(bytes(b))


def case_allow(d):
    rc, out = make(d)
    rc2, out2 = verify(d)
    return rc == 0 and rc2 == 0 and "release: verified" in out2, out + out2


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


def case_pkg_pcr8(d):
    (d / "pkg/pcr8").write_text("00" * 32 + "\n")
    rc, out = make(d)
    return rc == 1 and "pcr8 differs" in out and not (d / "rel").exists(), out


def case_existing_out(d):
    (d / "rel").mkdir()
    rc, out = make(d)
    return rc == 1 and "already exists" in out, out


def case_keys_in_repo(d):
    rc, out = run(BIN, "keygen", "--dir", str(ROOT / "build/release/keys-in-repo"), "--forbid", str(ROOT))
    return rc == 1 and "keys must live elsewhere" in out and not (ROOT / "build/release/keys-in-repo").exists(), out


CASES = [
    ("a release made and verified with its own key", case_allow),
    ("a published image changed after signing is refused", case_image),
    ("a boot descriptor changed after signing is refused", case_desc),
    ("an edited manifest is refused", case_manifest),
    ("another key's public half refuses the release", case_other_key),
    ("a package whose pcr8 disagrees with measure.py is refused", case_pkg_pcr8),
    ("an existing OUT is refused", case_existing_out),
    ("release keys inside the repo are refused", case_keys_in_repo),
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
