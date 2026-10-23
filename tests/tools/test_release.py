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
    # Code-like bytes everywhere except the two envelope ranges, which hold
    # the zero placeholder as a published image does.
    image = bytearray(bytes(range(1, 256)) * 65)[:0x4000]
    image[0x1000:0x1400] = bytes(0x400)
    image[0x2000:0x2800] = bytes(0x800)
    image = bytes(image)
    desc = measure.pack(len(image), [(0x1000, 0x400), (0x2000, 0x800)])
    (pkg / "published.img").write_bytes(image)
    (pkg / "boot.desc").write_bytes(desc)
    (pkg / "pcr8").write_text(measure.expected_pcr8(desc, image).hex() + "\n")


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


def case_dirty_refused(d):
    rel = d / "rel"
    rel.mkdir()
    fields = {"version": "m5-dev", "commit": "0" * 40 + "-dirty", "dev_image": "x",
              "loader_img_sha256": __import__("hashlib").sha256((d / "pkg/published.img").read_bytes()).hexdigest(),
              "boot_desc_sha256": __import__("hashlib").sha256((d / "pkg/boot.desc").read_bytes()).hexdigest(),
              "pcr8": (d / "pkg/pcr8").read_text().strip(), "cargo_lock_sha256": "x", "verus": "x", "kani": "x"}
    rc, manifest = run(BIN, "render", *(f"{k}={v}" for k, v in fields.items()))
    (rel / "manifest").write_text(manifest)
    run(BIN, "sign", "--keys", str(d / "keys"), "--manifest", str(rel / "manifest"), "--out", str(rel / "manifest.sig"))
    for f in ("published.img", "boot.desc"):
        (rel / f).write_bytes((d / "pkg" / f).read_bytes())
    rc1, out1 = run(*RELEASE, "verify", "--pub", str(d / "keys"), "--release", str(rel))
    rc2, out2 = verify(d)
    return rc == 0 and rc1 == 1 and "dirty tree" in out1 and rc2 == 0, out1 + out2


def case_range_over_code(d):
    img = bytearray((d / "pkg/published.img").read_bytes())
    img[0x1000] = 1
    (d / "pkg/published.img").write_bytes(bytes(img))
    desc = (d / "pkg/boot.desc").read_bytes()
    (d / "pkg/pcr8").write_text(measure.expected_pcr8(desc, bytes(img)).hex() + "\n")
    rc, out = make(d)
    return rc == 1 and "zero placeholder" in out, out


CASES = [
    ("a release made and verified with its own key", case_allow),
    ("a published image changed after signing is refused", case_image),
    ("a boot descriptor changed after signing is refused", case_desc),
    ("an edited manifest is refused", case_manifest),
    ("another key's public half refuses the release", case_other_key),
    ("a package whose pcr8 disagrees with measure.py is refused", case_pkg_pcr8),
    ("an existing OUT is refused", case_existing_out),
    ("release keys inside the repo are refused", case_keys_in_repo),
    ("a failed signing leaves no OUT and no staging, and the retry succeeds", case_sign_fails_leaves_nothing),
    ("a release from a dirty tree is refused unless accepted", case_dirty_refused),
    ("a descriptor range over non-zero image bytes is refused", case_range_over_code),
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
