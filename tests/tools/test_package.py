"""Each tools/package acceptance check must reject its one-change fixture and
accept the unmodified package (plan C16 acceptance [T8]).

Usage: python3 tests/tools/test_package.py
Prints "PACKAGE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("package", str(ROOT / "tools/package"))
spec = importlib.util.spec_from_loader("package", loader)
pkg = importlib.util.module_from_spec(spec)
loader.exec_module(pkg)

SYSTEM = """<system>
    <memory_region name="secrets" size="0x1000" prefill_path="placeholder.bin" />
    <memory_region name="ring" size="0x1000" />
    <protection_domain name="key" priority="140" passive="true">
        <program_image path="pd-key.elf" />
        <map mr="secrets" vaddr="0x8_000_000" perms="r" />
    </protection_domain>
</system>"""

BLOB = pkg.MAGIC + bytes(range(1, 101)) + bytes(pkg.REGION_SIZE - len(pkg.MAGIC) - 100)
PAD = bytes(5000)
PLACEHOLDER_IMG = b"\x7fELF" + PAD + bytes(pkg.REGION_SIZE) + PAD
PACKAGE_IMG = b"\x7fELF" + PAD + BLOB + PAD
GEN_DEBUG = "/* x */\n#define CONFIG_DEBUG_BUILD  1\n#define CONFIG_PRINTING  1\n"
GEN_RELEASE = "/* disabled: CONFIG_DEBUG_BUILD */\n/* disabled: CONFIG_PRINTING */\n"


def package_system(path="/elsewhere/secrets.bin"):
    return pkg.with_prefill(SYSTEM, path)


def flip(img: bytes, at: int) -> bytes:
    return img[:at] + bytes([img[at] ^ 1]) + img[at + 1:]


def tmp_tree():
    """A scratch directory outside the repo; each fixture removes its own."""
    return pathlib.Path(tempfile.mkdtemp(prefix="test-package-"))


def out_case(setup):
    def run():
        d = tmp_tree()
        try:
            return pkg.check_out_path(setup(d), ROOT)
        finally:
            shutil.rmtree(d)
    return run


def link_into_repo(d):
    (d / "link").symlink_to(ROOT / "build")
    return d / "link" / "pkg"


def secrets_in_cargo_home():
    d = tmp_tree()
    old = os.environ.get("CARGO_HOME")
    os.environ["CARGO_HOME"] = str(d)
    try:
        (d / "registry").mkdir()
        return pkg.check_secrets_path(d / "registry" / "s.bin", ROOT)
    finally:
        if old is None:
            del os.environ["CARGO_HOME"]
        else:
            os.environ["CARGO_HOME"] = old
        shutil.rmtree(d)


def existing_out(d):
    (d / "pkg").mkdir()
    return d / "pkg"


# (name, expected error substring or None for accept, check)
CASES = [
    ("real package accepted", None,
     lambda: pkg.check_systems(SYSTEM, package_system()) + pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG, BLOB)
     + pkg.check_blob(BLOB) + pkg.require_debug(GEN_DEBUG)),
    ("empty image diff", "identical to the placeholder", lambda: pkg.check_images(PLACEHOLDER_IMG, PLACEHOLDER_IMG, BLOB)),
    ("image diff outside the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 2), BLOB)),
    ("image diff just past the blob", "differs outside the blob",
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 4 + len(PAD) + len(BLOB)), BLOB)),
    ("image length changed", "length changed", lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG + b"\0", BLOB)),
    ("placeholder not zero under the blob", "not zero where the blob lands",
     lambda: pkg.check_images(flip(PLACEHOLDER_IMG, 4 + len(PAD) + 200), PACKAGE_IMG, BLOB)),
    # A second copy present at the same offset in both images: no extra
    # diff, so only the uniqueness clause can reject it.
    ("blob appears twice", "exactly once",
     lambda: pkg.check_images(PLACEHOLDER_IMG + BLOB, PACKAGE_IMG + BLOB, BLOB)),
    ("all-zero blob", "all zero", lambda: pkg.check_blob(bytes(pkg.REGION_SIZE))),
    ("short blob", "expected 4096", lambda: pkg.check_blob(BLOB[:-1])),
    ("blob without magic", "no secrets magic", lambda: pkg.check_blob(b"X" + BLOB[1:])),
    ("other attribute changed", "attributes of <protection_domain>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('priority="140"', 'priority="141"'))),
    ("other mr's attribute changed", "attributes of <memory_region>",
     lambda: pkg.check_systems(SYSTEM, package_system().replace('name="ring" size="0x1000"', 'name="ring" size="0x2000"'))),
    ("element added", "children",
     lambda: pkg.check_systems(SYSTEM, package_system().replace("</system>", '<memory_region name="x" size="0x1000" /></system>'))),
    ("non-debug kernel", "not debug", lambda: pkg.require_debug(GEN_RELEASE)),
    ("secrets path inside the repo", "inside", lambda: pkg.check_secrets_path(ROOT / "build/secrets.bin", ROOT)),
    ("secrets path outside the repo", None, lambda: pkg.check_secrets_path(pathlib.Path("/tmp/s.bin"), ROOT)),
    ("secrets path inside the cargo home", "inside", secrets_in_cargo_home),
    ("output inside build/", "inside", lambda: pkg.check_out_path(ROOT / "build/pkg", ROOT)),
    ("output inside the repo", "inside", lambda: pkg.check_out_path(ROOT / "pkg-out", ROOT)),
    ("output through a symlink into the repo", "inside", out_case(link_into_repo)),
    ("output directory already exists", "already exists", out_case(existing_out)),
    ("fresh output outside the repo", None, out_case(lambda d: d / "pkg")),
]


def main() -> int:
    failures = 0
    for name, want, run in CASES:
        errors = run()
        if want is None:
            ok = not errors
        else:
            ok = len(errors) == 1 and want in errors[0]
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"PACKAGE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
