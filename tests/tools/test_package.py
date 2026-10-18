"""Each tools/package acceptance check must reject its one-change fixture and
accept the unmodified package (plan C16 acceptance [T8]).

Usage: python3 tests/tools/test_package.py
Prints "PACKAGE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import pathlib
import sys

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


CASES = [
    ("real package accepted", True,
     lambda: pkg.check_systems(SYSTEM, package_system()) + pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG, BLOB)
     + pkg.check_blob(BLOB) + pkg.require_debug(GEN_DEBUG)),
    ("empty image diff", False, lambda: pkg.check_images(PLACEHOLDER_IMG, PLACEHOLDER_IMG, BLOB)),
    ("image diff outside the blob", False, lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 2), BLOB)),
    ("image diff just past the blob", False,
     lambda: pkg.check_images(PLACEHOLDER_IMG, flip(PACKAGE_IMG, 4 + len(PAD) + len(BLOB)), BLOB)),
    ("image length changed", False, lambda: pkg.check_images(PLACEHOLDER_IMG, PACKAGE_IMG + b"\0", BLOB)),
    ("placeholder not zero under the blob", False,
     lambda: pkg.check_images(flip(PLACEHOLDER_IMG, 4 + len(PAD) + 200), PACKAGE_IMG, BLOB)),
    ("blob appears twice", False,
     lambda: pkg.check_images(PLACEHOLDER_IMG + bytes(len(BLOB)), PACKAGE_IMG + BLOB, BLOB)),
    ("all-zero blob", False, lambda: pkg.check_blob(bytes(pkg.REGION_SIZE))),
    ("short blob", False, lambda: pkg.check_blob(BLOB[:-1])),
    ("blob without magic", False, lambda: pkg.check_blob(b"X" + BLOB[1:])),
    ("other attribute changed", False,
     lambda: pkg.check_systems(SYSTEM, package_system().replace('priority="140"', 'priority="141"'))),
    ("other mr's attribute changed", False,
     lambda: pkg.check_systems(SYSTEM, package_system().replace('name="ring" size="0x1000"', 'name="ring" size="0x2000"'))),
    ("element added", False,
     lambda: pkg.check_systems(SYSTEM, package_system().replace("</system>", '<memory_region name="x" size="0x1000" /></system>'))),
    ("non-debug kernel", False, lambda: pkg.require_debug(GEN_RELEASE)),
    ("secrets path inside the repo", False, lambda: pkg.check_secrets_path(ROOT / "build/secrets.bin", ROOT)),
    ("secrets path outside the repo", True, lambda: pkg.check_secrets_path(pathlib.Path("/elsewhere/s.bin"), ROOT)),
]


def main() -> int:
    failures = 0
    for name, accept, run in CASES:
        errors = run()
        ok = (not errors) == accept
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"PACKAGE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
