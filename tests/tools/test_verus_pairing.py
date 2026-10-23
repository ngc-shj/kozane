"""tools/verus-pairing on synthetic trees (M5 plan C5).

Usage: python3 tests/tools/test_verus_pairing.py
Prints "VERUS-PAIRING-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader("verus_pairing", str(ROOT / "tools/verus-pairing"))
spec = importlib.util.spec_from_loader("verus_pairing", loader)
vp = importlib.util.module_from_spec(spec)
loader.exec_module(vp)

POLICY = """image_root = "unused"
image_only = ["tests/"]
vendor_only = ["Cargo.toml", "README.md"]
[crates]
vstd = "vstd"
verus_builtin = "builtin"
"""
LOCK_PATH = """version = 4
[[package]]
name = "vstd"
version = "0.0.0-x"
[[package]]
name = "verus_builtin"
version = "0.0.0-x"
"""
LOCK_REGISTRY = LOCK_PATH.replace(
    'name = "verus_builtin"\nversion = "0.0.0-x"',
    'name = "verus_builtin"\nversion = "0.0.0-x"\nsource = "registry+https://github.com/rust-lang/crates.io-index"')
PATCH = """[patch.crates-io]
vstd = { path = "third_party/verus/vstd" }
verus_builtin = { path = "third_party/verus/verus_builtin" }
verus_syn = { path = "third_party/verus/verus_syn" }
"""
LOCK_EXTRA = LOCK_PATH + '[[package]]\nname = "verus_syn"\nversion = "0.0.0-x"\n'


def build(tmp: pathlib.Path, lock: str, mutate=None) -> tuple:
    root, image = tmp / "repo", tmp / "image"
    for base, sub in [(root / "third_party/verus/vstd", None), (image / "vstd", None),
                      (root / "third_party/verus/verus_builtin", None), (image / "builtin", None)]:
        (base / "src").mkdir(parents=True)
        (base / "src/lib.rs").write_text("pub fn f() {}\n")
    (root / "third_party/verus/vstd/Cargo.toml").write_text("[package]\nname = \"vstd\"\n")
    (root / "third_party/verus/vstd/README.md").write_text("readme\n")
    (image / "vstd/Cargo.toml").write_text("[package]\nname.workspace = true\n")
    (root / "policy").mkdir()
    (root / "policy/verus-pairing.toml").write_text(POLICY)
    (root / "Cargo.lock").write_text(lock)
    (root / "Cargo.toml").write_text(PATCH)
    if mutate:
        mutate(root, image)
    return vp.check(root, image)


def flip(root, image):
    (root / "third_party/verus/vstd/src/lib.rs").write_text("pub fn f() { }\n")


def extra(root, image):
    (root / "third_party/verus/vstd/src/extra.rs").write_text("\n")


def missing(root, image):
    (root / "third_party/verus/verus_builtin/src/lib.rs").unlink()


def no_image(root, image):
    for p in sorted((image / "builtin").rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    (image / "builtin").rmdir()


def no_vendor(root, image):
    for p in sorted((root / "third_party/verus/verus_builtin").rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    (root / "third_party/verus/verus_builtin").rmdir()


def unlisted_policy(root, image):
    (root / "policy/verus-pairing.toml").write_text(POLICY + 'verus_prettyplease = "prettyplease"\n')


def image_tests(root, image):
    (image / "vstd/tests").mkdir()
    (image / "vstd/tests/t.rs").write_text("#[test] fn t() {}\n")


def image_tests_named_like_src(root, image):
    (image / "vstd/testsuite.rs").write_text("\n")


def vendored_link_to_image(root, image):
    import shutil
    shutil.rmtree(root / "third_party/verus/vstd")
    (root / "third_party/verus/vstd").symlink_to(image / "vstd")


def patch_elsewhere(root, image):
    (root / "Cargo.toml").write_text(PATCH.replace("third_party/verus/verus_builtin", "vendor/verus_builtin"))


# (name, lock, mutation, expected paired count, needle in errors or None)
CASES = [
    ("identical trees pair (manifest and README are packaging)", LOCK_PATH, None, 2, None),
    ("an image-only directory is not compared", LOCK_PATH, image_tests, 2, None),
    ("image_only is a directory prefix, not a name prefix", LOCK_PATH, image_tests_named_like_src, 1,
     "vstd: testsuite.rs is missing from the vendored copy"),
    ("one changed byte is refused", LOCK_PATH, flip, 1, "vstd: src/lib.rs differs from the verified source"),
    ("a file only in the vendored copy is refused", LOCK_PATH, extra, 1, "vstd: src/extra.rs is only in the vendored copy"),
    ("a file missing from the vendored copy is refused", LOCK_PATH, missing, 1,
     "verus_builtin: src/lib.rs is missing from the vendored copy"),
    ("a registry source is refused", LOCK_REGISTRY, None, 1, "verus_builtin: Cargo.lock resolves it from"),
    ("a vendored crate linked at the image tree is refused", LOCK_PATH, vendored_link_to_image, 1,
     "vstd: "),
    ("a patch pointing elsewhere is refused", LOCK_PATH, patch_elsewhere, 1,
     "verus_builtin: the root Cargo.toml does not patch it to third_party/verus/verus_builtin"),
    ("a member without a policy entry is refused", LOCK_EXTRA, None, 2, "verus_syn: no entry in policy/verus-pairing.toml"),
    ("a missing image tree is refused", LOCK_PATH, no_image, 1, "verus_builtin: image tree"),
    ("a missing vendored tree is refused", LOCK_PATH, no_vendor, 1, "verus_builtin: third_party/verus/verus_builtin is missing"),
    ("a policy entry not in Cargo.lock is refused", LOCK_PATH, unlisted_policy, 2,
     "verus_prettyplease: listed in the policy but not in Cargo.lock"),
]


def main() -> int:
    failures = 0
    for name, lock, mutate, want_paired, needle in CASES:
        with tempfile.TemporaryDirectory() as d:
            errors, paired = build(pathlib.Path(d), lock, mutate)
        if needle is None:
            ok = not errors and paired == want_paired
        else:
            ok = paired == want_paired and any(needle in e for e in errors)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: paired={paired} errors={errors}")
    print(f"VERUS-PAIRING-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
