"""tools/check-manifest must accept exactly matching counts and reject each
kind of drift with its own message (code review R4-T1, T5-1, T5-3), and
require one IMAGE and one QEMU record per counts directory (M9 plan C6).

Usage: python3 tests/tools/test_check_manifest.py
Prints "CHECK-MANIFEST-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/check-manifest"
MANIFEST = "# comment\nA-TESTS 5\nB-TESTS 2\n"
MANIFEST_WITH_ZERO = MANIFEST + "Z-TESTS 0\n"
MANIFEST_WITH_DUP = MANIFEST + "A-TESTS 5\n"

IDENTITY = "IMAGE 1111\nQEMU aaaa\n"

# (name, counts file text, expected message or None for accept). Each case
# also gets IDENTITY in a file of its own, unless it sets `identity`.
CASES = [
    ("equal counts accepted", "A-TESTS 5\nB-TESTS 2\n", None),
    ("fewer than listed refused", "A-TESTS 4\nB-TESTS 2\n", "A-TESTS: 4 < manifest 5"),
    ("more than listed refused", "A-TESTS 6\nB-TESTS 2\n", "A-TESTS: 6 > manifest 5 (raise the manifest to 6)"),
    ("missing key refused", "A-TESTS 5\n", "B-TESTS: missing (gate did not run)"),
    ("zero refused", "A-TESTS 0\nB-TESTS 2\n", "A-TESTS: 0 < manifest 5"),
    # A manifest line of 0 does not make a count of 0 acceptable.
    ("zero refused even when listed as zero", "A-TESTS 5\nB-TESTS 2\nZ-TESTS 0\n", "Z-TESTS: 0 < manifest 0"),
    ("unlisted key refused", "A-TESTS 5\nB-TESTS 2\nC-TESTS 3\n", "C-TESTS: 3 not in the manifest (add it)"),
    ("key repeated within one counts file refused", "A-TESTS 5\nB-TESTS 2\nA-TESTS 7\n",
     "A-TESTS: reported twice by gate"),
    ("duplicate key across counts files refused", "A-TESTS 5\nB-TESTS 2\n", "A-TESTS: reported by both"),
    ("manifest key listed twice refused", "A-TESTS 5\nB-TESTS 2\n", "A-TESTS: listed twice in the manifest"),
    ("unlisted zero gets actionable advice", "A-TESTS 5\nB-TESTS 2\nC-TESTS 0\n",
     "C-TESTS: 0, the gate counted nothing"),
]

# (name, identity file texts, expected message or None for accept); the
# counts themselves match the manifest.
IDENTITY_CASES = [
    ("the same identity written twice is one record", [IDENTITY, IDENTITY], None),
    ("a missing IMAGE refused", ["QEMU aaaa\n"], "check-manifest: IMAGE missing"),
    ("a missing QEMU refused", ["IMAGE 1111\n"], "check-manifest: QEMU missing"),
    ("two IMAGE values refused", [IDENTITY, "IMAGE 2222\n"], "check-manifest: IMAGE: two values"),
    ("two QEMU values in one file refused", [IDENTITY + "QEMU bbbb\n"], "check-manifest: QEMU: two values"),
]

# --compare-identity over two counts directories' identity files.
COMPARE_CASES = [
    ("equal identities compare equal", IDENTITY, IDENTITY, None),
    ("another image refused", IDENTITY, "IMAGE 2222\nQEMU aaaa\n", "ran on different images"),
    ("another QEMU refused", IDENTITY, "IMAGE 1111\nQEMU bbbb\n", "ran on different images"),
    ("a directory without records refused", IDENTITY, "", "IMAGE missing"),
    # Each value keeps its key (code review F1): a QEMU-only difference names
    # QEMU with that directory's build ID, and swapped values are not equal.
    # (values that sort the other way round, so a sorted tuple mislabels them)
    ("a QEMU difference is labelled QEMU", "IMAGE ffff\nQEMU 0000\n", "IMAGE ffff\nQEMU 1111\n",
     "{'IMAGE': 'ffff', 'QEMU': '1111'}"),
    ("swapped values refused", IDENTITY, "IMAGE aaaa\nQEMU 1111\n", "ran on different images"),
]


def load_tool():
    loader = importlib.machinery.SourceFileLoader("check_manifest", str(TOOL))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def digest_cases() -> list:
    """IMAGE over a tree (D-27): the same bytes are one image whatever
    their mtimes; other bytes, even of the same size, another path or a
    symlink's other target, to a file or a directory, are another image."""
    tool = load_tool()
    results = []
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        db = d / "status"
        db.write_text("Package: x\n")
        tree = d / "opt"
        (tree / "a").mkdir(parents=True)
        f = tree / "a/file"
        f.write_text("bytes")
        (tree / "a/link").symlink_to("file")

        def digest() -> str:
            return tool.tree_digest(str(db), [str(tree)])

        first = digest()
        os.utime(f, ns=(1_793_687_763_208_809_344, 1_793_687_763_208_809_344))
        results.append(("the same bytes with another mtime are the same image", digest() == first))
        f.write_text("bytez")
        results.append(("other bytes of the same size are another image", digest() != first))
        f.write_text("bytes")
        f.rename(tree / "a/other")
        results.append(("another path is another image", digest() != first))
        (tree / "a/other").rename(f)
        (tree / "a/link").unlink()
        (tree / "a/link").symlink_to("other")
        results.append(("a symlink to another target is another image", digest() != first))
        (tree / "a/link").unlink()
        (tree / "a/link").symlink_to("file")
        (tree / "v1").mkdir()
        (tree / "v2").mkdir()
        (tree / "current").symlink_to("v1")
        before = digest()
        (tree / "current").unlink()
        (tree / "current").symlink_to("v2")
        results.append(("a directory symlink to another target is another image", digest() != before))

        def refused(f, want: str) -> bool:
            try:
                f()
            except SystemExit as e:
                return want in str(e)
            return False

        # Code review T6: examining nothing is a refusal, not an empty digest.
        results.append(("a missing image tree is refused",
                        refused(lambda: tool.tree_digest(str(db), [str(d / "absent")]), "image tree")))
        saved = os.environ.pop("MICROKIT_SDK", None)
        try:
            results.append(("IMAGE without MICROKIT_SDK is refused",
                            refused(tool.image_digest, "MICROKIT_SDK unset")))
        finally:
            if saved is not None:
                os.environ["MICROKIT_SDK"] = saved
    return results


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True)


def main() -> int:
    failures = 0
    for name, counts, want in CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            text = MANIFEST_WITH_ZERO if "Z-TESTS" in counts else MANIFEST_WITH_DUP if name.startswith("manifest") else MANIFEST
            (d / "manifest.txt").write_text(text)
            if name.startswith("duplicate"):
                (d / "counts").mkdir()
                (d / "counts" / "other").write_text("A-TESTS 4\n")
            (d / "counts").mkdir(exist_ok=True)
            (d / "counts" / "gate").write_text(counts)
            (d / "counts" / "gate.log").write_text("X-IGNORED 99\n")  # logs are not counts
            (d / "counts" / "identity").write_text(IDENTITY)
            r = run(d / "manifest.txt", d / "counts")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    for name, idents, want in IDENTITY_CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "manifest.txt").write_text(MANIFEST)
            (d / "counts").mkdir()
            (d / "counts" / "gate").write_text("A-TESTS 5\nB-TESTS 2\n")
            for i, text in enumerate(idents):
                (d / "counts" / f"identity-{i}").write_text(text)
            r = run(d / "manifest.txt", d / "counts")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    for name, a, b, want in COMPARE_CASES:
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            for sub, text in (("x", a), ("y", b)):
                (d / sub).mkdir()
                (d / sub / "identity").write_text(text)
            r = run("--compare-identity", d / "x", d / "y")
        ok = r.returncode == 0 and not r.stdout if want is None else r.returncode == 1 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={r.returncode} {r.stdout.strip()!r}")
    digests = digest_cases()
    for name, ok in digests:
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
    print(f"CHECK-MANIFEST-FIXTURES {len(CASES) + len(IDENTITY_CASES) + len(COMPARE_CASES) + len(digests)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
