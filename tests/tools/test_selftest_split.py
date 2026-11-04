"""tools/selftest-split: the partitions follow the Makefile, and the merge
accepts only logs that together are one full selftest run (post-M6 plan
P4(b)).

Each merge fixture is the valid split with one defect: the valid split
merges clean (the allow side), so each refusal is that defect's.

Usage: python3 tests/tools/test_selftest_split.py
Prints "SELFTEST-SPLIT-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import fcntl
import importlib.machinery
import importlib.util
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "tools/selftest-split"


def load(path: pathlib.Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


COMMIT = "c0ffee"
CASES = {"a", "b", "c"}


IMAGE = "ca72 934a"


def log(part, i, n, results, commit=COMMIT, exited=True, layers=True, image=IMAGE):
    text = f"SELFTEST-SPLIT-INSTANCE {part} {i}/{n} commit={commit}\n"
    if image:
        text += f"SELFTEST-SPLIT-IMAGE {image}\n"
    text += f"SELFTEST-SPLIT-ASSIGNED {' '.join(results)}\n"
    for case, ok in results.items():
        text += f"{'ok  ' if ok else 'FAIL'} {case}: exit=2\nSELFTEST-CASE {case} {'ok' if ok else 'FAIL'}\n"
    if layers:
        text += f"SELFTEST-LAYERS {sum(results.values())}\n"
    if exited:
        text += f"SELFTEST-SPLIT-EXIT {0 if all(results.values()) else 1}\n"
    return text


def valid():
    return {"qemu.log": log("qemu", 1, 1, {"a": True}), "rest-1.log": log("rest", 1, 2, {"b": True}),
            "rest-2.log": log("rest", 2, 2, {"c": True})}


def main() -> int:
    split = load(SRC, "selftest_split")
    st = split.load_selftest()
    failures = 0
    ran = 0

    def merged(name, logs, needle):
        nonlocal failures, ran
        ran += 1
        problems, failed, passed = split.merge(logs, CASES, COMMIT)
        ok = any(needle in p for p in problems) if needle else (not problems and not failed and passed == 3)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} merge: {name}: {problems or 'clean'}")

    merged("the valid split merges clean", valid(), None)
    crashed = valid()
    crashed["rest-2.log"] = log("rest", 2, 2, {"c": True}, exited=False, layers=False)
    merged("a crashed instance", crashed, "rest-2.log: instance did not exit")
    refused = valid()
    refused["rest-2.log"] = log("rest", 2, 2, {"c": True}, layers=False)
    merged("an instance that printed no SELFTEST-LAYERS", refused, "rest-2.log: instance printed no SELFTEST-LAYERS")
    dup = valid()
    dup["rest-2.log"] = log("rest", 2, 2, {"c": True, "a": True})
    merged("a duplicate case", dup, "a: ran 2 times")
    missing = valid()
    del missing["rest-2.log"]
    merged("a missing case", missing, "c: never ran")
    other = valid()
    other["rest-2.log"] = log("rest", 2, 2, {"c": True}, commit="deadbeef")
    merged("a commit mismatch", other, "instances ran different commits")
    # M9 plan C6 (image identity): one IMAGE and QEMU value across the logs.
    mixed = valid()
    mixed["rest-2.log"] = log("rest", 2, 2, {"c": True}, image="ffff 934a")
    merged("two images in one merge", mixed, "mixed images")
    unnamed = valid()
    unnamed["rest-2.log"] = log("rest", 2, 2, {"c": True}, image=None)
    merged("an instance with no image record", unnamed, "rest-2.log: no image record")

    # A failed case is no structural problem, but it fails the merge.
    ran += 1
    red = valid()
    red["rest-2.log"] = log("rest", 2, 2, {"c": False})
    problems, failed, passed = split.merge(red, CASES, COMMIT)
    ok = not problems and failed == ["c"] and passed == 2
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} merge: a failed case is reported: failed {failed}, problems {problems}")

    # Classification over a Makefile whose rule head and $(MAKE) call each
    # continue onto the next line.
    ran += 1
    makefile = ("gate: a \\\n\tpds\n"
                "gate2: | $(counts)\n\t$(MAKE) \\\n\t\timage MICROKIT_CONFIG=release\n"
                "image: kernel-config pds\n"
                "plain: a\n\techo $(MAKE) is not followed after a\n")
    cases = {"x": (["gate"], None, ""), "y": (["gate2"], None, ""), "z": (["plain"], None, "")}
    parts = split.classify(cases, split.makefile_deps(makefile, st.rule_prerequisites), st.closure)
    ok = parts["pds"] == ["x", "y"] and parts["rest"] == ["z"]
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} classify: multi-line rule head and $(MAKE) call: {parts}")

    # The real Makefile and cases: integration-count runs the full suite;
    # the KVM and kzc gates' cases get their own partitions (M9 plan C6).
    ran += 1
    _, real, _ = split.selftest_parts(4)
    ok = "integration-count" in real["qemu"]
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} classify: integration-count is a qemu case")
    ran += 1
    ok = "kvm-proof" in real["kvm"] and "kzc-cookie" in real["kzc"] \
        and not set(real["kvm"]) & set(real["qemu"]) and not set(real["kzc"]) & set(real["qemu"])
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} classify: test-kvm and test-kzc cases are kvm and kzc cases: "
          f"kvm {real['kvm']}, kzc {real['kzc']}")

    # The partition locks: kvm never beside solver (or a proof run), kzc
    # never beside qemu; each refusal names the holder. The allow side: with
    # nothing held, both take their locks.
    def locked(name, part, holder, held_lock, needle):
        nonlocal failures, ran
        ran += 1
        with tempfile.TemporaryDirectory() as d:
            paths = {k: pathlib.Path(d) / f"{k}.lock" for k in ("host", "solver", "proof")}
            other = None
            if holder:
                other = open(paths[held_lock], "w")
                fcntl.flock(other, fcntl.LOCK_EX)
                other.write(f"{holder}\n")
                other.flush()
            try:
                got = split.take_locks(part, paths)
                for f in got:
                    f.close()
                result = "taken"
            except SystemExit as e:
                result = str(e)
            finally:
                if other:
                    other.close()
        ok = (needle in result) if needle else result == "taken"
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} locks: {name}: {result}")

    locked("kvm with nothing held", "kvm", None, None, None)
    locked("kzc with nothing held", "kzc", None, None, None)
    locked("kvm beside solver", "kvm", "solver", "solver", "selftest-split: kvm beside solver")
    locked("kvm beside a proof run", "kvm", "kani-gate", "proof", "selftest-split: kvm beside kani-gate")
    locked("kvm beside qemu", "kvm", "qemu", "host", "selftest-split: kvm beside qemu")
    locked("kzc beside qemu", "kzc", "qemu", "host", "selftest-split: kzc beside qemu")

    # ... and every case lands in exactly one instance at any N.
    ran += 1
    counts = {}
    for n in (1, 4, 500):
        for _, _, _, names in split.instances(real, n):
            for case in names:
                counts[(n, case)] = counts.get((n, case), 0) + 1
    ok = all(counts.get((n, c)) == 1 for n in (1, 4, 500) for c in st.CASES) and len(counts) == 3 * len(st.CASES)
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} instances: every case exactly once at N = 1, 4, 500")
    print(f"SELFTEST-SPLIT-FIXTURES {ran}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
