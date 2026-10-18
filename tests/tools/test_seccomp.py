"""docker/make-seccomp.py --check must accept the committed profile and
reject each one-change mutation of it (M2 plan review T14).

Usage: python3 tests/tools/test_seccomp.py
Prints "SECCOMP-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("make_seccomp", ROOT / "docker/make-seccomp.py")
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)
PROFILE = (ROOT / "docker/seccomp-userns.json").read_text()


def mutate(fn):
    def run():
        p = json.loads(PROFILE)
        fn(p)
        return ms.check(json.dumps(p))
    return run


def set_arg(key, value):
    return mutate(lambda p: p["syscalls"][-1]["args"][0].__setitem__(key, value))


CASES = [
    ("committed profile accepted", True, lambda: ms.check(PROFILE)),
    ("extra clone flag allowed", False, set_arg("value", 0x50000000 | 0x00020000)),
    ("masked compare instead of EQ", False, set_arg("op", "SCMP_CMP_MASKED_EQ")),
    ("argument filter removed", False, mutate(lambda p: p["syscalls"][-1].pop("args"))),
    ("rule appended after ours", False,
     mutate(lambda p: p["syscalls"].append({"names": ["mount"], "action": "SCMP_ACT_ALLOW"}))),
    ("base profile changed", False, mutate(lambda p: p.__setitem__("defaultAction", "SCMP_ACT_ALLOW"))),
    ("base rule dropped", False, mutate(lambda p: p["syscalls"].pop(0))),
]


def main() -> int:
    failures = 0
    for name, accept, run in CASES:
        errors = run()
        ok = (not errors) == accept
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {errors or 'accepted'}")
    print(f"SECCOMP-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
