"""The integration suite's C8 stack-headroom judgment (M4 Phase 3, T15),
on fake console text: each clause of `stack_headroom_case` must refuse on
its own, and the measured figures must pass.

Usage: python3 tests/tools/test_stack_headroom.py   (in the dev container)
Prints "STACK-HEADROOM-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("run", ROOT / "tests/integration/run.py")
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

SIZE = 0x20000
KIB = 1024


class Console:
    def __init__(self, text: str):
        self.text = text

    def count(self, pattern: str, since: int = 0) -> list:
        return re.findall(pattern, self.text[since:])


def lines(pq: int, pqkey: int) -> str:
    return (f"audit: src=pq KeyStackHighWater bytes={pqkey} lost=0\n"
            f"audit: src=pq StackHighWater bytes={pq} lost=0\n")


# The measured run (M4 Phase 3): pq 61,808 B, pqkey 100,096 B.
MEASURED = lines(61808, 100096)

# (name, console text, expected Fail fragment or None for accept)
CASES = [
    ("the measured figures pass", MEASURED, None),
    ("exactly the minimum free passes", lines(61808, SIZE - run.STACK_HEADROOM_MIN), None),
    ("one byte under the minimum free fails", lines(61808, SIZE - run.STACK_HEADROOM_MIN + 1),
     "pqkey: 16383 B of stack free, want at least 16384"),
    ("no report from pq fails", "audit: src=pq KeyStackHighWater bytes=100096 lost=0\n",
     "pq: no stack high-water report"),
    ("no report from pqkey fails", "audit: src=pq StackHighWater bytes=61808 lost=0\n",
     "pqkey: no stack high-water report"),
    ("a mark shallower than the PD's own scrub fails", lines(61808, 90 * KIB),
     "pqkey: stack high-water 92160 B is below its own scrub depth 98304"),
    ("pq's mark shallower than its encaps scrub fails", lines(39 * KIB, 100096),
     "pq: stack high-water 39936 B is below its own scrub depth 40960"),
    ("a mark exactly at the scrub depth passes", lines(40 * KIB, 96 * KIB), None),
    ("a garbled pq report fails", MEASURED + "audit: src=pq StackHighWater bytes=6audit: x\n",
     "pq: 1 of 2 stack high-water reports garbled"),
    ("a garbled pqkey report fails", MEASURED + "audit: src=pq KeyStackHighWater bytes=1audit: x\n",
     "pqkey: 1 of 2 stack high-water reports garbled"),
    ("the deepest of several reports counts", MEASURED + "audit: src=pq StackHighWater bytes=126976 lost=0\n",
     "pq: 4096 B of stack free"),
]


def patched_size(text: str):
    """The case with pq's STACK_SIZE reading other than the system file's."""
    saved = run.pd_stack_const
    run.pd_stack_const = lambda pd: 0x1c000 if pd == "pq" else saved(pd)
    try:
        run.stack_headroom_case(Console(text))
    finally:
        run.pd_stack_const = saved


def main() -> int:
    failures = 0
    cases = CASES + [("a STACK_SIZE other than the system file's fails", MEASURED,
                      "pq: STACK_SIZE 114688 paints other than the system file's 131072", patched_size)]
    for name, text, want, *how in cases:
        try:
            (how[0] if how else lambda t: run.stack_headroom_case(Console(t)))(text)
            got = None
        except run.Fail as e:
            got = str(e)
        ok = (got is None) if want is None else (got is not None and want in got)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got or 'accepted'}")
    print(f"STACK-HEADROOM-FIXTURES {len(cases)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
