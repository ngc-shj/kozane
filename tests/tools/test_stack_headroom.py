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


def lines(pq: int, pqkey: int, size_pq: int = SIZE, size_pqkey: int = SIZE) -> str:
    return (f"pqkey: stack high-water {pqkey:#x} of {size_pqkey:#x}\n"
            f"pq: stack high-water {pq:#x} of {size_pq:#x}\n")


# The measured run (M4 Phase 3): pq 61,808 B, pqkey 100,096 B.
MEASURED = lines(61808, 100096)

# (name, console text, expected Fail fragment or None for accept)
CASES = [
    ("the measured figures pass", MEASURED, None),
    ("exactly the minimum free passes", lines(61808, SIZE - run.STACK_HEADROOM_MIN), None),
    ("one byte under the minimum free fails", lines(61808, SIZE - run.STACK_HEADROOM_MIN + 1),
     "pqkey: 16383 B of stack free, want at least 16384"),
    ("no line from a PD fails", "pqkey: stack high-water 0x18700 of 0x20000\n",
     "pq: no stack high-water line"),
    ("a painted size other than the system file's fails", lines(61808, 100096, size_pq=0x1c000),
     "pq: probe painted [114688] bytes, the system file gives 131072"),
    ("a mark shallower than the PD's own scrub fails", lines(61808, 90 * KIB),
     "pqkey: stack high-water 92160 B is below its own scrub depth 98304"),
    ("a garbled line fails", MEASURED + "pq: stack high-water 0x1audit: x\n",
     "pq: 1 of 2 stack high-water lines garbled"),
    ("the deepest of several lines counts", MEASURED + "pqkey: stack high-water 0x1f000 of 0x20000\n",
     "pqkey: 4096 B of stack free"),
]


def main() -> int:
    failures = 0
    for name, text, want in CASES:
        try:
            run.stack_headroom_case(Console(text))
            got = None
        except run.Fail as e:
            got = str(e)
        ok = (got is None) if want is None else (got is not None and want in got)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got or 'accepted'}")
    print(f"STACK-HEADROOM-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
