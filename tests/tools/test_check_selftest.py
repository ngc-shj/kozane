"""check-selftest must read the whole `check` rule the way make does.

Usage: python3 tests/tools/test_check_selftest.py
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "tools/check-selftest"


def load():
    g = {"__file__": str(SRC), "__name__": "check_selftest"}
    exec(compile(SRC.read_text(), str(SRC), "exec"), g)
    return g


def main() -> int:
    g = load()
    gates, err = g["check_gates"], g["GateParseError"]
    failures = 0

    def expect(name, text, want):
        nonlocal failures
        try:
            got = gates(text)
        except err:
            got = "error"
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: got {got} want {want}")

    expect("prerequisites and $(MAKE) lines", "check: a\n\t$(MAKE) b c\n\t$(MAKE) d\n", ["a", "b", "c", "d"])
    expect("blank line inside the recipe", "check:\n\t$(MAKE) a\n\n\t$(MAKE) b\n", ["a", "b"])
    expect("comment line inside the recipe", "check:\n\t$(MAKE) a\n# note\n\t$(MAKE) b\n", ["a", "b"])
    expect("raw command after a blank line", "check:\n\t$(MAKE) a\n\n\ttools/foo\n", "error")
    expect("raw command", "check:\n\ttools/foo\n", "error")
    expect("recipe ends at the next rule", "check:\n\t$(MAKE) a\nother:\n\ttools/foo\n", ["a"])
    expect("no check rule", "all:\n\t$(MAKE) a\n", "error")
    print("CHECK-SELFTEST-FIXTURES 7")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
