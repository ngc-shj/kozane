"""check-selftest must read the whole `check` rule the way make does.

Usage: python3 tests/tools/test_check_selftest.py
"""

import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

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
    ran = 0

    def expect(name, text, want):
        nonlocal failures, ran
        ran += 1
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
    expect("error-ignore prefix on a gate line", "check:\n\t-$(MAKE) a\n", "error")
    expect("error-ignore after @", "check:\n\t@-$(MAKE) a\n", "error")
    expect("allowed @ prefix", "check:\n\t@$(MAKE) a\n", ["a"])
    # sync_tree (the warm selftest tree): every case must start from the
    # real tree's sources, and cargo must see what changed.
    sync = g["sync_tree"]

    def synced(name, setup, check):
        nonlocal failures, ran
        ran += 1
        with tempfile.TemporaryDirectory() as d:
            src, dst = pathlib.Path(d) / "src", pathlib.Path(d) / "dst"
            src.mkdir()
            (src / "a.rs").write_text("a\n")
            (src / "dir").mkdir()
            (src / "dir/b.rs").write_text("b\n")
            sync(src, dst)
            old = os.stat(dst / "a.rs").st_mtime_ns
            os.utime(dst / "a.rs", ns=(old - 10**9, old - 10**9))
            setup(src, dst)
            # The copy's last build ran after the mutation: a restored file
            # must be newer than that, not carry the source's older time.
            os.utime(src / "a.rs", ns=(old - 10**9, old - 10**9))
            before = time.time_ns()
            sync(src, dst)
            why = check(src, dst, old - 10**9, before)
        failures += bool(why)
        print(f"{'ok  ' if not why else 'FAIL'} sync_tree: {name}{': ' + why if why else ''}")

    def same(src, dst):
        names = lambda r: sorted(str(p.relative_to(r)) for p in r.rglob("*") if "target" not in p.parts)
        if names(src) != names(dst):
            return f"trees differ: {names(src)} vs {names(dst)}"
        for f in src.rglob("*"):
            if f.is_file() and (f.read_bytes() != (dst / f.relative_to(src)).read_bytes()):
                return f"{f.name} differs"
        return ""

    synced("a mutated file is restored with a fresh mtime",
           lambda s, d: (d / "a.rs").write_text("mutated\n"),
           lambda s, d, t, now: same(s, d) or ("" if os.stat(d / "a.rs").st_mtime_ns >= now - 10**7
                                               else "mtime not refreshed"))
    synced("an unchanged file keeps its mtime", lambda s, d: None,
           lambda s, d, t, now: same(s, d) or ("" if os.stat(d / "a.rs").st_mtime_ns == t else "mtime changed"))
    synced("a file a case added is deleted", lambda s, d: (d / "dir/new.rs").write_text("x\n"), lambda s, d, t, now: same(s, d))
    synced("a SKIP dir in the copy is kept",
           lambda s, d: ((d / "target").mkdir(), (d / "target/obj").write_text("o\n")),
           lambda s, d, t, now: "" if (d / "target/obj").exists() else "target removed")
    synced("a mode change is synced", lambda s, d: (s / "a.rs").chmod(0o755),
           lambda s, d, t, now: "" if os.stat(d / "a.rs").st_mode & 0o777 == 0o755 else "mode not synced")
    synced("a dir replaced by a file is replaced",
           lambda s, d: (shutil.rmtree(s / "dir"), (s / "dir").write_text("now a file\n")), lambda s, d, t, now: same(s, d))
    # A timed-out case fails even with its needle in the partial output; the
    # same output with an ordinary failure passes (the allow side).
    def timed(name, code, want):
        nonlocal failures, ran
        ran += 1
        with tempfile.TemporaryDirectory() as d:
            saved = (g["warm_tree"], g["run_make"])
            g["warm_tree"] = lambda: pathlib.Path(d)
            g["run_make"] = lambda tree, *targets: subprocess.CompletedProcess(["make"], code, "selftest-needle\n", "")
            g["CASES"]["selftest-fixture"] = (["unit"], lambda t: None, "selftest-needle")
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    got = g["run_case"]("selftest-fixture")
            finally:
                g["warm_tree"], g["run_make"] = saved
                del g["CASES"]["selftest-fixture"]
        ok = got == want
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} run_case: {name}: got {got} want {want}")

    timed("a timed-out case fails though its needle printed", g["TIMED_OUT"], False)
    timed("an ordinary failure with the needle passes", 2, True)

    # run_make itself: a make that never ends is killed with its group and
    # reported as TIMED_OUT; one that fails keeps its own code.
    def stub_make(name, body, want_code, want_err):
        nonlocal failures, ran
        ran += 1
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "make"
            stub.write_text(f"#!/bin/sh\n{body}\n")
            stub.chmod(0o755)
            saved = (g["CASE_TIMEOUT_S"], g["MAKE_ENV"])
            g["CASE_TIMEOUT_S"] = 1
            g["MAKE_ENV"] = {**saved[1], "PATH": f"{d}:{saved[1].get('PATH', '')}"}
            try:
                out = g["run_make"](pathlib.Path(d))
            finally:
                g["CASE_TIMEOUT_S"], g["MAKE_ENV"] = saved
        ok = out.returncode == want_code and want_err in out.stderr
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} run_make: {name}: code {out.returncode}")

    stub_make("a make that never ends times out", "exec tail -f /dev/null", g["TIMED_OUT"], "timed out")
    stub_make("a failing make keeps its code", "exit 2", 2, "")

    # bolero's crash inputs are cleared at any depth, but not inside a SKIP
    # dir (a target dir is the build's own).
    ran += 1
    with tempfile.TemporaryDirectory() as d:
        t = pathlib.Path(d)
        for rel in ("crates/a/src/__fuzz__/x/crashes/c1", "crashes/c2", "target/crashes/keep"):
            (t / rel).parent.mkdir(parents=True, exist_ok=True)
            (t / rel).write_text("x\n")
        g["clear_crashes"](t)
        left = sorted(str(p.relative_to(t)) for p in t.rglob("*") if p.is_file())
    ok = left == ["target/crashes/keep"]
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} clear_crashes: crash inputs removed: left {left}")
    print(f"CHECK-SELFTEST-FIXTURES {ran}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
