"""tools/kani-guarded and tools/kani-harness (post-M6 plan P4(c), T14).

No real Kani or cbmc runs: KOZANE_KANI_GATE points both tools at a stub
gate, and the "cbmc" it starts is a script on PATH that execs python3 with
argv[0] "cbmc-fixture-<pid>" (KOZANE_KANI_CBMC), allocates a few MiB and
blocks. The RSS decision is
checked against fixture /proc trees; the live cases prove the guard's own
message, the timeout's group kill and the --exact pass-through, each with
an allow side, and that no stub process survives.

Usage: python3 tests/tools/test_kani_guard.py
Prints "KANI-GUARD-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
GUARDED = ROOT / "tools/kani-guarded"
HARNESS = ROOT / "tools/kani-harness"
# The stub cbmc's argv[0], and the only name the live runs stop: the host
# runs real Kani, and a broken descendant filter (a red-proof mutant) once
# sent a real cbmc SIGTERM.
FAKE_CBMC = f"cbmc-fixture-{os.getpid()}"
# Bounds a hang only; every live case finishes in a few seconds.
RUN_BOUND_S = 60

GATE = r"""#!/bin/bash
# Stub kani-gate.sh. guard: start cbmc and pass on its code. tree: a child
# with a grandchild, all blocking. filter: kani's harness filter, a prefix
# match unless --exact.
echo $$ > "$FAKE_DIR/gate.pid"
echo $PPID > "$FAKE_DIR/guarded.pid"
echo "$@" > "$FAKE_DIR/gate.args"
case $FAKE_MODE in
guard)
    cbmc --fixture &
    wait $!; rc=$?
    [ $rc -eq 0 ] && echo "Complete - 1 successfully verified harnesses, 0 failures, 1 total."
    exit $rc;;
tree)
    bash -c 'sleep 60 & echo $! > "$FAKE_DIR/grandchild.pid"; wait' &
    echo $! > "$FAKE_DIR/child.pid"
    wait;;
filter)
    want= exact=
    while [ $# -gt 0 ]; do
        case $1 in --harness) want=$2; shift;; --exact) exact=1;; esac
        shift
    done
    n=0
    for h in proofs::h proofs::h_long; do
        if [ "$h" = "$want" ] || { [ -z "$exact" ] && [ "${h#"$want"}" != "$h" ]; }; then
            echo "Checking harness $h..."; n=$((n + 1))
        fi
    done
    echo "Complete - $n successfully verified harnesses, 0 failures, $n total.";;
esac
"""

CBMC = r"""#!/bin/bash
echo $$ > "$FAKE_DIR/cbmc.pid"
exec -a "$KOZANE_KANI_CBMC" python3 -c '
import os, sys, time
block = b"\x01" * (int(os.environ["FAKE_MIB"]) << 20)
time.sleep(float(os.environ["FAKE_HOLD_S"]))
'
"""


def load(path: pathlib.Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


def fake_proc(root: pathlib.Path, procs: dict) -> pathlib.Path:
    """A /proc-shaped tree: pid -> (ppid, argv, VmRSS KiB)."""
    for pid, (ppid, argv, rss) in procs.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "status").write_text(f"Name:\tx\nPPid:\t{ppid}\nVmRSS:\t  {rss} kB\n")
    (root / "self").mkdir()
    return root


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return pathlib.Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except (ProcessLookupError, FileNotFoundError):
        return False


def survivors(d: pathlib.Path, names) -> list:
    """The stub processes still alive, waiting (bounded) for deaths already
    signalled rather than judging the first look."""
    pids = {n: int((d / f"{n}.pid").read_text()) for n in names if (d / f"{n}.pid").exists()}
    deadline = time.monotonic() + 10
    while any(alive(p) for p in pids.values()) and time.monotonic() < deadline:
        time.sleep(0.05)
    return [n for n, p in pids.items() if alive(p)] + [n for n in names if n not in pids]


def stub_env(d: pathlib.Path, mode: str, mib: int = 4, hold: float = 60) -> dict:
    for name, text in (("gate", GATE), ("cbmc", CBMC)):
        (d / name).write_text(text)
        (d / name).chmod(0o755)
    return {**os.environ, "KOZANE_KANI_GATE": str(d / "gate"), "PATH": f"{d}:{os.environ['PATH']}",
            "KOZANE_KANI_CBMC": FAKE_CBMC, "FAKE_DIR": str(d), "FAKE_MODE": mode, "FAKE_MIB": str(mib), "FAKE_HOLD_S": str(hold)}


def run(cmd: list, env: dict) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
                            start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=RUN_BOUND_S)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, 9)
        out, _ = proc.communicate()
        out += "\nfixture: bound exceeded\n"
    return subprocess.CompletedProcess(cmd, proc.returncode, out, "")


def main() -> int:
    guarded = load(GUARDED, "kani_guarded")
    failures = 0
    ran = 0

    def check(name, ok, detail=""):
        nonlocal failures, ran
        ran += 1
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")

    # The RSS decision on fixture /proc trees. 10 is the gate; 20 its
    # cargo; 30 and 31 cbmc under it (one by full path); 40 a cbmc of
    # another run; 50 a big non-cbmc process under the gate.
    tree = {10: (1, ["bash", "kani-gate.sh"], 3000), 20: (10, ["cargo", "kani"], 9000),
            30: (20, ["cbmc", "--json-ui"], 600), 31: (20, ["/opt/kani/bin/cbmc"], 500),
            40: (1, ["cbmc"], 900000), 50: (10, ["kani-driver"], 800000)}
    with tempfile.TemporaryDirectory() as d:
        procs = guarded.read_procs(fake_proc(pathlib.Path(d), tree))
        decide = guarded.cbmc_over_guard
        check("read_procs reads ppid, argv[0] and VmRSS", procs.get(31) == (20, "/opt/kani/bin/cbmc", 500),
              str(procs.get(31)))
        check("only this run's cbmc count, and past the guard both stop",
              decide(procs, 10, 1099) == (1100, [30, 31]), str(decide(procs, 10, 1099)))
        check("at the guard nothing stops", decide(procs, 10, 1100) == (1100, []), str(decide(procs, 10, 1100)))

    # Live: the stub cbmc holds 24 MiB plus python's own; the guard is
    # 20 MiB. The allow side runs the same stub under a 4 GiB guard.
    names = ["gate", "cbmc"]
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        out = run([str(GUARDED), "fixture", "proofs::h", "20480", "--poll", "0.1", "--grace", "5",
                   "--log", str(d / "kg.log")], stub_env(d, "guard", mib=24, hold=30))
        left = survivors(d, names)
        check("the guard stops a cbmc past it, no stub survives",
              "GUARD fixture proofs::h: cbmc RSS" in out.stdout and out.returncode != 0 and not left,
              f"rc {out.returncode}, survivors {left}, output {out.stdout.strip()[-300:]!r}")
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        out = run([str(GUARDED), "fixture", "proofs::h", str(4 << 20), "--poll", "0.1",
                   "--log", str(d / "kg.log")], stub_env(d, "guard", mib=24, hold=1))
        check("under the guard the run completes",
              "GUARD" not in out.stdout and out.returncode == 0 and "rc=0 Complete - 1" in out.stdout,
              f"rc {out.returncode}, output {out.stdout.strip()[-300:]!r}")

    # The timeout stops kani-guarded, the gate, its child and grandchild.
    names = ["guarded", "gate", "child", "grandchild"]
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        out = run([str(HARNESS), "-p", "fixture", "proofs::h", "1", "--grace", "0.5", "--log", str(d / "kg.log")],
                  stub_env(d, "tree"))
        left = survivors(d, names)
        check("the timeout kills the whole group",
              "proofs::h TIMEOUT after 1s" in out.stdout and out.returncode == 124 and not left,
              f"rc {out.returncode}, survivors {left}")

    # --exact reaches the gate, so one harness runs; without it, the prefix
    # match runs two (the allow side: the stub does filter).
    for exact, want in ((True, 1), (False, 2)):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            out = run([str(HARNESS), "-p", "fixture", "proofs::h", "30", "--log", str(d / "kg.log")]
                      + (["--exact"] if exact else []), stub_env(d, "filter"))
            got = (d / "kg.log").read_text().count("Checking harness") if (d / "kg.log").exists() else None
            check(f"{'with' if exact else 'without'} --exact {want} harness(es) run",
                  got == want and out.returncode == 0, f"ran {got}, gate args {(d / 'gate.args').read_text().strip()!r}")
    print(f"KANI-GUARD-FIXTURES {ran}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
