"""The integration harness's signal holding must work while helper threads
are alive (code review F-R5-1/S5-1): a stop signal sent to the process
during `signals_held` waits until the teardown finished, then ends the run.

Usage: python3 tests/tools/test_harness_signals.py   (in the dev container)
Prints "HARNESS-SIGNAL-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Runs in a child process: it installs the harness's handler and is killed
# by the signal if holding fails.
CHILD = r"""
import importlib.util, os, signal, sys, threading, time
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
signal.signal(signal.SIGTERM, run.exit_on_signal)
helper = threading.Thread(target=lambda: time.sleep(5), daemon=True)
run.start_without_stop_signals(helper)
if threading.active_count() < 2:
    print("NO-HELPER-THREAD")  # the fixture would prove nothing
    sys.exit(3)
steps = 0
try:
    with run.signals_held():
        os.kill(os.getpid(), signal.SIGTERM)
        for _ in range(5):
            time.sleep(0.02)
            steps += 1
except SystemExit as e:
    print(f"steps={steps} exit={e.code}")
    sys.exit(0)
print(f"steps={steps} signal lost")
"""

CASES = [
    # The teardown completes, then the held signal ends the run.
    ("signal held across a teardown while a helper thread runs", "steps=5 exit=143"),
]


def threads_started_only_through_the_helper() -> list:
    """A thread started any other way would bring back F-R5-1 silently: its
    signal mask lets a stop signal through mid-teardown."""
    import re
    src = (ROOT / "tests/integration/run.py").read_text()
    starts = [m.start() for m in re.finditer(r"\.start\(\)", src)]
    helper = src.index("def start_without_stop_signals")
    helper_end = src.index("\n\n\n", helper)
    stray = [src.count("\n", 0, i) + 1 for i in starts if not helper <= i < helper_end]
    return [f"run.py line {n}: thread started outside start_without_stop_signals" for n in stray]


def main() -> int:
    failures = 0
    errors = threads_started_only_through_the_helper()
    print(f"{'ok  ' if not errors else 'FAIL'} threads start only through start_without_stop_signals: {errors or 'ok'}")
    failures += bool(errors)
    for name, want in CASES:
        r = subprocess.run([sys.executable, "-c", CHILD, str(ROOT / "tests/integration/run.py")],
                           capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: rc={r.returncode} {r.stdout.strip()!r} {r.stderr.strip()[-200:]!r}")
    print(f"HARNESS-SIGNAL-FIXTURES {len(CASES) + 1}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
