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


GUARD_CHILD = r"""
import importlib.util, sys, threading
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
run.guard_thread_starts()
run.start_without_stop_signals(threading.Thread(target=lambda: None))
try:
    threading.Thread(target=lambda: None).start()
    print("plain start allowed")
except RuntimeError:
    print("plain start refused")
"""


IGNORE_CHILD = r"""
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
for s in run.STOP_SIGNALS:
    signal.signal(s, run.exit_on_signal)
real_signal, sent = signal.signal, []

def signal_then_other(s, h):
    old = real_signal(s, h)
    if h == signal.SIG_IGN and not sent:
        sent.append(signal.SIGTERM if s != signal.SIGTERM else signal.SIGHUP)
        os.kill(os.getpid(), sent[0])
    return old

signal.signal = signal_then_other
try:
    run.ignore_signals()
    print("teardown continued")
except SystemExit as e:
    print(f"cut short: exit {e.code}")
"""


def ignore_signals_has_no_window() -> list:
    """A signal landing between ignore_signals' per-signal calls must not
    end the final teardown (S6-1): it blocks all of them first."""
    r = subprocess.run([sys.executable, "-c", IGNORE_CHILD, str(ROOT / "tests/integration/run.py")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "teardown continued" not in r.stdout:
        return [f"ignore_signals let a signal through: rc={r.returncode} {r.stdout.strip()!r}"]
    return []


def threads_started_only_through_the_helper() -> list:
    """In the netns harness a thread started with stop signals unblocked
    would bring back F-R5-1; the run-time guard must refuse it and allow
    the helper's way."""
    r = subprocess.run([sys.executable, "-c", GUARD_CHILD, str(ROOT / "tests/integration/run.py")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "plain start refused" not in r.stdout:
        return [f"guard did not refuse a plain thread start: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
    return []


def main() -> int:
    failures = 0
    errors = threads_started_only_through_the_helper()
    print(f"{'ok  ' if not errors else 'FAIL'} the run-time guard refuses threads with unblocked stop signals: {errors or 'ok'}")
    failures += bool(errors)
    errors = ignore_signals_has_no_window()
    print(f"{'ok  ' if not errors else 'FAIL'} ignore_signals blocks before ignoring: {errors or 'ok'}")
    failures += bool(errors)
    for name, want in CASES:
        r = subprocess.run([sys.executable, "-c", CHILD, str(ROOT / "tests/integration/run.py")],
                           capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0 and want in r.stdout
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: rc={r.returncode} {r.stdout.strip()!r} {r.stderr.strip()[-200:]!r}")
    print(f"HARNESS-SIGNAL-FIXTURES {len(CASES) + 2}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
