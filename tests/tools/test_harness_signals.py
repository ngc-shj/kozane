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
        return [f"ignore_signals let a signal through: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
    return []


TEARDOWN_CHILD = r"""
import importlib.util, os, signal, sys, tempfile
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
for s in run.STOP_SIGNALS:
    signal.signal(s, run.exit_on_signal)
tmp = tempfile.mkdtemp(prefix="teardown-test-")
open(os.path.join(tmp, "secrets.bin"), "wb").write(b"key")
real_mask = signal.pthread_sigmask

def raising_once(how, mask):
    # As CPython does: the mask is set, then a pending handler raises.
    signal.pthread_sigmask = real_mask
    real_mask(how, mask)
    run.exit_on_signal(signal.SIGTERM, None)

signal.pthread_sigmask = raising_once
try:
    try:
        removed, held = run.final_teardown(tmp)
        print(f"removed={removed} gone={not os.path.exists(tmp)} held={getattr(held, 'code', None)}")
    except SystemExit as e:
        print(f"escaped exit {e.code}, gone={not os.path.exists(tmp)}")
finally:
    # The fixture's own key-bearing dir must not outlive a failing run.
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
"""


def final_teardown_holds_an_exit() -> list:
    """An exit raised as the final teardown blocks signals must wait until
    the key-bearing temp dir is removed (S8-2)."""
    r = subprocess.run([sys.executable, "-c", TEARDOWN_CHILD, str(ROOT / "tests/integration/run.py")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "removed=True gone=True held=143" not in r.stdout:
        return [f"final teardown did not hold the exit: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
    return []


MAIN_CHILD = r"""
import importlib.util, os, shutil, signal, sys, tempfile
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
mode = sys.argv[2]
tmp = tempfile.mkdtemp(prefix="main-test-")
open(os.path.join(tmp, "secrets.bin"), "wb").write(b"key")
run.tempfile.mkdtemp = lambda **_: tmp
run.preflight = lambda: None
def failing_build(_):
    raise run.Fail("build failed (fixture)")
run.build = failing_build
sys.argv = ["run.py"]
try:
    if mode == "entry":
        # A signal pending when main's teardown starts: its handler runs on
        # entry to final_teardown, before that function's own try.
        real = run.final_teardown
        calls = []
        def entering(tmp_dir):
            if not calls:
                calls.append(1)
                run.exit_on_signal(signal.SIGTERM, None)
            return real(tmp_dir)
        run.final_teardown = entering
    try:
        rc = run.main()
        print(f"returned {rc}, gone={not os.path.exists(tmp)}")
    except SystemExit as e:
        print(f"exit {e.code}, gone={not os.path.exists(tmp)}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
"""


def main_holds_and_reraises(mode: str, want: str):
    """main()'s teardown removes the key dir and then ends the run with the
    held exit; without a signal it returns the failure status."""
    def check() -> list:
        r = subprocess.run([sys.executable, "-c", MAIN_CHILD, str(ROOT / "tests/integration/run.py"), mode],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0 or want not in r.stdout:
            return [f"want {want!r}: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
        return []
    return check


HELD_CHILD = r"""
import importlib.util, signal, sys
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
for s in run.STOP_SIGNALS:
    signal.signal(s, run.exit_on_signal)
real_mask = signal.pthread_sigmask

def raising_once(how, mask):
    signal.pthread_sigmask = real_mask
    real_mask(how, mask)
    run.exit_on_signal(signal.SIGTERM, None)

signal.pthread_sigmask = raising_once
done = []
try:
    with run.signals_held():
        done.append("teardown")
    print(f"no exit, done={done}")
except SystemExit as e:
    print(f"exit {e.code}, done={done}")
"""


def signals_held_runs_the_teardown_first() -> list:
    """A handler raising as signals_held blocks must not skip the teardown it
    guards (S10-1): the body runs, then the run ends."""
    r = subprocess.run([sys.executable, "-c", HELD_CHILD, str(ROOT / "tests/integration/run.py")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "exit 143, done=['teardown']" not in r.stdout:
        return [f"signals_held skipped its teardown: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
    return []


CALL_SITE_CHILD = r"""
import _thread, contextlib, importlib.util, signal, sys, types
spec = importlib.util.spec_from_file_location("run", sys.argv[1])
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
for s in run.STOP_SIGNALS:
    signal.signal(s, run.exit_on_signal)
done = []
env = dict(vars(run), kill=lambda child: done.append("kill"), child=None, host=types.SimpleNamespace(stop=False),
           wg=types.SimpleNamespace(close=lambda: done.append("wg")),
           tap=types.SimpleNamespace(close=lambda: done.append("tap")), py=None, sniffer=None, opened=[])

def trace(frame, event, arg):
    # The pending handler runs on the way into the context manager, before
    # signals_held's own try can catch its exit.
    if event == "call" and frame.f_code.co_name == "__enter__" and frame.f_code.co_filename == contextlib.__file__:
        sys.settrace(None)
        _thread.interrupt_main(signal.SIGTERM)

sys.settrace(trace)
try:
    exec(sys.argv[2], env)
    print(f"no exit, done={done}")
except SystemExit as e:
    print(f"exit {e.code}, done={done}")
"""


def held_teardowns_survive_an_exit_on_entry() -> list:
    """Every `with signals_held()` in run.py sits in a try that runs its
    teardown again on SystemExit: a handler that runs while entering the
    context manager must not skip the kill (S11-1). Each real call site is
    executed with the teardown recorded."""
    import ast
    import textwrap
    src = (ROOT / "tests/integration/run.py").read_text()
    tree = ast.parse(src)
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    sites = [n for n in ast.walk(tree) if isinstance(n, ast.With)
             and any(isinstance(i.context_expr, ast.Call) and getattr(i.context_expr.func, "id", None) == "signals_held"
                     for i in n.items)]
    if not sites:
        return ["no signals_held call sites found"]
    errors = []
    for site in sites:
        enclosing = parents.get(site)
        if not isinstance(enclosing, ast.Try) or site not in enclosing.body:
            errors.append(f"line {site.lineno}: signals_held is not the body of a try")
            continue
        code = textwrap.dedent(ast.get_source_segment(src, enclosing, padded=True))
        r = subprocess.run([sys.executable, "-c", CALL_SITE_CHILD, str(ROOT / "tests/integration/run.py"), code],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0 or "exit 143" not in r.stdout or "'kill'" not in r.stdout:
            errors.append(f"line {site.lineno}: teardown skipped: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}")
    return errors


def netns_harness_installs_the_guard() -> list:
    """The guard only protects runs that install it: in_netns must do so
    before anything else."""
    import ast
    tree = ast.parse((ROOT / "tests/integration/run.py").read_text())
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "in_netns"), None)
    if fn is None:
        return ["in_netns not found in run.py"]
    first = fn.body[0]
    is_call = (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
               and isinstance(first.value.func, ast.Name) and first.value.func.id == "guard_thread_starts")
    return [] if is_call else ["in_netns does not call guard_thread_starts() first"]


def threads_started_only_through_the_helper() -> list:
    """In the netns harness a thread started with stop signals unblocked
    would bring back F-R5-1; the run-time guard must refuse it and allow
    the helper's way."""
    r = subprocess.run([sys.executable, "-c", GUARD_CHILD, str(ROOT / "tests/integration/run.py")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "plain start refused" not in r.stdout:
        return [f"guard did not refuse a plain thread start: rc={r.returncode} {r.stdout.strip()!r} {r.stderr[-200:]!r}"]
    return []


# Standalone checks: each returns a list of errors (empty when it holds).
CHECKS = [
    ("the run-time guard refuses threads with unblocked stop signals", lambda: threads_started_only_through_the_helper()),
    ("the netns harness installs the guard first", lambda: netns_harness_installs_the_guard()),
    ("the final teardown holds an exit until removal", lambda: final_teardown_holds_an_exit()),
    ("ignore_signals blocks before ignoring", lambda: ignore_signals_has_no_window()),
    ("signals_held runs its teardown even if entering it raises", lambda: signals_held_runs_the_teardown_first()),
    ("every held teardown runs even if the handler fires on entry", lambda: held_teardowns_survive_an_exit_on_entry()),
    ("main returns the failure status when no signal arrives", main_holds_and_reraises("plain", "returned 1, gone=True")),
    ("main re-raises an exit held on entry to its teardown", main_holds_and_reraises("entry", "exit 143, gone=True")),
]


def main() -> int:
    failures = ran = 0
    for name, check in CHECKS:
        errors = check()
        ran += 1
        failures += bool(errors)
        print(f"{'ok  ' if not errors else 'FAIL'} {name}: {errors or 'ok'}")
    for name, want in CASES:
        r = subprocess.run([sys.executable, "-c", CHILD, str(ROOT / "tests/integration/run.py")],
                           capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0 and want in r.stdout
        ran += 1
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: rc={r.returncode} {r.stdout.strip()!r} {r.stderr.strip()[-200:]!r}")
    # The count is what ran, so dropping a check lowers it (manifest).
    print(f"HARNESS-SIGNAL-FIXTURES {ran}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
