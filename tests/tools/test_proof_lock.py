"""tools/proof-lock serialises proof runs (M5 plan C2).

Stub A runs under the lock and waits, unbounded, for a release file. While
A holds it: `flock -n` on the lock path must fail, and stub B under the
same lock must not start within a bound. A slow host can only make B look
more blocked, so the serialising case cannot pass by luck. The red case runs
the same check against a copy of the script with the flock removed: B must
start, or the fixture fails loudly.

Usage: python3 tests/tools/test_proof_lock.py
Prints "PROOF-LOCK-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/proof-lock"
# B under a working lock: any bound proves the point, since a longer wait
# only makes "B did not start" more certain.
BLOCKED_BOUND_S = 2
# B under a broken lock writes one file; the bound only guards a hang.
UNBLOCKED_BOUND_S = 30


def wait_for(path: pathlib.Path, proc: subprocess.Popen, what: str):
    while not path.exists():
        if proc.poll() is not None:
            raise RuntimeError(f"{what} exited ({proc.returncode}) before writing {path.name}")
        time.sleep(0.05)


def b_starts_while_a_holds(script: pathlib.Path, tmp: pathlib.Path):
    """Returns (lock_free_while_a_runs, b_started) for one script."""
    lock, log, release = tmp / "lock", tmp / "log", tmp / "release"
    env = dict(os.environ, SECUREOS_PROOF_LOCK=str(lock))
    a_started = tmp / "a-started"
    a = subprocess.Popen(
        [str(script), "bash", "-c",
         f'touch {a_started}; echo A-start >> {log}; '
         f'while [ ! -e {release} ]; do sleep 0.05; done; echo A-end >> {log}'],
        env=env)
    try:
        wait_for(a_started, a, "stub A")
        free = subprocess.run(["flock", "-n", str(lock), "true"]).returncode == 0
        bound = UNBLOCKED_BOUND_S if free else BLOCKED_BOUND_S
        b = subprocess.run(
            ["timeout", str(bound), str(script), "bash", "-c", f"echo B-start >> {log}"], env=env)
        started = "B-start" in log.read_text()
        if free and not started:
            raise RuntimeError(f"stub B neither ran nor blocked (exit {b.returncode})")
        return free, started
    finally:
        release.touch()
        a.wait(timeout=UNBLOCKED_BOUND_S)


def main() -> int:
    failures = 0
    cases = 0
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)

        cases += 1
        (tmp / "real").mkdir()
        free, started = b_starts_while_a_holds(SCRIPT, tmp / "real")
        ok = not free and not started
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} the lock serialises A and B: lock free={free}, B started={started}")

        cases += 1
        (tmp / "broken").mkdir()
        broken = tmp / "broken" / "proof-lock"
        broken.write_text("".join(
            line for line in SCRIPT.read_text().splitlines(keepends=True) if line.strip() != "flock 9"))
        broken.chmod(0o755)
        free, started = b_starts_while_a_holds(broken, tmp / "broken")
        ok = free and started
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} without flock B overlaps A: lock free={free}, B started={started}")
    print(f"PROOF-LOCK-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
