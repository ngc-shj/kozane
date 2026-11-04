"""tools/sdk-repro (M9 plan C15, I15.1, VE27): `compare` passes two equal
lists that name the kernel, the loader and the tool, and fails a
difference or a missing artifact; `build`, against a stand-in docker that
runs the real in-container listing over a scratch SDK, writes the list
only when every step of that listing succeeded.

Usage: python3 tests/tools/test_sdk_repro.py
Prints "SDK-REPRO-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/sdk-repro"
BOARD = "./board/kozane_virt_aarch64_el1/release/elf"
ARTIFACTS = (f"{BOARD}/sel4.elf", f"{BOARD}/loader.elf", "./bin/microkit")
OTHER = "./include/kernel/gen_config.h"

# A stand-in docker: `build` and `rmi` succeed; `run --rm <tag> bash -c
# <script>` runs the tool's own script on the host, the SDK path moved to
# $FAKE_SDK, so its pipeline is the one under test. FAKE_RUN_STATUS makes
# the whole run fail instead.
DOCKER = """#!/bin/sh
case "$1" in
build|rmi) exit 0 ;;
run)
    [ -n "$FAKE_RUN_STATUS" ] && exit "$FAKE_RUN_STATUS"
    script=$(printf '%s' "$6" | sed "s#/opt/microkit/sdk#$FAKE_SDK#")
    exec bash -c "$script" ;;
esac
exit 64
"""
# A find that lists one file and then fails, as a find hitting an
# unreadable directory part-way does.
FAILING_FIND = """#!/bin/sh
printf './bin/microkit\\0'
exit 1
"""


def listing(paths, changed=()) -> str:
    return "".join(f"{('1' if p in changed else '0') * 64}  {p}\n" for p in paths)


def compare(a: str, b: str) -> tuple:
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "a.sha").write_text(a)
        (pathlib.Path(d) / "b.sha").write_text(b)
        r = subprocess.run([str(TOOL), "compare", f"{d}/a.sha", f"{d}/b.sha"], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def build(failing_find: bool = False, run_status: str = "") -> tuple:
    """(exit, output, the written list or None) of `build` against the
    stand-in docker, over a scratch SDK holding the three artifacts."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        sdk, bin_dir = d / "sdk", d / "bin"
        for p in (*ARTIFACTS, OTHER):
            (sdk / p).parent.mkdir(parents=True, exist_ok=True)
            (sdk / p).write_bytes(p.encode())
        bin_dir.mkdir()
        (bin_dir / "docker").write_text(DOCKER)
        (bin_dir / "docker").chmod(0o755)
        if failing_find:
            (bin_dir / "find").write_text(FAILING_FIND)
            (bin_dir / "find").chmod(0o755)
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_SDK": str(sdk),
               "FAKE_RUN_STATUS": run_status}
        out = d / "out.sha"
        r = subprocess.run([str(TOOL), "build", str(out)], capture_output=True, text=True, env=env)
        left = sorted(p.name for p in d.iterdir() if p.name.startswith("out.sha"))
        return r.returncode, r.stdout + r.stderr, out.read_text() if out.exists() else None, left


def main() -> int:
    failures = 0
    cases = 0

    def check(name: str, ok: bool, detail=""):
        nonlocal failures, cases
        cases += 1
        if ok:
            print(f"ok   {name}")
        else:
            failures += 1
            print(f"FAIL {name}: {detail}")

    full = listing((*ARTIFACTS, OTHER))
    status, out = compare(full, full)
    check("compare: equal lists naming all three artifacts pass", status == 0 and "SDK-REPRO-ARTIFACTS 3" in out,
          (status, out))
    status, out = compare(full, listing((*ARTIFACTS, OTHER), changed=(f"{BOARD}/sel4.elf",)))
    check("compare: one differing hash fails", status == 1 and "sdk-repro: differs" in out, (status, out))
    without_loader = listing((ARTIFACTS[0], ARTIFACTS[2], OTHER))
    status, out = compare(without_loader, without_loader)
    check("compare: equal lists without the loader fail the count",
          status == 1 and "sdk-repro: SDK-REPRO-ARTIFACTS 2 < 3" in out, (status, out))
    status, out = compare("", "")
    check("compare: two empty lists compare nothing", status == 1 and "sdk-repro: SDK-REPRO-ARTIFACTS 0 < 3" in out,
          (status, out))
    lookalike = listing(("x/bin/microkit", "./sdk/bin/microkit", *ARTIFACTS[:2]))
    status, out = compare(lookalike, lookalike)
    check("compare: a path only resembling an artifact's does not count",
          status == 1 and "sdk-repro: SDK-REPRO-ARTIFACTS 2 < 3" in out, (status, out))

    status, out, written, left = build()
    names = sorted(line.split("  ", 1)[1] for line in (written or "").splitlines())
    check("build: a clean listing writes every SDK file",
          status == 0 and names == sorted((*ARTIFACTS, OTHER)) and left == ["out.sha"], (status, out, written, left))
    status, out, written, left = build(failing_find=True)
    check("build: a find failing part-way writes no list",
          status != 0 and written is None and left == [] and "sdk-repro: listing the SDK failed" in out,
          (status, out, written, left))
    status, out, written, left = build(run_status="125")
    check("build: a failed docker run writes no list",
          status != 0 and written is None and left == [] and "sdk-repro: listing the SDK failed" in out,
          (status, out, written, left))

    print(f"SDK-REPRO-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
