"""tools/kernel-config (M9 plan C1, L11): the SDK's own gen_config.h files
pass; the GICv2 fixture (the SDK's release config with GICv3 support off)
fails naming GIC_V3 alone; and the release config with any one required
line removed fails naming that requirement alone.

Usage: python3 tests/tools/test_kernel_config.py   (needs $MICROKIT_SDK)
Prints "KERNEL-CONFIG-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/kernel-config"
GICV2 = ROOT / "tests/fixtures/kernel-config/gicv2-el1-gen_config.h"
BOARD = "kozane_virt_aarch64_el1"


def load_tool():
    loader = importlib.machinery.SourceFileLoader("kernel_config", str(TOOL))
    spec = importlib.util.spec_from_loader("kernel_config", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run(path) -> tuple:
    r = subprocess.run([sys.executable, str(TOOL), str(path)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main() -> int:
    sdk = os.environ.get("MICROKIT_SDK")
    if not sdk:
        print("FAIL kernel-config fixtures: MICROKIT_SDK is not set")
        return 1
    configs = {c: pathlib.Path(sdk) / "board" / BOARD / c / "include/kernel/gen_config.h" for c in ("debug", "release")}
    required = load_tool().REQUIRED
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

    for config, path in configs.items():
        status, out = run(path)
        check(f"the SDK's {config} config passes", status == 0 and out == "", (status, out))

    status, out = run(GICV2)
    check("the GICv2 fixture fails on GIC_V3 alone",
          status == 1 and out == f"kernel-config: GIC_V3 missing in {GICV2}\n", (status, out))

    release = configs["release"].read_text()
    with tempfile.TemporaryDirectory() as d:
        variant = pathlib.Path(d) / "gen_config.h"
        for label, line in required:
            lines = release.splitlines(keepends=True)
            kept = [x for x in lines if x.rstrip() != line]
            variant.write_text("".join(kept))
            status, out = run(variant)
            check(f"without {line!r}: {label} missing",
                  len(kept) == len(lines) - 1 and status == 1
                  and out == f"kernel-config: {label} missing in {variant}\n", (status, out))

    print(f"KERNEL-CONFIG-FIXTURES {cases}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
