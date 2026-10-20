"""tools/audit-gate must pass a clean, fully excepted report and refuse each
kind of failure with its own message (M3a external review, item 3). A fake
`cargo` on PATH prints a canned `cargo audit --json` report, so the cases
run without the real advisory database.

Usage: python3 tests/tools/test_audit_gate.py
Prints "AUDIT-GATE-FIXTURES <n>" and exits non-zero on any mismatch.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/audit-gate"

PASTE = {"kind": "unmaintained", "package": {"name": "paste", "version": "1.0.15"},
         "advisory": {"id": "RUSTSEC-2024-0436", "title": "paste - no longer maintained"}}
IGNORE_PASTE = '[[ignore]]\nid = "RUSTSEC-2024-0436"\ncrate = "paste"\nreason = "build-time only"\nowner = "M4"\n'
VULN = {"package": {"name": "libcrux-x", "version": "0.0.1"},
        "advisory": {"id": "RUSTSEC-2099-0001", "title": "bad"}}


def report(vulns=(), warnings=(), advisories=1338, crates=222):
    return {"database": {"advisory-count": advisories}, "lockfile": {"dependency-count": crates},
            "vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": list(vulns)},
            "warnings": {"unmaintained": list(warnings)} if warnings else {}}


# (name, canned report or raw stdout, ignore file text, expected message or None for accept)
CASES = [
    ("a clean report with every warning excepted passes", report(warnings=[PASTE]), IGNORE_PASTE, None),
    ("a vulnerability fails even if its id is excepted", report(vulns=[VULN], warnings=[PASTE]),
     IGNORE_PASTE + IGNORE_PASTE.replace("RUSTSEC-2024-0436", "RUSTSEC-2099-0001").replace("paste", "libcrux-x"),
     "vulnerability RUSTSEC-2099-0001 in libcrux-x"),
    ("an unexcepted warning fails", report(warnings=[PASTE]), "",
     "unmaintained warning RUSTSEC-2024-0436 for paste 1.0.15 is not excepted"),
    ("an exception for another crate does not cover the warning", report(warnings=[PASTE]),
     IGNORE_PASTE.replace('crate = "paste"', 'crate = "other"'), "is not excepted"),
    ("a stale exception fails", report(), IGNORE_PASTE, "exception RUSTSEC-2024-0436 matches no reported warning"),
    ("an empty database fails", report(advisories=0), "", "examined nothing"),
    ("a lock with no crates fails", report(crates=0), "", "examined nothing"),
    ("no JSON from cargo audit fails", "error: database not found", "", "cargo audit produced no report"),
    ("an exception without a reason fails", report(warnings=[PASTE]),
     IGNORE_PASTE.replace('reason = "build-time only"\n', ""), "must have exactly the non-empty string keys"),
]


def run_case(out, ignore_text: str) -> str:
    with tempfile.TemporaryDirectory(prefix="test-audit-gate-") as d:
        d = pathlib.Path(d)
        stdout = out if isinstance(out, str) else json.dumps(out)
        fake = d / "cargo"
        fake.write_text(f"#!/bin/sh\ncat <<'JSON'\n{stdout}\nJSON\nexit 1\n")
        fake.chmod(0o755)
        (d / "ignore.toml").write_text(ignore_text)
        r = subprocess.run([sys.executable, str(TOOL), "--db", str(d), "--lock", str(d / "Cargo.lock"),
                            "--ignore", str(d / "ignore.toml")], capture_output=True, text=True,
                           env={**os.environ, "PATH": f"{d}:{os.environ['PATH']}"})
        return r.returncode, r.stdout + r.stderr


def main() -> int:
    failures = 0
    for name, out, ignore_text, want in CASES:
        code, text = run_case(out, ignore_text)
        ok = (code == 0 and "AUDIT-ADVISORIES 1338" in text) if want is None else (code != 0 and want in text)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name}: exit={code} {text.strip()[-160:]!r}")
    print(f"AUDIT-GATE-FIXTURES {len(CASES)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
